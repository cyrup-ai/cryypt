//! CLI command definitions

use crate::security::{
    ProductionSecureFileOps, SecureFileOperations, SecuritySeverity, audit_security_violation,
    audit_vault_operation, validate_key_version, validate_keychain_namespace, validate_vault_path,
};
use clap::{Parser, Subcommand};
use cryypt_cipher::cipher::api::Cipher;
use cryypt_key::{KeyRetriever, store::KeychainStore};
use cryypt_pqcrypto::api::{KyberSecurityLevel as SecurityLevel, PqCryptoMasterBuilder};
use serde_json;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "cryypt")]
#[command(about = "Secure vault and key management")]
pub struct Cli {
    /// Path to the vault file
    #[arg(long)]
    pub vault_path: Option<PathBuf>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,

    /// Save vault after command execution
    #[arg(long)]
    pub save: bool,

    /// Vault passphrase (if not provided, will prompt interactively)
    #[arg(long)]
    pub passphrase: Option<String>,

    /// JWT token for session authentication
    #[arg(long)]
    pub jwt: Option<String>,

    /// Path to RSA private key for JWT signing (default: ~/.ssh/cryypt.rsa)
    #[arg(long = "rsa-key", short = 'k', global = true)]
    pub rsa_key_path: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Clone, Subcommand)]
pub enum Commands {
    /// Create a new encrypted vault with PQCrypto protection
    ///
    /// This command initializes a new vault at the specified path (or default XDG location)
    /// with Argon2id-based encryption and PQCrypto keypair generation. The vault is created as
    /// a SurrealDB database directory (.db) and is immediately ready for use.
    ///
    /// Default path: $XDG_CONFIG_HOME/cryypt/cryypt.db (or ~/.config/cryypt/cryypt.db)
    ///
    /// The command will:
    /// 1. Generate or reuse PQCrypto keypair in system keychain
    /// 2. Create all parent directories safely
    /// 3. Initialize an encrypted vault database (.db directory)
    /// 4. Persist the vault to disk
    ///
    /// After creation, use the vault immediately:
    ///   vault --vault-path <path> put mykey "myvalue" --passphrase <pass>
    ///   vault --vault-path <path> login --passphrase <pass>
    ///
    /// Optional: Encrypt vault contents into a portable .vault armor:
    ///   vault --vault-path <path> lock
    ///
    /// Example usage:
    ///   vault new
    ///   vault new --vault-path /my/vault
    ///   vault new --passphrase "my-secret-pass"
    New {
        /// Path where the vault will be created (default: $XDG_CONFIG_HOME/cryypt/cryypt.vault)
        #[arg(long)]
        vault_path: Option<PathBuf>,
        
        /// Passphrase for the vault (will prompt if not provided)
        #[arg(long)]
        passphrase: Option<String>,
    },

    /// Save vault data to disk
    Save {},

    /// Store a key-value pair in the vault
    Put {
        /// The key to store
        key: String,
        /// The value to store
        value: String,
        /// Optional namespace for organizing entries
        #[arg(long)]
        namespace: Option<String>,
    },

    /// Retrieve a value from the vault
    Get {
        /// The key to retrieve
        key: String,
        /// Optional namespace to search in
        #[arg(long)]
        namespace: Option<String>,
    },

    /// Delete a key from the vault
    Delete {
        /// The key to delete
        key: String,
        /// Optional namespace to delete from
        #[arg(long)]
        namespace: Option<String>,
    },

    /// List all keys in the vault
    List {
        /// Optional namespace to list from
        #[arg(long)]
        namespace: Option<String>,
        /// List all available namespaces
        #[arg(long)]
        namespaces: bool,
    },

    /// Find keys matching a pattern
    Find {
        /// Regular expression pattern to match keys
        pattern: String,
        /// Optional namespace to search in
        #[arg(long)]
        namespace: Option<String>,
    },

    /// Change the vault passphrase
    ChangePassphrase {
        /// Current passphrase (will prompt if not provided)
        #[arg(long)]
        old_passphrase: Option<String>,
        /// New passphrase (will prompt if not provided)
        #[arg(long)]
        new_passphrase: Option<String>,
    },

    /// Login to the vault and receive a JWT token for session authentication
    Login {
        /// Vault passphrase (will prompt if not provided)
        #[arg(long)]
        passphrase: Option<String>,
        /// JWT token expiration in hours (default: 1 hour)
        #[arg(long, default_value = "1")]
        expires_in: u64,
    },

    /// Logout from vault and lock the database
    Logout {
        /// Path to vault file (overrides global --vault-path)
        #[arg(long)]
        vault_path: Option<PathBuf>,
    },

    /// Run a command with secure vault token replacement
    Run {
        /// Command and arguments to execute
        command: Vec<String>,
        /// Namespace to load keys from (optional - loads all if not specified)
        #[arg(long)]
        namespace: Option<String>,
        /// JWT token for authentication
        #[arg(long)]
        jwt: Option<String>,
    },

    /// Generate a new cryptographic key
    GenerateKey {
        /// Namespace for organizing keys
        #[arg(long)]
        namespace: String,
        /// Version number for key rotation
        #[arg(long)]
        version: u32,
        /// Key size in bits (128, 192, 256, 384, or 512)
        #[arg(long, default_value = "256")]
        bits: u32,
        /// Storage backend (memory or file:<path>)
        #[arg(long, default_value = "memory")]
        store: String,
    },

    /// Retrieve an existing cryptographic key
    RetrieveKey {
        /// Namespace of the key to retrieve
        #[arg(long)]
        namespace: String,
        /// Version of the key to retrieve
        #[arg(long)]
        version: u32,
        /// Storage backend (memory or file:<path>)
        #[arg(long, default_value = "memory")]
        store: String,
    },

    /// Generate multiple keys in batch
    BatchGenerateKeys {
        /// Namespace for organizing keys
        #[arg(long)]
        namespace: String,
        /// Version number for key rotation
        #[arg(long)]
        version: u32,
        /// Key size in bits (128, 192, 256, 384, or 512)
        #[arg(long, default_value = "256")]
        bits: u32,
        /// Number of keys to generate
        #[arg(long)]
        count: usize,
        /// Storage backend (memory or file:<path>)
        #[arg(long, default_value = "memory")]
        store: String,
    },

    /// Apply PQCrypto armor to vault file (.db → .vault)
    Lock {
        /// Path to vault file (overrides global --vault-path)
        #[arg(long)]
        vault_path: Option<PathBuf>,
        /// Path to PQCrypto public key file (optional - falls back to keychain)
        #[arg(long)]
        pq_public_key: Option<PathBuf>,
        /// Keychain namespace for PQCrypto keys (default: "pq_armor")
        #[arg(long, default_value = "pq_armor")]
        keychain_namespace: String,
    },

    /// Remove PQCrypto armor from vault file (.vault → .db)  
    Unlock {
        /// Path to vault file (overrides global --vault-path)
        #[arg(long)]
        vault_path: Option<PathBuf>,
        /// Path to PQCrypto private key file (optional - falls back to keychain)
        #[arg(long)]
        pq_private_key: Option<PathBuf>,
    },

    /// Rotate PQCrypto keys for enhanced security
    RotateKeys {
        /// Vault path for re-encryption (required)
        #[arg(long)]
        vault_path: PathBuf,
        /// Namespace for key rotation (defaults to pq_armor)
        #[arg(long, default_value = "pq_armor")]
        namespace: String,
        /// Force rotation even if recent keys exist
        #[arg(long)]
        force: bool,
    },
}

// SUBTASK4: PQCrypto key management functions

/// Load PQCrypto key from OS keychain  
pub async fn load_pq_key_from_keychain(key_id: &str) -> Result<Vec<u8>, String> {
    let keychain_store = KeychainStore::for_app("vault");

    // Use KeyRetriever with dummy namespace/version since we pass full key_id
    let key_data = KeyRetriever::new()
        .with_store(keychain_store)
        .with_namespace("_") // Dummy, overridden by key_id parameter
        .version(1)          // Dummy, overridden by key_id parameter
        .retrieve(key_id)
        .await;

    if key_data.is_empty() {
        return Err(format!("PQCrypto keypair '{}' not found in keychain", key_id));
    }

    Ok(key_data)
}

/// Generate unique PQCrypto key ID with UUID v4
///
/// # Arguments
/// * `namespace` - Keychain namespace (e.g., "pq_armor")
///
/// # Returns
/// Unique key ID in format "{namespace}:{uuid}:pq_keypair"
///
/// # Performance
/// - Zero allocations beyond the returned String
/// - Inline for hot path optimization
#[inline]
pub fn generate_unique_key_id(namespace: &str) -> String {
    use uuid::Uuid;
    let uuid = Uuid::new_v4();
    // Pre-allocate exact capacity to avoid reallocation
    let mut key_id = String::with_capacity(namespace.len() + 37 + 11); // namespace + ":" + uuid + ":pq_keypair"
    key_id.push_str(namespace);
    key_id.push(':');
    key_id.push_str(&uuid.to_string());
    key_id.push_str(":pq_keypair");
    key_id
}

/// Parse key ID to extract namespace component
///
/// # Arguments
/// * `key_id` - Full key ID (e.g., "pq_armor:uuid:pq_keypair")
///
/// # Returns
/// Some(namespace) if format is valid, None otherwise
///
/// # Performance
/// - Zero allocations if namespace is not needed
/// - Returns owned String to avoid lifetime issues
#[inline]
pub fn parse_key_id_namespace(key_id: &str) -> Option<String> {
    // Fast path: find first colon
    key_id.find(':').map(|pos| key_id[..pos].to_string())
}

/// Generate and store new PQCrypto keypair
pub async fn generate_pq_keypair(
    key_id: &str,
    security_level: SecurityLevel,
) -> Result<(), String> {
    // Generate Kyber keypair
    let keypair = PqCryptoMasterBuilder::new()
        .kyber()
        .with_security_level(security_level)
        .on_result(|result| match result {
            Ok(keypair) => keypair,
            Err(e) => {
                log::error!("PQCrypto keypair generation failed: {}", e);
                panic!("Failed to generate PQCrypto keypair: {}", e)
            }
        })
        .generate_keypair()
        .await;

    // Store in keychain using cryypt_key API
    use cryypt_key::{KeyId, SimpleKeyId, traits::KeyImport};

    let keychain_store = KeychainStore::for_app("vault");
    let simple_key_id = SimpleKeyId::new(key_id);

    use std::sync::{Arc, Mutex};

    let error_state = Arc::new(Mutex::new(None::<String>));
    let error_state_clone = Arc::clone(&error_state);

    keychain_store
        .store(&simple_key_id, &keypair)
        .on_result(move |result| match result {
            Ok(()) => (),
            Err(e) => {
                log::error!("Failed to store PQCrypto keypair in keychain: {}", e);
                if let Ok(mut error_guard) = error_state_clone.lock() {
                    *error_guard = Some(format!(
                        "Failed to store PQCrypto keypair in keychain: {}",
                        e
                    ));
                }
            }
        })
        .await;

    if let Ok(error_guard) = error_state.lock()
        && let Some(error) = error_guard.as_ref()
    {
        return Err(error.clone());
    }

    println!("✅ PQCrypto keypair generated and stored in keychain");
    Ok(())
}

// SUBTASK2: Implement hybrid PQCrypto lock operation

pub async fn handle_lock_command(
    vault_path: &std::path::Path,
    pq_public_key: Option<&std::path::Path>,
    key_id: &str,
    use_json: bool,
) -> Result<(), String> {
    // 1. Security validation of all inputs
    if key_id.is_empty() {
        let error_msg = "Key ID cannot be empty";
        audit_security_violation(
            "Invalid key ID",
            SecuritySeverity::Medium,
            error_msg,
        )
        .await;
        return Err(error_msg.to_string());
    }

    // 2. Validate and canonicalize paths
    let db_path = match validate_vault_path(&vault_path.with_extension("db"), "db") {
        Ok(path) => path,
        Err(e) => {
            let error_msg = format!("DB path validation failed: {}", e);
            audit_security_violation("Path validation failed", SecuritySeverity::High, &error_msg)
                .await;
            return Err(format!("Invalid vault database path: {}", e));
        }
    };

    let vault_path = match validate_vault_path(&vault_path.with_extension("vault"), "vault") {
        Ok(path) => path,
        Err(e) => {
            let error_msg = format!("Vault path validation failed: {}", e);
            audit_security_violation("Path validation failed", SecuritySeverity::High, &error_msg)
                .await;
            return Err(format!("Invalid vault path: {}", e));
        }
    };

    // 3. Validate file existence and permissions
    if !db_path.exists() {
        audit_vault_operation("lock", &db_path.display().to_string(), false, None).await;
        return Err("Vault database not found".to_string());
    }

    if vault_path.exists() {
        audit_vault_operation("lock", &vault_path.display().to_string(), false, None).await;
        return Err("Vault already armored".to_string());
    }

    // Determine storage source
    use crate::services::key_storage::{KeyStorageSource, create_key_storage};
    use crate::services::PQCryptoArmorService;

    let storage_source = if let Some(key_file) = pq_public_key {
        KeyStorageSource::File(key_file.to_path_buf())
    } else {
        KeyStorageSource::Keychain("vault".to_string())
    };

    let key_storage = create_key_storage(storage_source);
    let armor_service = PQCryptoArmorService::new(key_storage, SecurityLevel::Level3);

    // Single unified path for all armor operations
    armor_service
        .armor(&db_path, &vault_path, key_id)
        .await
        .map_err(|e| e.to_string())?;

    if use_json {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "operation": "lock",
                "vault_path": vault_path.display().to_string()
            })
        );
    } else {
        println!("✅ Vault successfully armored: {}", vault_path.display());
    }

    Ok(())
}

// SUBTASK3: Implement hybrid PQCrypto unlock operation

pub async fn handle_unlock_command(
    vault_path: &std::path::Path,
    pq_private_key: Option<&std::path::Path>,
    key_id: &str,
    use_json: bool,
) -> Result<(), String> {
    // 1. Validate input file exists and has .vault extension
    let vault_path = vault_path.with_extension("vault");
    let db_path = vault_path.with_extension("db");

    if !vault_path.exists() {
        return Err(format!("Armored vault not found: {}", vault_path.display()).to_string());
    }

    if db_path.exists() {
        return Err(format!("Vault already unlocked: {}", db_path.display()).to_string());
    }

    // Determine storage source
    use crate::services::key_storage::{KeyStorageSource, create_key_storage};
    use crate::services::PQCryptoArmorService;

    let storage_source = if let Some(key_file) = pq_private_key {
        KeyStorageSource::File(key_file.to_path_buf())
    } else {
        KeyStorageSource::Keychain("vault".to_string())
    };

    let key_storage = create_key_storage(storage_source);
    let armor_service = PQCryptoArmorService::new(key_storage, SecurityLevel::Level3);

    // Single unified path for all unarmor operations
    armor_service
        .unarmor(&vault_path, &db_path, key_id)
        .await
        .map_err(|e| e.to_string())?;

    if use_json {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "operation": "unlock",
                "vault_path": db_path.display().to_string()
            })
        );
    } else {
        println!("✅ Vault successfully unlocked: {}", db_path.display());
    }

    Ok(())
}

/// Rotate PQCrypto keys with automatic UUID generation and cleanup
///
/// This function performs complete key rotation:
/// 1. Reads old key_id from .vault file header
/// 2. Generates new UUID-based key_id
/// 3. Unarmors vault with old key
/// 4. Armors vault with new key
/// 5. Deletes old key from keychain
pub async fn rotate_pq_keys(
    vault_path: &std::path::Path,
    namespace: &str,
) -> Result<(), String> {
    use crate::services::armor::read_key_id_from_vault_file;
    
    // Step 1: Read old key_id from .vault file header
    let vault_file = vault_path.with_extension("vault");
    if !vault_file.exists() {
        return Err(format!(
            "Vault file does not exist: {}",
            vault_file.display()
        ));
    }

    let old_key_id = read_key_id_from_vault_file(&vault_file)
        .await
        .map_err(|e| {
            format!(
                "Failed to read key ID from {}: {}",
                vault_file.display(),
                e
            )
        })?;

    log::info!("Rotating key from: {}", old_key_id);

    // Step 2: Generate new UUID-based key_id
    let new_key_id = generate_unique_key_id(namespace);
    log::info!("Rotating key to: {}", new_key_id);

    // Step 3: Generate new keypair in keychain
    generate_pq_keypair(&new_key_id, SecurityLevel::Level3)
        .await
        .map_err(|e| format!("Failed to generate new keypair: {}", e))?;

    // Step 4: Unarmor with old key (.vault → .db)
    handle_unlock_command(vault_path, None, &old_key_id, false)
        .await
        .map_err(|e| format!("Failed to unlock with old key: {}", e))?;

    // Step 5: Re-armor with new key (.db → .vault)
    handle_lock_command(vault_path, None, &new_key_id, false)
        .await
        .map_err(|e| format!("Failed to lock with new key: {}", e))?;

    // Step 6: Delete old key from keychain
    use crate::services::{KeychainStorage, key_storage::KeyStorage};
    let keychain = KeychainStorage::default_app();
    keychain
        .delete(&old_key_id)
        .await
        .map_err(|e| format!("Failed to delete old key from keychain: {}", e))?;

    log::info!("Key rotation complete. Old key deleted: {}", old_key_id);

    Ok(())
}

use crate::tui::cli::vault_detection::{VaultState, detect_vault_state};

/// Discover all .vault files for PQCrypto key rotation
pub async fn discover_vault_files(
    namespace: &str,
    search_paths: Option<Vec<PathBuf>>,
) -> Result<Vec<PathBuf>, String> {
    let mut vault_paths = Vec::new();

    // Default search paths if none provided
    let paths_to_search = search_paths.unwrap_or_else(|| {
        vec![
            PathBuf::from("."),         // Current directory
            PathBuf::from("./vaults"),  // Common vault directory
            PathBuf::from("../vaults"), // Parent vault directory
            dirs::home_dir()
                .map(|h| h.join(".cryypt"))
                .unwrap_or_else(|| PathBuf::from(".")),
        ]
    });

    for search_path in paths_to_search {
        if !search_path.exists() {
            continue;
        }

        // Search for .vault files recursively
        if let Ok(entries) = std::fs::read_dir(&search_path) {
            for entry in entries.flatten() {
                let path = entry.path();

                // Check if it's a .vault file
                if path.extension().and_then(|s| s.to_str()) == Some("vault") {
                    // Verify it's actually a valid vault state
                    let base_path = path.with_extension("");
                    match detect_vault_state(&base_path) {
                        Ok(VaultState::Locked {
                            vault_file,
                            db_file,
                        }) => {
                            log::debug!("Found locked vault: {}", vault_file.display());
                            vault_paths.push(db_file); // Use .db path for rotation
                        }
                        Ok(VaultState::Unlocked { db_file, .. }) => {
                            log::debug!("Found unlocked vault: {}", db_file.display());
                            vault_paths.push(db_file);
                        }
                        Err(e) => {
                            log::warn!("Invalid vault at {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }
    }

    log::info!(
        "Discovered {} vaults for namespace '{}' key rotation",
        vault_paths.len(),
        namespace
    );
    Ok(vault_paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_cli_lock_unlock_cycle() {
        let temp_dir = tempdir().unwrap();
        let vault_path = temp_dir.path().join("test.db");
        let public_key_file = temp_dir.path().join("test_public_key.bin");
        let private_key_file = temp_dir.path().join("test_private_key.bin");

        // Generate test keypair directly using PQCrypto API
        let combined_keypair = PqCryptoMasterBuilder::new()
            .kyber()
            .with_security_level(SecurityLevel::Level3)
            .on_result(|result| match result {
                Ok(keypair) => keypair,
                Err(e) => {
                    panic!("Failed to generate test keypair: {}", e)
                }
            })
            .generate_keypair()
            .await;

        // Save combined keypair to both files (functions will extract appropriate portions)
        tokio::fs::write(&public_key_file, &combined_keypair)
            .await
            .unwrap();
        tokio::fs::write(&private_key_file, &combined_keypair)
            .await
            .unwrap();

        // Create test vault database
        tokio::fs::write(&vault_path, b"test vault content")
            .await
            .unwrap();

        // Test lock command with file-based public key (bypasses keychain)
        let test_key_id = "test_namespace:12345678-1234-1234-1234-123456789abc:pq_keypair";
        handle_lock_command(
            &vault_path,
            Some(&public_key_file), // Use public key file for encryption
            test_key_id,
            false,
        )
        .await
        .unwrap();

        // Verify .vault file exists and .db is removed
        assert!(!vault_path.exists());
        assert!(vault_path.with_extension("vault").exists());

        // Test unlock command with private key file
        handle_unlock_command(
            &vault_path,
            Some(&private_key_file), // Use private key file for decryption
            test_key_id,
            false,
        )
        .await
        .unwrap();

        // Verify .db file restored and .vault is removed
        assert!(vault_path.exists());
        assert!(!vault_path.with_extension("vault").exists());

        // Verify content integrity
        let recovered_content = tokio::fs::read(&vault_path).await.unwrap();
        assert_eq!(recovered_content, b"test vault content");
    }
}
