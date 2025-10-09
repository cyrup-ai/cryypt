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

    /// JWT token for session authentication (can also be provided via VAULT_JWT environment variable)
    #[arg(long)]
    pub jwt: Option<String>,

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
        /// JWT token for authentication (can also use VAULT_JWT env var)
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
        /// Keychain namespace for PQCrypto keys (default: "pq_armor")
        #[arg(long, default_value = "pq_armor")]
        keychain_namespace: String,
    },

    /// Rotate PQCrypto keys for enhanced security
    RotateKeys {
        /// Namespace for key rotation (defaults to pq_armor)
        #[arg(long, default_value = "pq_armor")]
        namespace: String,
        /// Force rotation even if recent keys exist
        #[arg(long)]
        force: bool,
    },
}

// SUBTASK5: .vault file format handling constants and functions
const VAULT_ARMOR_MAGIC: &[u8] = b"CRYYPT\x01\x02";

/// Create .vault file format with hybrid PQCrypto structure
fn create_armor_file_format(
    kyber_algorithm: SecurityLevel,
    kyber_ciphertext: &[u8],
    encrypted_data: &[u8],
) -> Result<Vec<u8>, String> {
    let mut armor_data = Vec::new();

    // Magic header
    armor_data.extend_from_slice(VAULT_ARMOR_MAGIC);

    // Algorithm identifier
    let algorithm_byte = match kyber_algorithm {
        SecurityLevel::Level1 => 0x01, // MlKem512
        SecurityLevel::Level3 => 0x02, // MlKem768
        SecurityLevel::Level5 => 0x03, // MlKem1024
    };
    armor_data.push(algorithm_byte);

    // Ciphertext length (little endian)
    let ciphertext_len = kyber_ciphertext.len() as u32;
    armor_data.extend_from_slice(&ciphertext_len.to_le_bytes());

    // Kyber ciphertext
    armor_data.extend_from_slice(kyber_ciphertext);

    // AES encrypted data
    armor_data.extend_from_slice(encrypted_data);

    Ok(armor_data)
}

/// Parse .vault file format and extract components
fn parse_armor_file_format(armor_data: &[u8]) -> Result<(SecurityLevel, Vec<u8>, Vec<u8>), String> {
    if armor_data.len() < VAULT_ARMOR_MAGIC.len() + 5 {
        return Err("Invalid .vault file: too short".to_string());
    }

    // Validate magic header
    if &armor_data[..VAULT_ARMOR_MAGIC.len()] != VAULT_ARMOR_MAGIC {
        return Err("Invalid .vault file: bad magic header".to_string());
    }

    let mut offset = VAULT_ARMOR_MAGIC.len();

    // Parse algorithm
    let algorithm_byte = armor_data[offset];
    let security_level = match algorithm_byte {
        0x01 => SecurityLevel::Level1,
        0x02 => SecurityLevel::Level3,
        0x03 => SecurityLevel::Level5,
        _ => {
            return Err(
                format!("Unsupported Kyber algorithm: 0x{:02x}", algorithm_byte).to_string(),
            );
        }
    };
    offset += 1;

    // Parse ciphertext length
    let ciphertext_len = u32::from_le_bytes([
        armor_data[offset],
        armor_data[offset + 1],
        armor_data[offset + 2],
        armor_data[offset + 3],
    ]) as usize;
    offset += 4;

    if offset + ciphertext_len > armor_data.len() {
        return Err("Invalid .vault file: ciphertext length exceeds file size".to_string());
    }

    // Extract Kyber ciphertext
    let kyber_ciphertext = armor_data[offset..offset + ciphertext_len].to_vec();
    offset += ciphertext_len;

    // Extract AES encrypted data (remaining bytes)
    let encrypted_data = armor_data[offset..].to_vec();

    Ok((security_level, kyber_ciphertext, encrypted_data))
}

// SUBTASK4: PQCrypto key management functions

/// Load PQCrypto public key from external file (for lock operation)
async fn load_pq_public_key_from_file(key_path: &std::path::Path) -> Result<Vec<u8>, String> {
    let key_data = tokio::fs::read(key_path).await.map_err(|e| e.to_string())?;

    // For ML-KEM-768 (Level3): public key is first 1184 bytes of combined keypair
    if key_data.len() >= 1184 {
        Ok(key_data[..1184].to_vec())
    } else {
        Err("Invalid PQCrypto keypair: too short for public key extraction".to_string())
    }
}

/// Load PQCrypto private key from external file (for unlock operation)  
async fn load_pq_private_key_from_file(key_path: &std::path::Path) -> Result<Vec<u8>, String> {
    let key_data = tokio::fs::read(key_path).await.map_err(|e| e.to_string())?;

    // For ML-KEM-768 (Level3): private key is last portion of combined keypair
    // Debug: check actual key size
    if key_data.len() >= 1184 {
        // Extract private key portion (everything after the public key)
        Ok(key_data[1184..].to_vec())
    } else {
        Err(format!(
            "Invalid PQCrypto keypair: got {} bytes, need at least 1184 for key extraction",
            key_data.len()
        )
        .to_string())
    }
}

/// Load PQCrypto key from OS keychain  
pub async fn load_pq_key_from_keychain(namespace: &str, version: u32) -> Result<Vec<u8>, String> {
    let keychain_store = KeychainStore::for_app("vault");

    let full_key_id = format!("{}:v{}:pq_keypair", namespace, version);

    let key_data = KeyRetriever::new()
        .with_store(keychain_store)
        .with_namespace(namespace)
        .version(version)
        .retrieve(full_key_id)
        .await;

    if key_data.is_empty() {
        return Err("PQCrypto keypair not found in keychain".to_string());
    }

    Ok(key_data)
}

/// Generate and store new PQCrypto keypair
pub async fn generate_pq_keypair(
    namespace: &str,
    version: u32,
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
    let key_id = SimpleKeyId::new(format!("{}:v{}:pq_keypair", namespace, version));

    use std::sync::{Arc, Mutex};

    let error_state = Arc::new(Mutex::new(None::<String>));
    let error_state_clone = Arc::clone(&error_state);

    keychain_store
        .store(&key_id, &keypair)
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
    keychain_namespace: &str,
    key_version: u32,
    use_json: bool,
) -> Result<(), String> {
    // 1. Security validation of all inputs
    let validated_namespace = match validate_keychain_namespace(keychain_namespace) {
        Ok(namespace) => namespace,
        Err(e) => {
            let error_msg = format!("Namespace validation failed: {}", e);
            audit_security_violation(
                "Invalid keychain namespace",
                SecuritySeverity::Medium,
                &error_msg,
            )
            .await;
            return Err(format!("Invalid keychain namespace: {}", e));
        }
    };

    let validated_key_version = match validate_key_version(key_version) {
        Ok(version) => version,
        Err(e) => {
            let error_msg = format!("Key version validation failed: {}", e);
            audit_security_violation("Invalid key version", SecuritySeverity::Medium, &error_msg)
                .await;
            return Err(format!("Invalid key version: {}", e));
        }
    };

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

    // 2. Load or retrieve PQCrypto public key
    let public_key = match pq_public_key {
        Some(key_file) => load_pq_public_key_from_file(key_file).await?,
        None => {
            let combined_key = load_pq_key_from_keychain(keychain_namespace, key_version).await?;
            // Extract public key portion (first 1184 bytes for ML-KEM-768)
            if combined_key.len() >= 1184 {
                combined_key[..1184].to_vec()
            } else {
                return Err("Invalid PQCrypto keypair from keychain: too short".to_string());
            }
        }
    };

    // 3. Read vault database file
    let vault_file_bytes = tokio::fs::read(&db_path).await.map_err(|e| e.to_string())?;

    // 4. Generate random symmetric key using Kyber KEM
    let (ciphertext, shared_secret) = PqCryptoMasterBuilder::new()
        .kyber()
        .with_security_level(SecurityLevel::Level3)
        .encapsulate_hybrid(public_key)
        .await
        .map_err(|e| format!("Kyber encapsulation failed: {}", e))?;

    // 5. Extract AES key from shared secret
    let aes_key = shared_secret;

    // 6. Encrypt vault file with AES-256-GCM
    let encrypted_data = Cipher::aes()
        .with_key(aes_key)
        .on_result(|result| result.unwrap_or_default())
        .encrypt(vault_file_bytes)
        .await;

    // 7. Create .vault file with hybrid format
    let armor_data = create_armor_file_format(
        SecurityLevel::Level3,
        &ciphertext, // Kyber ciphertext for decapsulation
        encrypted_data.as_ref(),
    )?;

    // 8. Atomic file operations
    let temp_path = vault_path.with_extension("vault.tmp");
    tokio::fs::write(&temp_path, armor_data)
        .await
        .map_err(|e| e.to_string())?;
    tokio::fs::rename(&temp_path, &vault_path)
        .await
        .map_err(|e| e.to_string())?;
    tokio::fs::remove_file(&db_path)
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
    keychain_namespace: &str,
    key_version: u32,
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

    // 2. Load or retrieve PQCrypto private key
    let private_key = match pq_private_key {
        Some(key_file) => load_pq_private_key_from_file(key_file).await?,
        None => {
            let combined_key = load_pq_key_from_keychain(keychain_namespace, key_version).await?;
            // Extract private key portion (everything after public key)
            if combined_key.len() >= 1184 {
                combined_key[1184..].to_vec()
            } else {
                return Err(format!(
                    "Invalid PQCrypto keypair from keychain: got {} bytes, need at least 1184",
                    combined_key.len()
                )
                .to_string());
            }
        }
    };

    // 3. Parse .vault file format
    let armor_data = tokio::fs::read(&vault_path)
        .await
        .map_err(|e| e.to_string())?;
    let (kyber_algorithm, kyber_ciphertext, encrypted_data) = parse_armor_file_format(&armor_data)?;

    // 4. Decapsulate symmetric key using Kyber KEM
    let shared_secret = PqCryptoMasterBuilder::new()
        .kyber()
        .with_security_level(kyber_algorithm)
        .decapsulate_hybrid(private_key, kyber_ciphertext)
        .await
        .map_err(|e| format!("Kyber decapsulation failed: {}", e))?;

    // 5. Extract AES key from shared secret
    let aes_key = shared_secret;

    // 6. Decrypt vault file with AES-256-GCM
    let decrypted_data = Cipher::aes()
        .with_key(aes_key)
        .on_result(|result| result.unwrap_or_default())
        .decrypt(encrypted_data)
        .await;

    // 7. Atomic file operations
    let temp_path = db_path.with_extension("db.tmp");
    tokio::fs::write(&temp_path, decrypted_data)
        .await
        .map_err(|e| e.to_string())?;
    tokio::fs::rename(&temp_path, &db_path)
        .await
        .map_err(|e| e.to_string())?;
    tokio::fs::remove_file(&vault_path)
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

/// Rotate PQCrypto keys with version increment
pub async fn rotate_pq_keys(
    namespace: &str,
    current_version: u32,
    vault_paths: Vec<std::path::PathBuf>,
) -> Result<u32, String> {
    let new_version = current_version + 1;

    // Generate new keypair with incremented version
    generate_pq_keypair(namespace, new_version, SecurityLevel::Level3)
        .await
        .map_err(|e| e.to_string())?;

    // Re-encrypt all existing vaults with new keys
    for vault_path in vault_paths {
        if vault_path.with_extension("vault").exists() {
            // Decrypt with old keys
            handle_unlock_command(
                &vault_path,
                None, // Use keychain
                namespace,
                current_version,
                false,
            )
            .await
            .map_err(|e| e.to_string())?;

            // Re-encrypt with new keys
            handle_lock_command(
                &vault_path,
                None, // Use keychain
                namespace,
                new_version,
                false,
            )
            .await
            .map_err(|e| e.to_string())?;
        }
    }

    Ok(new_version)
}

/// Detect the highest version number for keys in a namespace
pub async fn detect_current_key_version(namespace: &str) -> Result<u32, String> {
    // Start from version 1 and increment until no key found
    let mut version = 1;
    loop {
        match load_pq_key_from_keychain(namespace, version).await {
            Ok(_) => version += 1,
            Err(_) => {
                if version == 1 {
                    return Err("No keys found in keychain for namespace".to_string());
                }
                return Ok(version - 1);
            }
        }

        // Safety check to prevent infinite loops
        if version > 1000000 {
            return Err("Version detection exceeded reasonable limit".to_string());
        }
    }
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
    async fn test_armor_file_format_roundtrip() {
        // Test .vault format creation and parsing
        let test_data = b"test vault database content";
        let ciphertext = b"kyber_ciphertext_example";

        let armor_data =
            create_armor_file_format(SecurityLevel::Level3, ciphertext, test_data).unwrap();

        let (algorithm, extracted_ct, extracted_data) =
            parse_armor_file_format(&armor_data).unwrap();

        assert_eq!(algorithm, SecurityLevel::Level3);
        assert_eq!(extracted_ct, ciphertext);
        assert_eq!(extracted_data, test_data);
    }

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
        handle_lock_command(
            &vault_path,
            Some(&public_key_file), // Use public key file for encryption
            "test_namespace",
            1,
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
            "test_namespace",
            1,
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
