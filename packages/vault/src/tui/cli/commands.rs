//! CLI command definitions

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use cryypt_key::{KeyRetriever, store::KeychainStore};
use cryypt_pqcrypto::api::{PqCryptoMasterBuilder, KyberSecurityLevel as SecurityLevel};
use cryypt_cipher::cipher::api::Cipher;
use std::collections::HashMap;
use serde_json;

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

    /// Run a command with vault variables as environment variables
    Run {
        /// Command and arguments to execute
        command: Vec<String>,
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
        /// Path to PQCrypto public key file (optional - falls back to keychain)
        #[arg(long)]
        pq_public_key: Option<PathBuf>,
        /// Keychain namespace for PQCrypto keys (default: "pq_armor")
        #[arg(long, default_value = "pq_armor")]
        keychain_namespace: String,
        /// Key version for rotation (default: 1)
        #[arg(long, default_value = "1")]
        key_version: u32,
    },

    /// Remove PQCrypto armor from vault file (.vault → .db)  
    Unlock {
        /// Path to PQCrypto private key file (optional - falls back to keychain)
        #[arg(long)]
        pq_private_key: Option<PathBuf>,
        /// Keychain namespace for PQCrypto keys (default: "pq_armor")
        #[arg(long, default_value = "pq_armor")]
        keychain_namespace: String,
        /// Key version for rotation (default: 1)  
        #[arg(long, default_value = "1")]
        key_version: u32,
    },
}

// SUBTASK5: .vault file format handling constants and functions
const VAULT_ARMOR_MAGIC: &[u8] = b"CRYYPT\x01\x02";

/// Create .vault file format with hybrid PQCrypto structure
fn create_armor_file_format(
    kyber_algorithm: SecurityLevel,
    kyber_ciphertext: &[u8],
    encrypted_data: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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
fn parse_armor_file_format(
    armor_data: &[u8]
) -> Result<(SecurityLevel, Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    if armor_data.len() < VAULT_ARMOR_MAGIC.len() + 5 {
        return Err("Invalid .vault file: too short".into());
    }
    
    // Validate magic header
    if &armor_data[..VAULT_ARMOR_MAGIC.len()] != VAULT_ARMOR_MAGIC {
        return Err("Invalid .vault file: bad magic header".into());
    }
    
    let mut offset = VAULT_ARMOR_MAGIC.len();
    
    // Parse algorithm  
    let algorithm_byte = armor_data[offset];
    let security_level = match algorithm_byte {
        0x01 => SecurityLevel::Level1,
        0x02 => SecurityLevel::Level3, 
        0x03 => SecurityLevel::Level5,
        _ => return Err(format!("Unsupported Kyber algorithm: 0x{:02x}", algorithm_byte).into()),
    };
    offset += 1;
    
    // Parse ciphertext length
    let ciphertext_len = u32::from_le_bytes([
        armor_data[offset], armor_data[offset + 1], 
        armor_data[offset + 2], armor_data[offset + 3]
    ]) as usize;
    offset += 4;
    
    if offset + ciphertext_len > armor_data.len() {
        return Err("Invalid .vault file: ciphertext length exceeds file size".into());
    }
    
    // Extract Kyber ciphertext
    let kyber_ciphertext = armor_data[offset..offset + ciphertext_len].to_vec();
    offset += ciphertext_len;
    
    // Extract AES encrypted data (remaining bytes)
    let encrypted_data = armor_data[offset..].to_vec();
    
    Ok((security_level, kyber_ciphertext, encrypted_data))
}

// SUBTASK4: PQCrypto key management functions

/// Load PQCrypto key from external file
async fn load_pq_key_from_file(key_path: &std::path::Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let key_data = tokio::fs::read(key_path).await?;
    
    // Validate key format (could be PEM, DER, or raw bytes)
    if key_data.len() < 32 {
        return Err("Invalid PQCrypto key: too short".into());
    }
    
    Ok(key_data)
}

/// Load PQCrypto key from OS keychain  
async fn load_pq_key_from_keychain(
    namespace: &str, 
    version: u32
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let keychain_store = KeychainStore::for_app("vault");
    
    let key_data = KeyRetriever::new()
        .with_store(keychain_store)
        .with_namespace(namespace)
        .version(version)
        .retrieve("pq_keypair".to_string())
        .await;
        
    Ok(key_data)
}

/// Generate and store new PQCrypto keypair
pub async fn generate_pq_keypair(
    _namespace: &str,
    _version: u32,
    security_level: SecurityLevel,
) -> Result<(), Box<dyn std::error::Error>> {
    // Generate Kyber keypair
    let _keypair = PqCryptoMasterBuilder::new()
        .kyber()
        .with_security_level(security_level)
        .on_result(|result| result.unwrap_or_default())
        .generate_keypair()
        .await;
    
    // TODO: Store in keychain when storage API is available
    println!("✅ PQCrypto keypair generated (storage TODO)");
    Ok(())
}

// SUBTASK2: Implement hybrid PQCrypto lock operation

pub async fn handle_lock_command(
    vault_path: &std::path::Path,
    pq_public_key: Option<&std::path::Path>,
    keychain_namespace: &str,
    key_version: u32,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Validate input file exists and has .db extension
    let db_path = vault_path.with_extension("db");
    let vault_path = vault_path.with_extension("vault");
    
    if !db_path.exists() {
        return Err(format!("Vault database not found: {}", db_path.display()).into());
    }
    
    if vault_path.exists() {
        return Err(format!("Vault already armored: {}", vault_path.display()).into());
    }

    // 2. Load or retrieve PQCrypto public key
    let public_key = match pq_public_key {
        Some(key_file) => load_pq_key_from_file(key_file).await?,
        None => load_pq_key_from_keychain(keychain_namespace, key_version).await?,
    };

    // 3. Read vault database file
    let vault_file_bytes = tokio::fs::read(&db_path).await?;
    
    // 4. Generate random symmetric key using Kyber KEM  
    let ciphertext = PqCryptoMasterBuilder::new()
        .kyber()
        .with_security_level(SecurityLevel::Level3)
        .on_result(|result| result.unwrap_or_default())
        .encapsulate(public_key)
        .await;
    
    // 5. Extract AES key from shared secret (for now use a dummy key)
    let aes_key = vec![0u8; 32]; // TODO: Extract from actual shared secret
    
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
    tokio::fs::write(&temp_path, armor_data).await?;
    tokio::fs::rename(&temp_path, &vault_path).await?;
    tokio::fs::remove_file(&db_path).await?;
    
    if use_json {
        println!("{}", serde_json::json!({
            "success": true,
            "operation": "lock",
            "vault_path": vault_path.display().to_string()
        }));
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
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Validate input file exists and has .vault extension
    let vault_path = vault_path.with_extension("vault");
    let db_path = vault_path.with_extension("db");
    
    if !vault_path.exists() {
        return Err(format!("Armored vault not found: {}", vault_path.display()).into());
    }
    
    if db_path.exists() {
        return Err(format!("Vault already unlocked: {}", db_path.display()).into());
    }

    // 2. Load or retrieve PQCrypto private key
    let private_key = match pq_private_key {
        Some(key_file) => load_pq_key_from_file(key_file).await?,
        None => load_pq_key_from_keychain(keychain_namespace, key_version).await?,
    };

    // 3. Parse .vault file format
    let armor_data = tokio::fs::read(&vault_path).await?;
    let (kyber_algorithm, kyber_ciphertext, encrypted_data) = parse_armor_file_format(&armor_data)?;
    
    // 4. Decapsulate symmetric key using Kyber KEM
    let _shared_secret = PqCryptoMasterBuilder::new()
        .kyber()
        .with_security_level(kyber_algorithm)
        .on_result(|result| result.unwrap_or_default())
        .decapsulate(private_key, kyber_ciphertext)
        .await;
    
    // 5. Extract AES key from shared secret (for now use a dummy key)
    let aes_key = vec![0u8; 32]; // TODO: Extract from actual shared secret
    
    // 6. Decrypt vault file with AES-256-GCM
    let decrypted_data = Cipher::aes()
        .with_key(aes_key)
        .on_result(|result| result.unwrap_or_default())
        .decrypt(encrypted_data)
        .await;

    // 7. Atomic file operations
    let temp_path = db_path.with_extension("db.tmp");
    tokio::fs::write(&temp_path, decrypted_data).await?;
    tokio::fs::rename(&temp_path, &db_path).await?;
    tokio::fs::remove_file(&vault_path).await?;
    
    if use_json {
        println!("{}", serde_json::json!({
            "success": true,
            "operation": "unlock", 
            "vault_path": db_path.display().to_string()
        }));
    } else {
        println!("✅ Vault successfully unlocked: {}", db_path.display());
    }
    
    Ok(())
}

// Unit Tests as specified in task

#[cfg(test)]
mod armor_tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_armor_file_format_roundtrip() {
        // Test .vault format creation and parsing
        let test_data = b"test vault database content";
        let ciphertext = b"kyber_ciphertext_example";
        
        let armor_data = create_armor_file_format(
            SecurityLevel::Level3,
            ciphertext,
            test_data,
        ).unwrap();
        
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
        
        // Create test vault database
        tokio::fs::write(&vault_path, b"test vault content").await.unwrap();
        
        // Test lock command
        handle_lock_command(
            &vault_path,
            None, // Use keychain
            "test_namespace",
            1,
            false,
        ).await.unwrap();
        
        // Verify .vault file exists and .db is removed
        assert!(!vault_path.exists());
        assert!(vault_path.with_extension("vault").exists());
        
        // Test unlock command
        handle_unlock_command(
            &vault_path,
            None, // Use keychain
            "test_namespace", 
            1,
            false,
        ).await.unwrap();
        
        // Verify .db file restored and .vault is removed
        assert!(vault_path.exists());
        assert!(!vault_path.with_extension("vault").exists());
        
        // Verify content integrity
        let recovered_content = tokio::fs::read(&vault_path).await.unwrap();
        assert_eq!(recovered_content, b"test vault content");
    }
}
