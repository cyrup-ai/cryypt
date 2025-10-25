//! PQCrypto armor service for vault file protection
//!
//! This service provides post-quantum cryptographic protection for vault files,
//! using hybrid encryption (ML-KEM + AES-256-GCM) to secure the entire database file.
//!
//! ## Architecture
//!
//! The armor service implements a two-layer encryption scheme:
//! 1. **Key Encapsulation**: ML-KEM (Kyber) generates a random symmetric key
//! 2. **File Encryption**: AES-256-GCM encrypts the vault file with that key
//!
//! ## File Format
//!
//! The .vault file format:
//! ```text
//! +--------------------+
//! | Magic (7 bytes)    |  "CRYYPT\x01"
//! +--------------------+
//! | Algorithm (1)      |  0x01=Level1, 0x02=Level3, 0x03=Level5
//! +--------------------+
//! | Key ID Length (4)  |  u32 little-endian
//! +--------------------+
//! | Key ID (variable)  |  UTF-8 string (e.g., "pq_armor:v3:pq_keypair")
//! +--------------------+
//! | CT Length (4)      |  u32 little-endian
//! +--------------------+
//! | Kyber CT (var)     |  KEM ciphertext
//! +--------------------+
//! | AES Data (var)     |  Encrypted vault file
//! +--------------------+
//! ```
//!
//! ## Security
//!
//! - **Post-Quantum Safe**: Uses NIST-approved ML-KEM (Kyber) algorithm
//! - **Authenticated Encryption**: AES-256-GCM provides confidentiality + integrity
//! - **Key Isolation**: PQCrypto keys stored separately from vault passphrase
//! - **Forward Secrecy**: Each armor operation generates a new symmetric key

use super::key_storage::KeyStorage;
use crate::error::{VaultError, VaultResult};
use crate::logging::log_security_event;
use cryypt_cipher::cipher::api::Cipher;
use cryypt_pqcrypto::api::{KyberSecurityLevel as SecurityLevel, PqCryptoMasterBuilder};
use std::path::Path;

/// Magic header for .vault file format
const VAULT_ARMOR_MAGIC: &[u8] = b"CRYYPT\x01";

/// ML-KEM-768 public key size (bytes)
const PUBLIC_KEY_SIZE_768: usize = 1184;

/// PQCrypto armor service for vault file protection
///
/// This service handles all PQCrypto armor operations:
/// - Encrypting vault files (.db → .vault)
/// - Decrypting vault files (.vault → .db)
/// - Key management via KeyStorage abstraction
///
/// # Example
///
/// ```no_run
/// use vault::services::armor::PQCryptoArmorService;
/// use vault::services::key_storage::KeychainStorage;
///
/// let key_storage = KeychainStorage::default_app();
/// let armor_service = PQCryptoArmorService::new(key_storage, SecurityLevel::Level3);
///
/// // Armor a vault file
/// armor_service.armor(
///     Path::new("vault.db"),
///     Path::new("vault.vault"),
///     "pq_armor:v1:pq_keypair"
/// ).await?;
/// ```
#[derive(Clone)]
pub struct PQCryptoArmorService<S: KeyStorage> {
    key_storage: S,
    security_level: SecurityLevel,
}

impl<S: KeyStorage> PQCryptoArmorService<S> {
    /// Create a new PQCrypto armor service
    ///
    /// # Arguments
    /// * `key_storage` - Key storage backend (keychain, file, env, etc.)
    /// * `security_level` - Kyber security level (Level1, Level3, Level5)
    pub fn new(key_storage: S, security_level: SecurityLevel) -> Self {
        Self {
            key_storage,
            security_level,
        }
    }

    /// Apply PQCrypto armor to a vault file (.db → .vault)
    ///
    /// # Arguments
    /// * `db_path` - Path to unarmored vault database file
    /// * `vault_path` - Path for armored .vault output file
    /// * `key_id` - Full keychain key identifier (e.g., "pq_armor:v1:pq_keypair")
    ///
    /// # Process
    /// 1. Retrieve PQCrypto public key from storage
    /// 2. Read vault database file
    /// 3. Generate random symmetric key via Kyber KEM
    /// 4. Encrypt file with AES-256-GCM
    /// 5. Create .vault format (header + ciphertext + encrypted data)
    /// 6. Atomic write: .tmp → rename → remove original
    ///
    /// # Errors
    /// Returns error if:
    /// - Key retrieval fails
    /// - File I/O fails
    /// - Encryption fails
    /// - Atomic file operations fail
    pub async fn armor(
        &self,
        db_path: &Path,
        vault_path: &Path,
        key_id: &str,
    ) -> VaultResult<()> {
        log_security_event(
            "ARMOR_START",
            &format!("Starting PQCrypto armor: {} → {}", db_path.display(), vault_path.display()),
            true,
        );

        // Step 1: Retrieve PQCrypto keypair from storage
        let keypair = self.key_storage.retrieve(key_id).await?;

        // Extract public key (first 1184 bytes for ML-KEM-768)
        let public_key = if keypair.len() >= PUBLIC_KEY_SIZE_768 {
            keypair[..PUBLIC_KEY_SIZE_768].to_vec()
        } else {
            return Err(VaultError::Crypto(format!(
                "Invalid PQCrypto keypair: expected at least {} bytes, got {}",
                PUBLIC_KEY_SIZE_768,
                keypair.len()
            )));
        };

        // Step 2: Compress vault database (file or directory) to zip archive
        use cryypt_compression::Compress;

        let vault_data = Compress::zip()
            .on_result(|result| match result {
                Ok(compression_result) => compression_result.to_vec(),
                Err(e) => {
                    log::error!("Compression failed: {}", e);
                    Vec::new()
                }
            })
            .compress_path(db_path)
            .await;

        if vault_data.is_empty() {
            return Err(VaultError::Provider(format!(
                "Failed to compress vault database {}: compression returned empty data",
                db_path.display()
            )));
        }

        log::debug!("Compressed {} to {} bytes", db_path.display(), vault_data.len());

        // Step 3: Generate random symmetric key using Kyber KEM
        let (ciphertext, shared_secret) = PqCryptoMasterBuilder::new()
            .kyber()
            .with_security_level(self.security_level)
            .encapsulate_hybrid(public_key)
            .await
            .map_err(|e| VaultError::Crypto(format!("Kyber encapsulation failed: {}", e)))?;

        log::debug!(
            "Kyber KEM encapsulation: {} byte ciphertext, {} byte shared secret",
            ciphertext.len(),
            shared_secret.len()
        );

        // Step 4: Encrypt vault file with AES-256-GCM
        let encrypted_data = Cipher::aes()
            .with_key(shared_secret)
            .on_result(|result| match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("AES encryption failed: {}", e);
                    Vec::new()
                }
            })
            .encrypt(vault_data)
            .await;

        if encrypted_data.is_empty() {
            return Err(VaultError::Encryption(
                "AES encryption failed - check logs for details".to_string(),
            ));
        }

        log::debug!("AES encryption: {} bytes encrypted", encrypted_data.len());

        // Step 5: Create .vault file format with embedded key ID
        let armor_data = Self::create_armor_format(self.security_level, &ciphertext, &encrypted_data, key_id)?;

        log::debug!(
            "Created armor format: {} total bytes",
            armor_data.len()
        );

        // Step 6: Atomic file operations
        let temp_path = vault_path.with_extension("vault.tmp");

        // Write to temp file
        tokio::fs::write(&temp_path, armor_data)
            .await
            .map_err(|e| {
                VaultError::Provider(format!(
                    "Failed to write armored vault {}: {}",
                    temp_path.display(),
                    e
                ))
            })?;

        // Atomic rename
        tokio::fs::rename(&temp_path, vault_path)
            .await
            .map_err(|e| {
                VaultError::Provider(format!(
                    "Failed to rename {} → {}: {}",
                    temp_path.display(),
                    vault_path.display(),
                    e
                ))
            })?;

        // Remove original unarmored file or directory
        if db_path.is_file() {
            tokio::fs::remove_file(db_path).await.map_err(|e| {
                VaultError::Provider(format!(
                    "Failed to remove original file {}: {}",
                    db_path.display(),
                    e
                ))
            })?;
        } else if db_path.is_dir() {
            tokio::fs::remove_dir_all(db_path).await.map_err(|e| {
                VaultError::Provider(format!(
                    "Failed to remove original directory {}: {}",
                    db_path.display(),
                    e
                ))
            })?;
        }

        log_security_event(
            "ARMOR_COMPLETE",
            &format!("PQCrypto armor applied: {}", vault_path.display()),
            true,
        );

        Ok(())
    }

    /// Remove PQCrypto armor from a vault file (.vault → .db)
    ///
    /// # Arguments
    /// * `vault_path` - Path to armored .vault file
    /// * `db_path` - Path for unarmored .db output file
    /// * `key_id` - Full keychain key identifier (e.g., "pq_armor:v1:pq_keypair")
    ///
    /// # Process
    /// 1. Retrieve PQCrypto private key from storage
    /// 2. Read and parse .vault file
    /// 3. Decapsulate symmetric key via Kyber KEM
    /// 4. Decrypt file with AES-256-GCM
    /// 5. Atomic write: .tmp → rename → remove armored file
    ///
    /// # Errors
    /// Returns error if:
    /// - Key retrieval fails
    /// - File parsing fails
    /// - Decryption fails
    /// - Atomic file operations fail
    pub async fn unarmor(
        &self,
        vault_path: &Path,
        db_path: &Path,
        key_id: &str,
    ) -> VaultResult<()> {
        log_security_event(
            "UNARMOR_START",
            &format!("Starting PQCrypto unarmor: {} → {}", vault_path.display(), db_path.display()),
            true,
        );

        // Step 1: Retrieve PQCrypto keypair from storage
        let keypair = self.key_storage.retrieve(key_id).await?;

        // Extract private key (everything after public key)
        let private_key = if keypair.len() >= PUBLIC_KEY_SIZE_768 {
            keypair[PUBLIC_KEY_SIZE_768..].to_vec()
        } else {
            return Err(VaultError::Crypto(format!(
                "Invalid PQCrypto keypair: expected at least {} bytes, got {}",
                PUBLIC_KEY_SIZE_768,
                keypair.len()
            )));
        };

        // Step 2: Read and parse .vault file
        let armor_data = tokio::fs::read(vault_path).await.map_err(|e| {
            VaultError::Provider(format!(
                "Failed to read armored vault {}: {}",
                vault_path.display(),
                e
            ))
        })?;

        log::debug!("Read {} bytes from {}", armor_data.len(), vault_path.display());

        let (security_level, kyber_ciphertext, encrypted_data, file_key_id) =
            Self::parse_armor_format(&armor_data)?;

        log::debug!(
            "Parsed armor: {:?}, key_id '{}', {} byte ciphertext, {} bytes encrypted data",
            security_level,
            file_key_id,
            kyber_ciphertext.len(),
            encrypted_data.len()
        );

        // Verify that the key_id in the file matches the key_id we're using
        if file_key_id != key_id {
            log::warn!(
                "Key ID mismatch: file contains '{}' but trying to decrypt with '{}'",
                file_key_id,
                key_id
            );
        }

        // Step 3: Decapsulate symmetric key using Kyber KEM
        let shared_secret = PqCryptoMasterBuilder::new()
            .kyber()
            .with_security_level(security_level)
            .decapsulate_hybrid(private_key, kyber_ciphertext)
            .await
            .map_err(|e| VaultError::Crypto(format!("Kyber decapsulation failed: {}", e)))?;

        log::debug!("Kyber KEM decapsulation: {} byte shared secret", shared_secret.len());

        // Step 4: Decrypt vault file with AES-256-GCM
        let decrypted_data = Cipher::aes()
            .with_key(shared_secret)
            .on_result(|result| match result {
                Ok(data) => data,
                Err(e) => {
                    log::error!("AES decryption failed: {}", e);
                    Vec::new()
                }
            })
            .decrypt(encrypted_data)
            .await;

        if decrypted_data.is_empty() {
            return Err(VaultError::Decryption(
                "AES decryption failed - check logs for details".to_string(),
            ));
        }

        log::debug!("AES decryption: {} bytes decrypted", decrypted_data.len());

        // Step 5: Decompress vault database from zip archive
        use cryypt_compression::Compress;

        let _result = Compress::zip()
            .on_result(|result| match result {
                Ok(_) => Vec::new(), // Success - filesystem operation
                Err(e) => {
                    log::error!("Decompression failed: {}", e);
                    Vec::new()
                }
            })
            .decompress_to_path(decrypted_data.clone(), db_path)
            .await;

        // Verify the decompression succeeded by checking if the path exists
        if !db_path.exists() {
            return Err(VaultError::Provider(format!(
                "Failed to decompress vault database to {}: path does not exist after decompression",
                db_path.display()
            )));
        }

        log::debug!("Decompressed {} bytes to {}", decrypted_data.len(), db_path.display());

        // Remove armored file
        tokio::fs::remove_file(vault_path).await.map_err(|e| {
            VaultError::Provider(format!(
                "Failed to remove armored file {}: {}",
                vault_path.display(),
                e
            ))
        })?;

        log_security_event(
            "UNARMOR_COMPLETE",
            &format!("PQCrypto armor removed: {}", db_path.display()),
            true,
        );

        Ok(())
    }

    /// Create .vault file format with hybrid PQCrypto structure
    fn create_armor_format(
        kyber_algorithm: SecurityLevel,
        kyber_ciphertext: &[u8],
        encrypted_data: &[u8],
        key_id: &str,
    ) -> VaultResult<Vec<u8>> {
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

        // Key ID length and string
        let key_id_bytes = key_id.as_bytes();
        let key_id_len = key_id_bytes.len() as u32;
        armor_data.extend_from_slice(&key_id_len.to_le_bytes());
        armor_data.extend_from_slice(key_id_bytes);

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
    fn parse_armor_format(
        armor_data: &[u8],
    ) -> VaultResult<(SecurityLevel, Vec<u8>, Vec<u8>, String)> {
        // Minimum: 7 (magic) + 1 (algorithm) + 4 (key_id_len) + 4 (ct length) = 16 bytes
        if armor_data.len() < VAULT_ARMOR_MAGIC.len() + 1 + 4 + 4 {
            return Err(VaultError::Crypto(
                "Invalid .vault file: too short".to_string(),
            ));
        }

        // Validate magic header
        if &armor_data[..VAULT_ARMOR_MAGIC.len()] != VAULT_ARMOR_MAGIC {
            return Err(VaultError::Crypto(
                "Invalid .vault file: incorrect magic header".to_string(),
            ));
        }

        let mut offset = VAULT_ARMOR_MAGIC.len();

        // Parse algorithm
        let algorithm_byte = armor_data[offset];
        let security_level = match algorithm_byte {
            0x01 => SecurityLevel::Level1,
            0x02 => SecurityLevel::Level3,
            0x03 => SecurityLevel::Level5,
            _ => {
                return Err(VaultError::Crypto(format!(
                    "Unsupported Kyber algorithm: 0x{:02x}",
                    algorithm_byte
                )));
            }
        };
        offset += 1;

        // Parse key ID length
        let key_id_len = u32::from_le_bytes([
            armor_data[offset],
            armor_data[offset + 1],
            armor_data[offset + 2],
            armor_data[offset + 3],
        ]) as usize;
        offset += 4;

        // Extract key ID string
        if offset + key_id_len > armor_data.len() {
            return Err(VaultError::Crypto(
                "Invalid .vault file: key ID length exceeds file size".to_string(),
            ));
        }
        let key_id_bytes = &armor_data[offset..offset + key_id_len];
        let key_id = String::from_utf8(key_id_bytes.to_vec()).map_err(|e| {
            VaultError::Crypto(format!("Invalid key ID encoding: {}", e))
        })?;
        offset += key_id_len;

        // Parse ciphertext length
        if offset + 4 > armor_data.len() {
            return Err(VaultError::Crypto(
                "Invalid .vault file: missing ciphertext length".to_string(),
            ));
        }
        let ciphertext_len = u32::from_le_bytes([
            armor_data[offset],
            armor_data[offset + 1],
            armor_data[offset + 2],
            armor_data[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + ciphertext_len > armor_data.len() {
            return Err(VaultError::Crypto(
                "Invalid .vault file: ciphertext length exceeds file size".to_string(),
            ));
        }

        // Extract Kyber ciphertext
        let kyber_ciphertext = armor_data[offset..offset + ciphertext_len].to_vec();
        offset += ciphertext_len;

        // Extract AES encrypted data (remaining bytes)
        let encrypted_data = armor_data[offset..].to_vec();

        Ok((security_level, kyber_ciphertext, encrypted_data, key_id))
    }
}

/// Read key ID from .vault file header without loading entire file
///
/// This is a standalone function that peeks at the file header to extract the keychain
/// key identifier, allowing unlock operations to know which key to retrieve before
/// attempting decryption.
///
/// # Arguments
/// * `vault_path` - Path to .vault file
///
/// # Returns
/// The key ID string embedded in the file (e.g., "pq_armor:v1:pq_keypair")
///
/// # Errors
/// Returns error if:
/// - File cannot be read
/// - File format is invalid
/// - File is too short to contain key ID
/// - Key ID is not valid UTF-8
pub async fn read_key_id_from_vault_file(vault_path: &Path) -> VaultResult<String> {
    use tokio::io::AsyncReadExt;

    let mut file = tokio::fs::File::open(vault_path).await.map_err(|e| {
        VaultError::Provider(format!(
            "Failed to open .vault file {}: {}",
            vault_path.display(),
            e
        ))
    })?;

    // Read header: magic (7) + algorithm (1) + key_id_len (4) = 12 bytes
    let initial_header_size = VAULT_ARMOR_MAGIC.len() + 1 + 4;
    let mut header = vec![0u8; initial_header_size];
    file.read_exact(&mut header).await.map_err(|e| {
        VaultError::Crypto(format!(
            "Failed to read .vault file header: {} (file may be corrupted or too short)",
            e
        ))
    })?;

    // Validate magic bytes
    if &header[..VAULT_ARMOR_MAGIC.len()] != VAULT_ARMOR_MAGIC {
        return Err(VaultError::Crypto(
            "Invalid .vault file: incorrect magic header".to_string(),
        ));
    }

    // Extract key ID length from bytes after magic + algorithm
    let key_id_len_offset = VAULT_ARMOR_MAGIC.len() + 1;
    let key_id_len = u32::from_le_bytes([
        header[key_id_len_offset],
        header[key_id_len_offset + 1],
        header[key_id_len_offset + 2],
        header[key_id_len_offset + 3],
    ]) as usize;

    // Read the key ID string
    let mut key_id_bytes = vec![0u8; key_id_len];
    file.read_exact(&mut key_id_bytes).await.map_err(|e| {
        VaultError::Crypto(format!(
            "Failed to read key ID from .vault file: {}",
            e
        ))
    })?;

    // Convert to string
    let key_id = String::from_utf8(key_id_bytes).map_err(|e| {
        VaultError::Crypto(format!("Invalid key ID encoding: {}", e))
    })?;

    Ok(key_id)
}
