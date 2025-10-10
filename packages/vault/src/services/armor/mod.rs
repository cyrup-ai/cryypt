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
//! +------------------+
//! | Magic (8 bytes)  |  "CRYYPT\x01\x02"
//! +------------------+
//! | Algorithm (1)    |  0x01=Level1, 0x02=Level3, 0x03=Level5
//! +------------------+
//! | CT Length (4)    |  u32 little-endian
//! +------------------+
//! | Kyber CT (var)   |  KEM ciphertext
//! +------------------+
//! | AES Data (var)   |  Encrypted vault file
//! +------------------+
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
const VAULT_ARMOR_MAGIC: &[u8] = b"CRYYPT\x01\x02";

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
///     "pq_armor",
///     1
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
    /// * `namespace` - Key namespace (e.g., "pq_armor")
    /// * `version` - Key version number
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
        namespace: &str,
        version: u32,
    ) -> VaultResult<()> {
        log_security_event(
            "ARMOR_START",
            &format!("Starting PQCrypto armor: {} → {}", db_path.display(), vault_path.display()),
            true,
        );

        // Step 1: Retrieve PQCrypto keypair from storage
        let keypair = self.key_storage.retrieve(namespace, version).await?;

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
            .on_result(|result| result.unwrap_or_default())
            .encrypt(vault_data)
            .await;

        if encrypted_data.is_empty() {
            return Err(VaultError::Encryption(
                "AES encryption failed - empty result".to_string(),
            ));
        }

        log::debug!("AES encryption: {} bytes encrypted", encrypted_data.len());

        // Step 5: Create .vault file format
        let armor_data = Self::create_armor_format(self.security_level, &ciphertext, &encrypted_data)?;

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
    /// * `namespace` - Key namespace (e.g., "pq_armor")
    /// * `version` - Key version number
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
        namespace: &str,
        version: u32,
    ) -> VaultResult<()> {
        log_security_event(
            "UNARMOR_START",
            &format!("Starting PQCrypto unarmor: {} → {}", vault_path.display(), db_path.display()),
            true,
        );

        // Step 1: Retrieve PQCrypto keypair from storage
        let keypair = self.key_storage.retrieve(namespace, version).await?;

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

        let (security_level, kyber_ciphertext, encrypted_data) =
            Self::parse_armor_format(&armor_data)?;

        log::debug!(
            "Parsed armor: {:?}, {} byte ciphertext, {} bytes encrypted data",
            security_level,
            kyber_ciphertext.len(),
            encrypted_data.len()
        );

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
            .on_result(|result| result.unwrap_or_default())
            .decrypt(encrypted_data)
            .await;

        if decrypted_data.is_empty() {
            return Err(VaultError::Decryption(
                "AES decryption failed - empty result".to_string(),
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
    ) -> VaultResult<(SecurityLevel, Vec<u8>, Vec<u8>)> {
        if armor_data.len() < VAULT_ARMOR_MAGIC.len() + 5 {
            return Err(VaultError::Crypto(
                "Invalid .vault file: too short".to_string(),
            ));
        }

        // Validate magic header
        if &armor_data[..VAULT_ARMOR_MAGIC.len()] != VAULT_ARMOR_MAGIC {
            return Err(VaultError::Crypto(
                "Invalid .vault file: bad magic header".to_string(),
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

        // Parse ciphertext length
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

        Ok((security_level, kyber_ciphertext, encrypted_data))
    }
}
