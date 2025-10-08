//! Cryptographic operations for vault data protection
//!
//! Contains encryption, decryption, key derivation, and secure data handling.

use super::super::LocalVaultProvider;
use crate::error::{VaultError, VaultResult};
use crate::operation::Passphrase;
use cryypt_cipher::Cryypt;
use cryypt_key::api::{MasterKeyBuilder, MasterKeyProvider};
use cryypt_pqcrypto::api::KyberSecurityLevel as SecurityLevel;
use secrecy::ExposeSecret;

const VAULT_ARMOR_MAGIC: &[u8] = b"CRYYPT\x01\x02";

impl LocalVaultProvider {
    /// Derive encryption key from passphrase using cryypt_key
    pub(crate) async fn derive_encryption_key(
        &self,
        passphrase: &Passphrase,
    ) -> VaultResult<Vec<u8>> {
        log::trace!("Starting passphrase-based key derivation...");

        // Use cryypt_key PassphraseMasterKey for secure key derivation
        let master_key = MasterKeyBuilder::from_passphrase(passphrase.expose_secret());
        let key_bytes = master_key
            .resolve()
            .map_err(|e| VaultError::KeyDerivation(format!("Key derivation failed: {e}")))?;

        log::trace!("Successfully derived {} byte key", key_bytes.len());

        let output_key = key_bytes.to_vec();

        // Store derived key in memory for session
        let mut key_guard = self.encryption_key.lock().await;
        *key_guard = Some(output_key.clone());

        Ok(output_key)
    }

    /// Derive JWT signing key from passphrase using cryypt_key with different context
    pub(crate) async fn derive_jwt_key(&self, passphrase: &Passphrase) -> VaultResult<Vec<u8>> {
        log::trace!("Starting JWT key derivation with passphrase context...");

        // Create JWT-specific input by combining passphrase with context
        let jwt_context = "JWT_SIGNING_CONTEXT";
        let combined_input = format!("{}:{}", passphrase.expose_secret(), jwt_context);

        // Use cryypt_key PassphraseMasterKey for secure JWT key derivation
        let master_key = MasterKeyBuilder::from_passphrase(&combined_input);
        let key_bytes = master_key
            .resolve()
            .map_err(|e| VaultError::KeyDerivation(format!("JWT key derivation failed: {e}")))?;

        log::trace!(
            "Successfully derived {} byte JWT signing key",
            key_bytes.len()
        );

        let jwt_output_key = key_bytes.to_vec();

        // Store derived JWT key in memory for session
        let mut jwt_key_guard = self.jwt_key.lock().await;
        *jwt_key_guard = Some(jwt_output_key.clone());

        Ok(jwt_output_key)
    }

    /// Encrypt data using AES with session key
    pub(crate) async fn encrypt_data(&self, data: &[u8]) -> VaultResult<Vec<u8>> {
        // Get the encryption key from session
        let key_guard = self.encryption_key.lock().await;
        let encryption_key = key_guard.as_ref().ok_or_else(|| VaultError::VaultLocked)?;

        log::trace!(
            "Encrypting {} bytes with {} byte key",
            data.len(),
            encryption_key.len()
        );

        // Use AES encryption with cryypt_cipher - proper error handling
        let encrypted_data = Cryypt::cipher()
            .aes()
            .with_key(encryption_key.clone())
            .encrypt(data.to_vec())
            .await;

        // Check for encryption failure (empty result indicates error per API documentation)
        if encrypted_data.is_empty() {
            let detailed_error = format!(
                "AES encryption failed - input size: {} bytes, key size: {} bytes",
                data.len(),
                encryption_key.len()
            );
            log::error!("Crypto operation failed: {}", detailed_error);
            return Err(VaultError::Encryption(detailed_error));
        }

        log::trace!(
            "Encryption completed successfully, output: {} bytes",
            encrypted_data.len()
        );
        Ok(encrypted_data)
    }

    /// Decrypt data using AES with session key
    pub(crate) async fn decrypt_data(&self, encrypted_data: &[u8]) -> VaultResult<Vec<u8>> {
        // Get the encryption key from session
        let key_guard = self.encryption_key.lock().await;
        let encryption_key = key_guard.as_ref().ok_or_else(|| VaultError::VaultLocked)?;

        log::trace!(
            "Decrypting {} bytes with {} byte key",
            encrypted_data.len(),
            encryption_key.len()
        );

        // Validate input data before attempting decryption
        if encrypted_data.len() < 32 {
            let error_msg = format!(
                "Invalid encrypted data: too short ({} bytes, minimum 32 required)",
                encrypted_data.len()
            );
            log::error!("{}", error_msg);
            return Err(VaultError::Decryption(error_msg));
        }

        // Use AES decryption with cryypt_cipher - proper error handling
        let decrypted_data = Cryypt::cipher()
            .aes()
            .with_key(encryption_key.clone())
            .decrypt(encrypted_data.to_vec())
            .await;

        // Check for decryption failure (empty result indicates error per API documentation)
        if decrypted_data.is_empty() {
            let detailed_error = format!(
                "AES decryption failed - input size: {} bytes, key size: {} bytes, possible causes: corrupted data, wrong key, or invalid format",
                encrypted_data.len(),
                encryption_key.len()
            );
            log::error!("Crypto operation failed: {}", detailed_error);
            return Err(VaultError::Decryption(detailed_error));
        }

        log::trace!(
            "Decryption completed successfully, output: {} bytes",
            decrypted_data.len()
        );
        Ok(decrypted_data)
    }

    /// Get or create salt for key derivation - stored encrypted in SurrealDB
    pub(crate) async fn get_or_create_salt(&self) -> VaultResult<Vec<u8>> {
        use rand::RngCore;

        // Try to retrieve existing salt using natural keys format
        let salt_record_id = super::key_utils::create_record_id("__vault_salt__");
        let query = format!("SELECT * FROM {salt_record_id}");
        let db = self.dao.db();

        let mut result = db
            .query(&query)
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {e}")))?
            .check()
            .map_err(|e| VaultError::Provider(format!("DB check failed: {e}")))?;

        use super::super::VaultEntry;
        let salt_entry: Option<VaultEntry> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {e}")))?;

        match salt_entry {
            Some(entry) => {
                log::debug!("Found existing encrypted salt in database");

                // Decode salt from base64 with robust error handling - use URL_SAFE_NO_PAD for Argon2 compatibility
                use base64::{
                    Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_ARGON2,
                };
                match BASE64_ARGON2.decode(&entry.value) {
                    Ok(salt) => {
                        if salt.len() == 32 {
                            log::debug!("Successfully decoded existing salt from database");
                            Ok(salt)
                        } else {
                            log::warn!(
                                "Salt corrupted: expected exactly 32 bytes, got {}. Generating new salt.",
                                salt.len()
                            );
                            // Generate new salt if existing one is corrupted
                            self.generate_and_store_new_salt().await
                        }
                    }
                    Err(e) => {
                        log::warn!(
                            "Failed to decode existing salt from database ({}). Generating new salt.",
                            e
                        );
                        // Generate new salt if decoding fails
                        self.generate_and_store_new_salt().await
                    }
                }
            }
            None => {
                log::info!("No existing salt found - generating new salt");
                self.generate_and_store_new_salt().await
            }
        }
    }

    /// Generate and store a new salt in the database
    async fn generate_and_store_new_salt(&self) -> VaultResult<Vec<u8>> {
        use rand::RngCore;

        // Generate new salt
        let mut salt = vec![0u8; 32]; // 32 bytes salt
        rand::rng().fill_bytes(&mut salt);

        // Store encrypted salt in database - use URL_SAFE_NO_PAD for Argon2 compatibility
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as BASE64_ARGON2};
        let salt_b64 = BASE64_ARGON2.encode(&salt);

        // Use natural keys format for consistency
        let record_id = super::key_utils::create_record_id("__vault_salt__");
        let upsert_query = format!(
            "UPSERT {} SET value = $value, created_at = $created_at, updated_at = $updated_at",
            record_id
        );

        let db = self.dao.db();
        let now = chrono::Utc::now();
        match db
            .query(upsert_query)
            .bind(("value", salt_b64))
            .bind(("created_at", surrealdb::value::Datetime::from(now)))
            .bind(("updated_at", surrealdb::value::Datetime::from(now)))
            .await
        {
            Ok(_) => {
                log::info!("Generated and stored new encrypted salt in database");
                Ok(salt)
            }
            Err(e) => Err(VaultError::Provider(format!("Failed to store salt: {e}"))),
        }
    }

    /// Create .vault file format with hybrid PQCrypto structure
    pub(crate) fn create_armor_file_format(
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
    pub(crate) fn parse_armor_file_format(
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
