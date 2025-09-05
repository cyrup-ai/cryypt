//! Cryptographic operations for vault data protection
//!
//! Contains encryption, decryption, key derivation, and secure data handling.

use super::super::LocalVaultProvider;
use crate::error::{VaultError, VaultResult};
use crate::operation::Passphrase;
use cryypt_cipher::Cryypt;
use secrecy::ExposeSecret;

impl LocalVaultProvider {
    /// Derive encryption key from passphrase using Argon2
    pub(crate) async fn derive_encryption_key(
        &self,
        passphrase: &Passphrase,
    ) -> VaultResult<Vec<u8>> {
        // Read or generate salt from file
        log::trace!("Getting salt for key derivation...");
        let salt = self.get_or_create_salt().await?;
        log::trace!("Using {} byte salt for key derivation", salt.len());

        // Use Argon2 for secure key derivation with the vault's configured parameters
        use argon2::Argon2;

        log::trace!(
            "Configuring Argon2 with memory_cost={}, time_cost={}, parallelism={}",
            self.config.argon2_memory_cost,
            self.config.argon2_time_cost,
            self.config.argon2_parallelism
        );

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                self.config.argon2_memory_cost,
                self.config.argon2_time_cost,
                self.config.argon2_parallelism,
                Some(32), // 32 bytes for AES-256
            )
            .map_err(|e| VaultError::KeyDerivation(format!("Invalid Argon2 params: {}", e)))?,
        );

        // Use raw salt bytes directly with Argon2
        log::trace!("Using {} byte raw salt for Argon2 derivation", salt.len());

        // Derive key using Argon2
        let mut output_key = vec![0u8; 32];
        log::trace!("Running Argon2 key derivation...");
        argon2
            .hash_password_into(
                passphrase.expose_secret().as_bytes(),
                &salt,
                &mut output_key,
            )
            .map_err(|e| {
                VaultError::KeyDerivation(format!("Argon2 key derivation failed: {}", e))
            })?;

        log::trace!("Successfully derived {} byte key", output_key.len());

        // Store derived key in memory for session
        let mut key_guard = self.encryption_key.lock().await;
        *key_guard = Some(output_key.clone());

        Ok(output_key)
    }

    /// Derive JWT signing key from passphrase using Argon2 with different context
    pub(crate) async fn derive_jwt_key(
        &self,
        passphrase: &Passphrase,
    ) -> VaultResult<Vec<u8>> {
        // Read or generate salt from file (same salt as encryption key for simplicity)
        log::trace!("Getting salt for JWT key derivation...");
        let base_salt = self.get_or_create_salt().await?;
        
        // Create JWT-specific salt by appending context bytes to avoid key reuse
        let mut jwt_salt = base_salt;
        jwt_salt.extend_from_slice(b"JWT_SIGNING_CONTEXT");
        log::trace!("Using {} byte JWT-specific salt for key derivation", jwt_salt.len());

        // Use Argon2 for secure key derivation with the same parameters as encryption key
        use argon2::Argon2;

        log::trace!(
            "Configuring Argon2 for JWT key with memory_cost={}, time_cost={}, parallelism={}",
            self.config.argon2_memory_cost,
            self.config.argon2_time_cost,
            self.config.argon2_parallelism
        );

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(
                self.config.argon2_memory_cost,
                self.config.argon2_time_cost,
                self.config.argon2_parallelism,
                Some(32), // 32 bytes for HS256 compliance
            )
            .map_err(|e| VaultError::KeyDerivation(format!("Invalid Argon2 params for JWT key: {}", e)))?,
        );

        // Derive JWT signing key using Argon2
        let mut jwt_output_key = vec![0u8; 32];
        log::trace!("Running Argon2 JWT key derivation...");
        argon2
            .hash_password_into(
                passphrase.expose_secret().as_bytes(),
                &jwt_salt,
                &mut jwt_output_key,
            )
            .map_err(|e| {
                VaultError::KeyDerivation(format!("Argon2 JWT key derivation failed: {}", e))
            })?;

        log::trace!("Successfully derived {} byte JWT signing key", jwt_output_key.len());

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

        // Use AES encryption with cryypt_cipher - README.md compliant pattern
        let encrypted_data = Cryypt::cipher()
            .aes()
            .with_key(encryption_key.clone())
            .on_result(|result| match result {
                Ok(data) => {
                    log::trace!(
                        "cryypt_cipher encryption succeeded, output: {} bytes",
                        data.len()
                    );
                    data
                }
                Err(error) => {
                    let error_msg = format!("AES encryption failed: {}", error);
                    log::error!("{}", error_msg);
                    // Return error details in a special format for later detection
                    format!("ENCRYPTION_ERROR:{}", error_msg).into_bytes()
                }
            })
            .encrypt(data.to_vec())
            .await;

        if encrypted_data.is_empty() {
            let detailed_error = format!(
                "Encryption failed - input size: {} bytes, key size: {} bytes, vault locked: {}",
                data.len(),
                encryption_key.len(),
                false // We already checked above
            );
            log::error!("Crypto operation failed: {}", detailed_error);
            return Err(VaultError::Encryption(detailed_error));
        }

        // Check for error marker from on_result handler
        if let Ok(error_str) = String::from_utf8(encrypted_data.clone()) {
            if error_str.starts_with("ENCRYPTION_ERROR:") {
                let error_details = error_str.strip_prefix("ENCRYPTION_ERROR:").unwrap_or("Unknown encryption error");
                return Err(VaultError::Encryption(error_details.to_string()));
            }
        }

        log::trace!("Encryption completed successfully, output: {} bytes", encrypted_data.len());
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

        // Use AES decryption with cryypt_cipher - README.md compliant pattern
        let decrypted_data = Cryypt::cipher()
            .aes()
            .with_key(encryption_key.clone())
            .on_result(|result| match result {
                Ok(data) => {
                    log::trace!(
                        "cryypt_cipher decryption succeeded, output: {} bytes",
                        data.len()
                    );
                    data
                }
                Err(error) => {
                    let error_msg = format!("AES decryption failed: {}", error);
                    log::error!("{}", error_msg);
                    // Return error details in a special format for later detection
                    format!("DECRYPTION_ERROR:{}", error_msg).into_bytes()
                }
            })
            .decrypt(encrypted_data.to_vec())
            .await;

        if decrypted_data.is_empty() {
            let detailed_error = format!(
                "Decryption failed - input size: {} bytes, key size: {} bytes, possible causes: corrupted data, wrong key, or invalid format",
                encrypted_data.len(),
                encryption_key.len()
            );
            log::error!("Crypto operation failed: {}", detailed_error);
            return Err(VaultError::Decryption(detailed_error));
        }

        // Check for error marker from on_result handler
        if let Ok(error_str) = String::from_utf8(decrypted_data.clone()) {
            if error_str.starts_with("DECRYPTION_ERROR:") {
                let error_details = error_str.strip_prefix("DECRYPTION_ERROR:").unwrap_or("Unknown decryption error");
                return Err(VaultError::Decryption(error_details.to_string()));
            }
        }

        log::trace!("Decryption completed successfully, output: {} bytes", decrypted_data.len());
        Ok(decrypted_data)
    }

    /// Get or create salt for key derivation - stored encrypted in SurrealDB
    pub(crate) async fn get_or_create_salt(&self) -> VaultResult<Vec<u8>> {
        use rand::RngCore;

        // Try to retrieve existing salt from encrypted database storage
        let query = "SELECT * FROM vault_entries WHERE key = $key LIMIT 1";
        let db = self.dao.db();

        let mut result = db
            .query(query)
            .bind(("key", "__vault_salt__"))
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {}", e)))?
            .check()
            .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?;

        use super::super::VaultEntry;
        let salt_entry: Option<VaultEntry> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;

        match salt_entry {
            Some(entry) => {
                log::debug!("Found existing encrypted salt in database");

                // Decode salt from base64
                use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
                let salt = BASE64_STANDARD.decode(entry.value).map_err(|_| {
                    VaultError::Crypto("Invalid stored salt data".to_string())
                })?;

                if salt.len() == 32 {
                    Ok(salt)
                } else {
                    Err(VaultError::Crypto(
                        format!("Salt corrupted: expected exactly 32 bytes, got {}", salt.len())
                    ))
                }
            }
            None => {
                log::info!("No existing salt found - generating new salt");
                
                // Generate new salt
                let mut salt = vec![0u8; 32]; // 32 bytes salt
                rand::rng().fill_bytes(&mut salt);

                // Store encrypted salt in database
                use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
                let salt_b64 = BASE64_STANDARD.encode(&salt);

                // Use UPSERT to handle existing records
                use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL};
                let key_encoded = BASE64_URL.encode("__vault_salt__".as_bytes());
                let record_id = format!("vault_entries:{}", key_encoded);
                let upsert_query = format!("UPSERT {} SET key = $key, value = $value, created_at = $created_at, updated_at = $updated_at", record_id);
                
                let now = chrono::Utc::now();
                match db
                    .query(upsert_query)
                    .bind(("key", "__vault_salt__"))
                    .bind(("value", salt_b64))
                    .bind(("created_at", surrealdb::value::Datetime::from(now)))
                    .bind(("updated_at", surrealdb::value::Datetime::from(now)))
                    .await
                {
                    Ok(_) => {
                        log::info!("Generated and stored new encrypted salt in database");
                        Ok(salt)
                    }
                    Err(e) => Err(VaultError::Provider(format!("Failed to store salt: {}", e)))
                }
            }
        }
    }
}
