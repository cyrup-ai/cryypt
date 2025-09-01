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
                    // Store error for detailed reporting (can't modify closure captured vars)
                    Vec::new()
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
                    Vec::new()
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

        log::trace!("Decryption completed successfully, output: {} bytes", decrypted_data.len());
        Ok(decrypted_data)
    }

    /// Get or create salt for key derivation
    pub(crate) async fn get_or_create_salt(&self) -> VaultResult<Vec<u8>> {
        use rand::RngCore;
        use tokio::fs;

        // Try to read existing salt
        match fs::read(&self.config.salt_path).await {
            Ok(salt) => {
                if salt.len() >= 16 {
                    // Minimum 16 bytes for salt
                    Ok(salt)
                } else {
                    Err(VaultError::Crypto(
                        "Salt file corrupted: insufficient length".to_string(),
                    ))
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Generate new salt
                let mut salt = vec![0u8; 32]; // 32 bytes salt
                rand::rng().fill_bytes(&mut salt);

                // Ensure parent directory exists
                if let Some(parent) = self.config.salt_path.parent() {
                    fs::create_dir_all(parent)
                        .await
                        .map_err(VaultError::Io)?;
                }

                // Write salt to file
                fs::write(&self.config.salt_path, &salt)
                    .await
                    .map_err(VaultError::Io)?;

                // Set restrictive permissions on Unix
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = std::fs::Permissions::from_mode(0o600);
                    std::fs::set_permissions(&self.config.salt_path, perms)
                        .map_err(VaultError::Io)?;
                }

                log::info!(
                    "Generated new salt file at: {}",
                    self.config.salt_path.display()
                );
                Ok(salt)
            }
            Err(e) => Err(VaultError::Io(e)),
        }
    }
}
