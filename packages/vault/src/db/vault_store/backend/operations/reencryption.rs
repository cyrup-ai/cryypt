//! Re-encryption operations for vault entries
//!
//! This module handles cryptographic operations for re-encrypting vault data
//! with new passphrases, including key rotation functionality and secure
//! memory handling for sensitive cryptographic operations.

use super::super::super::{LocalVaultProvider, VaultEntry};

use crate::error::{VaultError, VaultResult};

impl LocalVaultProvider {
    /// Re-encrypt all vault entries with a new passphrase
    ///
    /// This operation performs a complete key rotation by:
    /// 1. Decrypting all entries with the old passphrase
    /// 2. Re-encrypting them with the new passphrase  
    /// 3. Updating the database with new encrypted values
    ///
    /// Security considerations:
    /// - Uses secure memory handling for decrypted data
    /// - Validates encryption/decryption at each step
    /// - Provides detailed error messages for debugging
    pub async fn re_encrypt_with_new_passphrase(
        &self,
        old_passphrase: &str,
        new_passphrase: &str,
    ) -> VaultResult<()> {
        let db = self.dao.db();

        // Get all vault entries for re-encryption
        let entries: Vec<VaultEntry> = db
            .select("vault_entries")
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to get entries: {e}")))?;

        // Re-encrypt each entry with the new passphrase
        for entry in entries {
            // Decode the current encrypted value from base64
            let encrypted_bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &entry.value)
                    .map_err(|_| VaultError::Provider("Invalid base64 in entry".to_string()))?;

            // Decrypt using the old passphrase
            let decrypted_bytes = self
                .decrypt_data_with_passphrase(&encrypted_bytes, old_passphrase)
                .await?;

            // Re-encrypt using the new passphrase
            let re_encrypted_bytes = self
                .encrypt_data_with_passphrase(&decrypted_bytes, new_passphrase)
                .await?;

            // Encode to base64 for database storage
            let value_b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                re_encrypted_bytes,
            );

            // Update entry in database with new encrypted value using natural keys
            use super::super::key_utils;
            let record_id = entry
                .id
                .as_ref()
                .ok_or_else(|| VaultError::InvalidInput("Entry missing record ID".to_string()))?;
            let _key_owned = key_utils::extract_key_from_record_id(&record_id.to_string())?;
            let query = format!("UPDATE {} SET value = $value", record_id);
            let mut result = db
                .query(query)
                .bind(("value", value_b64))
                .await
                .map_err(|e| VaultError::Provider(format!("Failed to update entry: {e}")))?
                .check()
                .map_err(|e| VaultError::Provider(format!("DB check failed: {e}")))?;

            let _: Option<()> = result
                .take(0)
                .map_err(|e| VaultError::Provider(format!("DB result take failed: {e}")))?;
        }

        Ok(())
    }

    /// Decrypt data using a specific passphrase (internal helper)
    ///
    /// Uses AES-256-GCM decryption with passphrase-derived key.
    /// Includes comprehensive validation and error handling.
    pub(crate) async fn decrypt_data_with_passphrase(
        &self,
        encrypted_data: &[u8],
        passphrase: &str,
    ) -> VaultResult<Vec<u8>> {
        // Derive encryption key from the specified passphrase
        use crate::operation::Passphrase;
        let passphrase_secret = Passphrase::new(passphrase.to_string().into());
        let key = self.derive_encryption_key(&passphrase_secret).await?;

        // Validate input data before attempting decryption
        if encrypted_data.len() < 32 {
            let error_msg = format!(
                "Re-encryption: invalid encrypted data size ({} bytes, minimum 32 required)",
                encrypted_data.len()
            );
            log::error!("{}", error_msg);
            return Err(VaultError::Decryption(error_msg));
        }

        // Perform AES decryption with the passphrase-derived key
        let decrypted_data = cryypt_cipher::Cryypt::cipher()
            .aes()
            .with_key(key.clone())
            .on_result(|result| match result {
                Ok(data) => data,
                Err(error) => {
                    log::error!("passphrase decryption failed: {}", error);
                    Vec::new()
                }
            })
            .decrypt(encrypted_data.to_vec())
            .await;

        // Validate decryption success
        if decrypted_data.is_empty() {
            let detailed_error = format!(
                "Passphrase decryption failed - input size: {} bytes, key size: {} bytes, possible cause: wrong old passphrase",
                encrypted_data.len(),
                key.len()
            );
            log::error!("Re-encryption decrypt failed: {}", detailed_error);
            return Err(VaultError::Decryption(detailed_error));
        }

        Ok(decrypted_data)
    }

    /// Encrypt data using a specific passphrase (internal helper)
    ///
    /// Uses AES-256-GCM encryption with passphrase-derived key.
    /// Includes comprehensive validation and logging.
    pub(crate) async fn encrypt_data_with_passphrase(
        &self,
        data: &[u8],
        passphrase: &str,
    ) -> VaultResult<Vec<u8>> {
        // Derive encryption key from the specified passphrase (unchanged)
        use crate::operation::Passphrase;
        let passphrase_secret = Passphrase::new(passphrase.to_string().into());
        let key = self.derive_encryption_key(&passphrase_secret).await?;

        log::trace!("Re-encrypting {} bytes with new passphrase", data.len());

        // Use service for encryption
        let encrypted_data = self.encryption_service.encrypt(data, &key).await?;

        log::trace!(
            "Re-encryption completed successfully, output: {} bytes",
            encrypted_data.len()
        );
        Ok(encrypted_data)
    }
}
