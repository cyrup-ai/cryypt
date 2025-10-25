//! Re-encryption operations for vault entries
//!
//! This module handles cryptographic operations for re-encrypting vault data
//! with new passphrases, including key rotation functionality and secure
//! memory handling for sensitive cryptographic operations.

use super::super::super::{LocalVaultProvider, VaultEntry};

use crate::error::{VaultError, VaultResult};

impl LocalVaultProvider {
    /// Update vault passphrase without re-encrypting data
    ///
    /// This operation updates the passphrase hash used for authentication:
    /// 1. Verifies the old passphrase
    /// 2. Stores hash of the new passphrase
    ///
    /// NOTE: Vault data remains encrypted with RSA-derived keys, which don't change
    /// when the passphrase changes. The passphrase is only used for authentication,
    /// not for deriving encryption keys (encryption keys are derived from RSA key material).
    ///
    /// Security considerations:
    /// - Validates old passphrase before allowing change
    /// - Uses Argon2id for secure passphrase hashing
    /// - No re-encryption needed as encryption keys are RSA-derived, not passphrase-derived
    pub async fn re_encrypt_with_new_passphrase(
        &self,
        old_passphrase: &str,
        new_passphrase: &str,
    ) -> VaultResult<()> {
        use crate::operation::Passphrase;

        // Verify old passphrase first
        let old_pass = Passphrase::new(old_passphrase.to_string().into());
        self.verify_passphrase(&old_pass).await?;

        // Store new passphrase hash
        let new_pass = Passphrase::new(new_passphrase.to_string().into());
        self.store_passphrase_hash(&new_pass).await?;

        log::info!("Passphrase updated successfully (encryption keys unchanged)");

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
