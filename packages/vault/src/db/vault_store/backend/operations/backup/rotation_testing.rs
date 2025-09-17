//! Key rotation testing and validation operations

use super::super::super::super::{KeyRotationTestStats, LocalVaultProvider, VaultEntry};
use crate::error::{VaultError, VaultResult};

impl LocalVaultProvider {
    /// Test key rotation by performing a dry run
    pub async fn test_key_rotation(
        &self,
        current_passphrase: &str,
        new_passphrase: &str,
    ) -> VaultResult<KeyRotationTestStats> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        log::info!("Starting key rotation test (dry run)");

        let db = self.dao.db();

        // Get first 5 entries as a sample
        let sample_entries: Vec<VaultEntry> = db
            .query("SELECT * FROM vault_entries LIMIT 5")
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to get sample entries: {e}")))?
            .take(0)
            .map_err(|e| VaultError::Provider(format!("Failed to parse sample entries: {e}")))?;

        log::debug!(
            "Testing key rotation with {} sample entries",
            sample_entries.len()
        );

        let mut stats = KeyRotationTestStats {
            sample_entries_tested: 0,
            successful_decryptions: 0,
            successful_re_encryptions: 0,
            failed_operations: 0,
        };

        for entry in sample_entries {
            stats.sample_entries_tested += 1;

            // Extract key from record ID for natural keys
            use crate::db::vault_store::backend::key_utils;
            let record_id = entry
                .id
                .as_ref()
                .ok_or_else(|| VaultError::InvalidInput("Entry missing record ID".to_string()))?;
            let key = key_utils::extract_key_from_record_id(&record_id.to_string())?;

            log::trace!("Testing rotation for sample entry: {}", key);

            // Test decryption with current passphrase
            let encrypted_bytes = match base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &entry.value,
            ) {
                Ok(bytes) => bytes,
                Err(_) => {
                    stats.failed_operations += 1;
                    continue;
                }
            };

            let decrypted_data = match self
                .decrypt_data_with_passphrase(&encrypted_bytes, current_passphrase)
                .await
            {
                Ok(data) => {
                    stats.successful_decryptions += 1;
                    data
                }
                Err(_) => {
                    stats.failed_operations += 1;
                    continue;
                }
            };

            // Test re-encryption with new passphrase
            match self
                .encrypt_data_with_passphrase(&decrypted_data, new_passphrase)
                .await
            {
                Ok(_) => {
                    stats.successful_re_encryptions += 1;
                }
                Err(_) => {
                    stats.failed_operations += 1;
                }
            }
        }

        log::info!(
            "Key rotation test completed: {} tested, {} decrypt OK, {} re-encrypt OK, {} failed",
            stats.sample_entries_tested,
            stats.successful_decryptions,
            stats.successful_re_encryptions,
            stats.failed_operations
        );

        Ok(stats)
    }
}
