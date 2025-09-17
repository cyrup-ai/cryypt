//! Encryption key rotation operations for vault entries

use super::super::super::super::{KeyRotationStats, LocalVaultProvider, VaultEntry};
use crate::error::{VaultError, VaultResult};
use base64::Engine as _;

impl LocalVaultProvider {
    /// Rotate vault encryption key - re-encrypts all entries with a new derived key
    pub async fn rotate_encryption_key(
        &self,
        current_passphrase: &str,
        new_passphrase: &str,
    ) -> VaultResult<KeyRotationStats> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        log::info!("Starting encryption key rotation");

        let db = self.dao.db();

        // Get all vault entries
        let entries: Vec<VaultEntry> = db.select("vault_entries").await.map_err(|e| {
            VaultError::Provider(format!("Failed to get entries for key rotation: {e}"))
        })?;

        log::info!("Key rotation: processing {} entries", entries.len());

        let mut stats = KeyRotationStats {
            entries_processed: 0,
            entries_rotated: 0,
            entries_failed: 0,
            old_salt_used: false,
            new_salt_created: true,
        };

        // Step 1: Verify current passphrase by trying to decrypt a test entry
        if let Some(test_entry) = entries.first() {
            log::debug!("Verifying current passphrase with test decryption");

            let encrypted_bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &test_entry.value,
            )
            .map_err(|e| VaultError::KeyRotation(format!("Invalid base64 in test entry: {e}")))?;

            // Try to decrypt with current passphrase
            match self
                .decrypt_data_with_passphrase(&encrypted_bytes, current_passphrase)
                .await
            {
                Ok(_) => {
                    log::debug!("Current passphrase verified successfully");
                }
                Err(e) => {
                    return Err(VaultError::KeyRotation(format!(
                        "Current passphrase verification failed: {}",
                        e
                    )));
                }
            }
        }

        // Step 2: Generate new salt for the new passphrase
        log::info!("Generating new salt for key rotation");
        let new_salt = self.generate_new_rotation_salt().await?;

        // Step 3: Re-encrypt all entries
        for entry in entries {
            stats.entries_processed += 1;

            // Extract key from record ID for natural keys
            use crate::db::vault_store::backend::key_utils;
            let record_id = entry
                .id
                .as_ref()
                .ok_or_else(|| VaultError::InvalidInput("Entry missing record ID".to_string()))?;
            let key = key_utils::extract_key_from_record_id(&record_id.to_string())?;

            log::trace!("Rotating key for entry: {}", key);

            // Decrypt with old passphrase
            let encrypted_bytes = match base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &entry.value,
            ) {
                Ok(bytes) => bytes,
                Err(e) => {
                    log::error!("Failed to decode base64 for entry {}: {}", key, e);
                    stats.entries_failed += 1;
                    continue;
                }
            };

            let decrypted_data = match self
                .decrypt_data_with_passphrase(&encrypted_bytes, current_passphrase)
                .await
            {
                Ok(data) => data,
                Err(e) => {
                    log::error!(
                        "Failed to decrypt entry {} with current passphrase: {}",
                        key,
                        e
                    );
                    stats.entries_failed += 1;
                    continue;
                }
            };

            // Re-encrypt with new passphrase
            let re_encrypted_data = match self
                .encrypt_data_with_passphrase(&decrypted_data, new_passphrase)
                .await
            {
                Ok(data) => data,
                Err(e) => {
                    log::error!(
                        "Failed to re-encrypt entry {} with new passphrase: {}",
                        key,
                        e
                    );
                    stats.entries_failed += 1;
                    continue;
                }
            };

            let new_value_b64 = base64::engine::general_purpose::STANDARD.encode(re_encrypted_data);

            // Update entry in database using natural keys
            let update_query = format!(
                "UPDATE {} SET value = $value, updated_at = $updated_at",
                record_id
            );

            match db
                .query(update_query)
                .bind(("value", new_value_b64))
                .bind(("updated_at", chrono::Utc::now()))
                .await
            {
                Ok(_) => {
                    log::trace!("Successfully rotated key for entry: {}", key);
                    stats.entries_rotated += 1;
                }
                Err(e) => {
                    log::error!("Failed to update entry {} in database: {}", key, e);
                    stats.entries_failed += 1;
                }
            }
        }

        // Step 4: Replace old salt in encrypted database storage
        log::info!("Replacing old salt with new salt in encrypted database");
        match self.replace_salt_database(&new_salt).await {
            Ok(_) => {
                log::info!("Salt successfully updated in encrypted storage");
            }
            Err(e) => {
                log::error!("Failed to update salt in database: {}", e);
                // This is concerning but not fatal - the rotation already happened
            }
        }

        // Step 5: Update session with new encryption key
        log::info!("Updating session with new encryption key");
        if let Err(e) = self.update_session_key_after_rotation(new_passphrase).await {
            log::error!("Failed to update session key: {}", e);
        }

        log::info!(
            "Key rotation completed: {} processed, {} rotated, {} failed",
            stats.entries_processed,
            stats.entries_rotated,
            stats.entries_failed
        );

        Ok(stats)
    }

    /// Update session encryption key after rotation
    pub(super) async fn update_session_key_after_rotation(
        &self,
        new_passphrase: &str,
    ) -> VaultResult<()> {
        use crate::operation::Passphrase;

        // Create new passphrase secret
        let new_passphrase_secret = Passphrase::new(new_passphrase.to_string().into());

        // Derive new encryption key
        let new_key = self.derive_encryption_key(&new_passphrase_secret).await?;

        // Update session passphrase
        {
            let mut passphrase_guard = self.passphrase.lock().await;
            *passphrase_guard = Some(new_passphrase_secret);
        }

        // Update session encryption key
        {
            let mut key_guard = self.encryption_key.lock().await;
            *key_guard = Some(new_key);
        }

        log::debug!("Session updated with new encryption key");

        Ok(())
    }
}
