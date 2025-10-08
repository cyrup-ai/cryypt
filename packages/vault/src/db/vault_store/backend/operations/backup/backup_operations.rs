//! Backup creation and restoration operations for vault entries

use super::super::super::super::{
    BackupRestoreOptions, BackupRestoreStats, LocalVaultProvider, VaultEntry,
};
use crate::error::{VaultError, VaultResult};
use serde::{Deserialize, Serialize};

impl LocalVaultProvider {
    /// Create encrypted backup of all vault entries
    pub async fn create_encrypted_backup(&self, backup_passphrase: &str) -> VaultResult<Vec<u8>> {
        use chrono::Utc;

        // Check if vault is unlocked
        self.check_unlocked().await?;

        log::info!("Creating encrypted vault backup");

        let db = self.dao.db();

        // Get all vault entries (including expired ones for backup purposes)
        let entries: Vec<VaultEntry> = db
            .select("vault_entries")
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to get entries for backup: {e}")))?;

        log::debug!("Backup: found {} entries to backup", entries.len());

        #[derive(Serialize, Deserialize)]
        struct BackupData {
            version: String,
            timestamp: chrono::DateTime<Utc>,
            entries: Vec<VaultEntry>,
            metadata: std::collections::HashMap<String, String>,
        }

        // Create backup metadata
        let mut backup_metadata = std::collections::HashMap::new();
        backup_metadata.insert("created_by".to_string(), "cryypt_vault".to_string());
        backup_metadata.insert("entry_count".to_string(), entries.len().to_string());
        backup_metadata.insert("backup_type".to_string(), "full".to_string());

        let backup_data = BackupData {
            version: "1.0".to_string(),
            timestamp: Utc::now(),
            entries,
            metadata: backup_metadata,
        };

        // Serialize backup data to JSON
        let backup_json = serde_json::to_vec(&backup_data).map_err(VaultError::Serialization)?;

        log::debug!(
            "Backup: serialized {} bytes of JSON data",
            backup_json.len()
        );

        // Encrypt backup with provided passphrase
        let encrypted_backup = self
            .encrypt_data_with_passphrase(&backup_json, backup_passphrase)
            .await?;

        log::info!(
            "Backup: created encrypted backup ({} bytes)",
            encrypted_backup.len()
        );

        Ok(encrypted_backup)
    }

    /// Restore vault from encrypted backup
    pub async fn restore_from_encrypted_backup(
        &self,
        encrypted_backup: &[u8],
        backup_passphrase: &str,
        restore_options: BackupRestoreOptions,
    ) -> VaultResult<BackupRestoreStats> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        log::info!("Restoring vault from encrypted backup");

        // Decrypt backup data
        let backup_json = self
            .decrypt_data_with_passphrase(encrypted_backup, backup_passphrase)
            .await?;

        log::debug!(
            "Backup: decrypted {} bytes of backup data",
            backup_json.len()
        );

        #[derive(Serialize, Deserialize)]
        struct BackupData {
            version: String,
            timestamp: chrono::DateTime<chrono::Utc>,
            entries: Vec<VaultEntry>,
            metadata: std::collections::HashMap<String, String>,
        }

        // Deserialize backup data
        let backup_data: BackupData =
            serde_json::from_slice(&backup_json).map_err(VaultError::Serialization)?;

        log::info!(
            "Backup: restoring backup version {} from {} with {} entries",
            backup_data.version,
            backup_data.timestamp,
            backup_data.entries.len()
        );

        let mut stats = BackupRestoreStats {
            entries_processed: 0,
            entries_restored: 0,
            entries_skipped: 0,
            entries_failed: 0,
        };

        let db = self.dao.db();

        for entry in backup_data.entries {
            stats.entries_processed += 1;

            // Extract key from record ID for natural keys
            use crate::db::vault_store::backend::key_utils;
            let record_id = entry
                .id
                .as_ref()
                .ok_or_else(|| VaultError::InvalidInput("Entry missing record ID".to_string()))?;
            let key = key_utils::extract_key_from_record_id(&record_id.to_string())?;

            // Check if entry already exists using record ID
            let existing_query = format!("SELECT * FROM {} LIMIT 1", record_id);
            let mut result = db.query(existing_query).await.map_err(|e| {
                VaultError::Provider(format!("Failed to check existing entry: {e}"))
            })?;

            let existing_entry: Option<serde_json::Value> = result.take(0).map_err(|e| {
                VaultError::Provider(format!("Failed to parse existing entry check: {e}"))
            })?;

            if existing_entry.is_some() && !restore_options.overwrite_existing {
                log::debug!("Skipping existing entry: {}", key);
                stats.entries_skipped += 1;
                continue;
            }

            // Insert or update entry using natural keys
            let create_query = format!(
                "
                CREATE {} SET 
                    value = $value,
                    metadata = $metadata,
                    created_at = $created_at,
                    updated_at = $updated_at,
                    expires_at = $expires_at,
                    namespace = $namespace
                ON DUPLICATE KEY UPDATE
                    value = $value,
                    metadata = $metadata,
                    updated_at = $updated_at
            ",
                record_id
            );

            match db
                .query(create_query)
                .bind(("value", entry.value))
                .bind(("metadata", entry.metadata))
                .bind(("created_at", entry.created_at))
                .bind(("updated_at", entry.updated_at))
                .bind(("expires_at", entry.expires_at))
                .bind(("namespace", entry.namespace))
                .await
            {
                Ok(_) => {
                    log::trace!("Restored entry: {}", key);
                    stats.entries_restored += 1;
                }
                Err(e) => {
                    log::error!("Failed to restore entry {}: {}", key, e);
                    stats.entries_failed += 1;
                }
            }
        }

        log::info!(
            "Backup restore completed: {} processed, {} restored, {} skipped, {} failed",
            stats.entries_processed,
            stats.entries_restored,
            stats.entries_skipped,
            stats.entries_failed
        );

        Ok(stats)
    }
}
