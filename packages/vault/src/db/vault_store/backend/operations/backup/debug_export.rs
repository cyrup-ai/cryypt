//! Debug export functionality for vault entries

use super::super::super::super::LocalVaultProvider;
use super::super::super::super::VaultEntry;
use crate::error::{VaultError, VaultResult};

use serde::{Deserialize, Serialize};

impl LocalVaultProvider {
    /// Export vault entries to unencrypted JSON for debugging (vault must be unlocked)
    pub async fn export_to_json_debug(&self) -> VaultResult<String> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        log::warn!("Creating UNENCRYPTED debug export - use only for debugging!");

        let db = self.dao.db();

        // Get all vault entries
        let entries: Vec<VaultEntry> = db.select("vault_entries").await.map_err(|e| {
            VaultError::Provider(format!("Failed to get entries for debug export: {e}"))
        })?;

        #[derive(Serialize, Deserialize)]
        struct DebugExport {
            warning: String,
            version: String,
            timestamp: chrono::DateTime<chrono::Utc>,
            entries: Vec<DebugEntry>,
        }

        #[derive(Serialize, Deserialize)]
        struct DebugEntry {
            key: String,
            value_preview: String, // Only first 50 chars
            metadata: Option<serde_json::Value>,
            created_at: Option<chrono::DateTime<chrono::Utc>>,
            expires_at: Option<chrono::DateTime<chrono::Utc>>,
            namespace: Option<String>,
        }

        let mut debug_entries = Vec::new();

        for entry in entries {
            // Decrypt the value to show preview
            let preview = match base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                &entry.value,
            ) {
                Ok(encrypted_bytes) => match self.decrypt_data(&encrypted_bytes).await {
                    Ok(decrypted) => {
                        let value_str = String::from_utf8_lossy(&decrypted);
                        if value_str.len() > 50 {
                            format!("{}...", &value_str[..50])
                        } else {
                            value_str.to_string()
                        }
                    }
                    Err(_) => "<decryption_failed>".to_string(),
                },
                Err(_) => "<invalid_base64>".to_string(),
            };

            // Extract key from record ID for natural keys
            use crate::db::vault_store::backend::key_utils;
            let record_id = entry
                .id
                .as_ref()
                .ok_or_else(|| VaultError::InvalidInput("Entry missing record ID".to_string()))?;
            let key = key_utils::extract_key_from_record_id(&record_id.to_string())?;

            debug_entries.push(DebugEntry {
                key,
                value_preview: preview,
                metadata: entry.metadata,
                created_at: entry.created_at,
                expires_at: entry.expires_at,
                namespace: entry.namespace,
            });
        }

        let debug_export = DebugExport {
            warning: "THIS IS AN UNENCRYPTED DEBUG EXPORT - DO NOT SHARE".to_string(),
            version: "1.0".to_string(),
            timestamp: chrono::Utc::now(),
            entries: debug_entries,
        };

        serde_json::to_string_pretty(&debug_export).map_err(VaultError::Serialization)
    }
}
