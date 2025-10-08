//! Search and listing operations for vault entries

use super::super::super::LocalVaultProvider;
use super::super::key_utils;
use crate::core::VaultValue;
use crate::error::{VaultError, VaultResult};
use base64::{
    Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD,
    engine::general_purpose::URL_SAFE_NO_PAD as BASE64_URL,
};
use serde::Deserialize;

impl LocalVaultProvider {
    /// Find entries matching a pattern
    pub(crate) async fn find_impl(&self, pattern: &str) -> VaultResult<Vec<(String, VaultValue)>> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        // Special case for ".*" pattern to list all entries (used by CLI list command)
        // Filter out system records (salt, passphrase hash, etc.)
        let (query, use_pattern) = if pattern == ".*" {
            ("SELECT id, value, metadata FROM vault_entries", false)
        } else {
            // Use SurrealDB string::contains function for substring matching, filter out system records
            ("SELECT id, value, metadata FROM vault_entries", true)
        };
        let db_pattern = pattern.to_string();
        let db = self.dao.db();

        log::debug!("FIND: Executing query: {}", query);
        log::debug!("FIND: Searching for pattern: '{}'", db_pattern);

        let mut result = if use_pattern {
            db.query(query)
                .bind(("pattern", db_pattern))
                .await
                .map_err(|e| VaultError::Provider(format!("DB query failed: {e}")))?
                .check() // Check for SurrealDB errors in the response
                .map_err(|e| VaultError::Provider(format!("DB check failed: {e}")))?
        } else {
            db.query(query)
                .await
                .map_err(|e| VaultError::Provider(format!("DB query failed: {e}")))?
                .check() // Check for SurrealDB errors in the response
                .map_err(|e| VaultError::Provider(format!("DB check failed: {e}")))?
        };

        #[derive(Deserialize)]
        struct KeyValue {
            id: surrealdb::RecordId,
            value: String,
            metadata: Option<serde_json::Value>,
        }

        // Extract the first result set (index 0)
        let entries: Vec<KeyValue> = result.take(0).map_err(|e| {
            log::error!("FIND: DB result take failed: {}", e);
            VaultError::Provider(format!("DB result take failed: {e}"))
        })?;

        log::debug!(
            "FIND: Successfully extracted {} entries from DB",
            entries.len()
        );

        log::debug!("FIND: Query returned {} entries", entries.len());
        for entry in &entries {
            let extracted_key =
                key_utils::extract_key_from_record_id(&entry.id.to_string()).unwrap_or_default();
            log::debug!("FIND: Found key: {}", extracted_key);
        }

        let mut results = Vec::with_capacity(entries.len());
        for entry in entries {
            // Extract key from record ID
            let key = key_utils::extract_key_from_record_id(&entry.id.to_string())
                .map_err(|e| VaultError::Provider(format!("Failed to extract key: {e}")))?;

            // Filter out system entries that are not user data
            // System entries can be either direct (__vault_*) or base64 encoded versions
            if key.starts_with("__vault_") {
                log::debug!("FIND: Skipping system entry (direct): {}", key);
                continue;
            }

            // Check if this is a base64 encoded system entry
            if let Ok(decoded_bytes) = BASE64_URL.decode(&key)
                && let Ok(decoded_str) = String::from_utf8(decoded_bytes)
                && decoded_str.starts_with("__vault_")
            {
                log::debug!(
                    "FIND: Skipping system entry (base64 encoded): {} -> {}",
                    key,
                    decoded_str
                );
                continue;
            }

            // Apply pattern filtering for pattern searches
            if use_pattern {
                if pattern == ".*" {
                    // Accept all entries for list-all operation
                } else if !key.contains(pattern) {
                    continue; // Skip entries that don't match pattern
                }
            }

            // Decode base64 string back to encrypted bytes
            let encrypted_bytes = BASE64_STANDARD
                .decode(entry.value)
                .map_err(|e| VaultError::Decryption(format!("Base64 decode failed: {e}")))?;
            // Decrypt the bytes using AES decryption
            let decrypted_bytes = self.decrypt_data(&encrypted_bytes).await?;

            // Create VaultValue from decrypted bytes
            let mut vault_value = VaultValue::from_bytes(decrypted_bytes);

            // If metadata exists, convert it back to the format VaultValue expects
            if let Some(metadata_json) = entry.metadata
                && let Some(metadata_obj) = metadata_json.as_object()
            {
                let mut metadata_map = std::collections::HashMap::new();
                for (key_meta, value) in metadata_obj {
                    let value_str = match value {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::Bool(b) => b.to_string(),
                        serde_json::Value::Null => "null".to_string(),
                        _ => serde_json::to_string(value).unwrap_or_default(),
                    };
                    metadata_map.insert(key_meta.clone(), value_str);
                }
                if !metadata_map.is_empty() {
                    vault_value = vault_value.with_metadata(metadata_map);
                }
            }

            results.push((key, vault_value));
        }

        Ok(results)
    }

    /// List all keys, optionally filtered by prefix
    pub(crate) async fn list_impl(&self, prefix: Option<&str>) -> VaultResult<Vec<String>> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        let query = "SELECT id FROM vault_entries";
        let db = self.dao.db();

        let query_builder = db.query(query);

        log::debug!("LIST: Executing query: {}", query);
        let mut result = query_builder
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {e}")))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| VaultError::Provider(format!("DB check failed: {e}")))?;

        #[derive(Deserialize)]
        struct KeyOnly {
            id: surrealdb::RecordId,
        }

        // Extract the first result set (index 0) - handle deserialization errors gracefully
        let keys_only: Vec<KeyOnly> = match result.take(0) {
            Ok(keys) => keys,
            Err(e) => {
                log::debug!("LIST: Failed to deserialize result as KeyOnly: {}", e);
                // If deserialization fails, return empty list
                Vec::new()
            }
        };

        let mut keys = Vec::new();
        for entry in keys_only {
            let key = key_utils::extract_key_from_record_id(&entry.id.to_string())
                .map_err(|e| VaultError::Provider(format!("Failed to extract key: {e}")))?;

            // Filter out system entries that are not user data (same logic as find_impl)
            // System entries can be either direct (__vault_*) or base64 encoded versions
            if key.starts_with("__vault_") {
                log::debug!("LIST: Skipping system entry (direct): {}", key);
                continue;
            }

            // Check if this is a base64 encoded system entry
            if let Ok(decoded_bytes) = BASE64_URL.decode(&key)
                && let Ok(decoded_str) = String::from_utf8(decoded_bytes)
                && decoded_str.starts_with("__vault_")
            {
                log::debug!(
                    "LIST: Skipping system entry (base64 encoded): {} -> {}",
                    key,
                    decoded_str
                );
                continue;
            }

            // Apply prefix filtering if specified
            if let Some(prefix) = prefix {
                if key.starts_with(prefix) {
                    keys.push(key);
                }
            } else {
                keys.push(key);
            }
        }

        log::debug!("LIST: Query returned {} keys", keys.len());
        for key in &keys {
            log::debug!("LIST: Found key: {}", key);
        }

        Ok(keys)
    }
}
