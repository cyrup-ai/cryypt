//! Search and listing operations for vault entries

use super::super::super::LocalVaultProvider;
use crate::core::VaultValue;
use crate::error::{VaultError, VaultResult};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use serde::Deserialize;

impl LocalVaultProvider {
    /// Find entries matching a pattern
    pub(crate) async fn find_impl(&self, pattern: &str) -> VaultResult<Vec<(String, VaultValue)>> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        // Special case for ".*" pattern to list all entries (used by CLI list command)
        // Filter out system records (salt, passphrase hash, etc.)
        let (query, use_pattern) = if pattern == ".*" {
            ("SELECT key, value FROM vault_entries WHERE !string::starts_with(key, '__vault')", false)
        } else {
            // Use SurrealDB string::contains function for substring matching, filter out system records
            ("SELECT key, value FROM vault_entries WHERE string::contains(key, $pattern) AND !string::starts_with(key, '__vault')", true)
        };
        let db_pattern = pattern.to_string();
        let db = self.dao.db();

        log::debug!("FIND: Executing query: {}", query);
        log::debug!("FIND: Searching for pattern: '{}'", db_pattern);

        let mut result = if use_pattern {
            db.query(query)
                .bind(("pattern", db_pattern))
                .await
                .map_err(|e| VaultError::Provider(format!("DB query failed: {}", e)))?
                .check() // Check for SurrealDB errors in the response
                .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?
        } else {
            db.query(query)
                .await
                .map_err(|e| VaultError::Provider(format!("DB query failed: {}", e)))?
                .check() // Check for SurrealDB errors in the response
                .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?
        };

        #[derive(Deserialize)]
        struct KeyValue {
            key: String,
            value: String,
            metadata: Option<serde_json::Value>,
        }

        // Extract the first result set (index 0)
        let entries: Vec<KeyValue> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;

        log::debug!("FIND: Query returned {} entries", entries.len());
        for entry in &entries {
            log::debug!("FIND: Found key: {}", entry.key);
        }

        let mut results = Vec::with_capacity(entries.len());
        for entry in entries {
            // Decode base64 string back to encrypted bytes
            let encrypted_bytes = BASE64_STANDARD.decode(entry.value)
                .map_err(|e| VaultError::Decryption(format!("Base64 decode failed: {}", e)))?;
            // Decrypt the bytes using AES decryption
            let decrypted_bytes = self.decrypt_data(&encrypted_bytes).await?;
            
            // Create VaultValue from decrypted bytes
            let mut vault_value = VaultValue::from_bytes(decrypted_bytes);
            
            // If metadata exists, convert it back to the format VaultValue expects
            if let Some(metadata_json) = entry.metadata {
                if let Some(metadata_obj) = metadata_json.as_object() {
                    let mut metadata_map = std::collections::HashMap::new();
                    for (key, value) in metadata_obj {
                        let value_str = match value {
                            serde_json::Value::String(s) => s.clone(),
                            serde_json::Value::Number(n) => n.to_string(),
                            serde_json::Value::Bool(b) => b.to_string(),
                            serde_json::Value::Null => "null".to_string(),
                            _ => serde_json::to_string(value).unwrap_or_default(),
                        };
                        metadata_map.insert(key.clone(), value_str);
                    }
                    if !metadata_map.is_empty() {
                        vault_value = vault_value.with_metadata(metadata_map);
                    }
                }
            }
            
            results.push((entry.key, vault_value));
        }

        Ok(results)
    }

    /// List all keys, optionally filtered by prefix
    pub(crate) async fn list_impl(&self, prefix: Option<&str>) -> VaultResult<Vec<String>> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        let query = if prefix.is_some() {
            // Use STARTSWITH for prefix filtering, exclude system records
            "SELECT key FROM vault_entries WHERE string::starts_with(key, $prefix) AND !string::starts_with(key, '__vault')"
        } else {
            // List all user entries, exclude system records
            "SELECT key FROM vault_entries WHERE !string::starts_with(key, '__vault')"
        };
        let db = self.dao.db();

        let mut query_builder = db.query(query);
        if let Some(p) = prefix {
            let p = p.to_string(); // Clone to satisfy 'static lifetime
            query_builder = query_builder.bind(("prefix", p));
        }

        log::debug!("LIST: Executing query: {}", query);
        let mut result = query_builder
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {}", e)))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?;

        #[derive(Deserialize)]
        struct KeyOnly {
            key: String,
        }

        // Extract the first result set (index 0)
        let keys_only: Vec<KeyOnly> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;

        log::debug!("LIST: Query returned {} keys", keys_only.len());
        for key in &keys_only {
            log::debug!("LIST: Found key: {}", key.key);
        }

        let keys = keys_only.into_iter().map(|k| k.key).collect();
        Ok(keys)
    }
}
