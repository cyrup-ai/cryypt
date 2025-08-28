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

        // Basic wildcard matching for simplicity, adjust if complex regex needed
        let db_pattern = format!("%{}%", pattern.replace('%', "\\%").replace('_', "\\_"));
        let query = "SELECT key, value FROM vault_entries WHERE key LIKE $pattern";
        let db = self.dao.db();

        let mut result = db
            .query(query)
            .bind(("pattern", db_pattern))
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {}", e)))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?;

        #[derive(Deserialize)]
        struct KeyValue {
            key: String,
            value: String,
        }

        // Extract the first result set (index 0)
        let entries: Vec<KeyValue> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;

        let mut results = Vec::with_capacity(entries.len());
        for entry in entries {
            // Decode base64 string back to encrypted bytes
            let encrypted_bytes = BASE64_STANDARD.decode(entry.value).map_err(|_| {
                VaultError::Serialization(serde_json::from_str::<()>("invalid base64").unwrap_err())
            })?;
            // Decrypt the bytes using AES decryption
            let decrypted_bytes = self.decrypt_data(&encrypted_bytes).await?;
            results.push((entry.key, VaultValue::from_bytes(decrypted_bytes)));
        }

        Ok(results)
    }

    /// List all keys, optionally filtered by prefix
    pub(crate) async fn list_impl(&self, prefix: Option<&str>) -> VaultResult<Vec<String>> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        let query = if prefix.is_some() {
            // Use STARTSWITH for prefix filtering
            "SELECT key FROM vault_entries WHERE string::startsWith(key, $prefix)"
        } else {
            "SELECT key FROM vault_entries"
        };
        let db = self.dao.db();

        let mut query_builder = db.query(query);
        if let Some(p) = prefix {
            let p = p.to_string(); // Clone to satisfy 'static lifetime
            query_builder = query_builder.bind(("prefix", p));
        }

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

        let keys = keys_only.into_iter().map(|k| k.key).collect();
        Ok(keys)
    }
}
