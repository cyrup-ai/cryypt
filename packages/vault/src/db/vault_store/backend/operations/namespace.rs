//! Namespace-specific vault operations

use super::super::super::{LocalVaultProvider, VaultEntry};
use super::super::key_utils;
use crate::core::VaultValue;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::Utc;
use serde::Deserialize;

impl LocalVaultProvider {
    /// Store a value with a specific namespace
    pub async fn put_with_namespace(
        &self,
        namespace: String,
        key: String,
        value: VaultValue, // Accept VaultValue
    ) -> Result<(), crate::db::dao::Error> {
        // Use the proven put_impl method with namespace parameter
        self.put_impl(key, value, Some(&namespace))
            .await
            .map_err(|e| crate::db::dao::Error::Database(format!("Namespace put failed: {e}")))
    }

    /// Get all entries in a namespace
    pub async fn get_by_namespace(
        &self,
        namespace: String,
    ) -> Result<Vec<(String, VaultValue)>, crate::db::dao::Error> {
        // Check if vault is unlocked
        self.check_unlocked()
            .await
            .map_err(|e| crate::db::dao::Error::Database(format!("Vault locked: {e}")))?;

        let query = "SELECT id, value, metadata FROM vault_entries WHERE namespace = $namespace";
        let db = self.dao.db();

        let mut result = db
            .query(query)
            .bind(("namespace", namespace))
            .await
            .map_err(|e| crate::db::dao::Error::Database(e.to_string()))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| crate::db::dao::Error::Database(e.to_string()))?;

        #[derive(Deserialize)]
        struct IdValueMetadata {
            id: surrealdb::RecordId,
            value: String,
            metadata: Option<serde_json::Value>,
        }
        // Extract the first result set (index 0)
        let entries: Vec<IdValueMetadata> = result
            .take(0)
            .map_err(|e| crate::db::dao::Error::Database(e.to_string()))?;

        let mut results = Vec::with_capacity(entries.len());
        for entry in entries {
            // Extract key from record ID
            let key =
                key_utils::extract_key_from_record_id(&entry.id.to_string()).map_err(|e| {
                    crate::db::dao::Error::Database(format!(
                        "Failed to extract key from record ID: {}",
                        e
                    ))
                })?;

            // Decode base64 string back to encrypted bytes
            let encrypted_bytes = BASE64_STANDARD.decode(entry.value).map_err(|e| {
                crate::db::dao::Error::Serialization(format!("Base64 decode error: {e}"))
            })?;
            // Decrypt the bytes using AES decryption
            let decrypted_bytes = self
                .decrypt_data(&encrypted_bytes)
                .await
                .map_err(|e| crate::db::dao::Error::Database(format!("Decryption failed: {e}")))?;

            let mut vault_value = VaultValue::from_bytes(decrypted_bytes);

            // Restore metadata if present
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

    /// Get keys only from a namespace (optimized for trait interface)
    pub async fn get_keys_by_namespace(
        &self,
        namespace: String,
    ) -> Result<Vec<String>, crate::db::dao::Error> {
        // Check if vault is unlocked
        self.check_unlocked()
            .await
            .map_err(|e| crate::db::dao::Error::Database(format!("Vault locked: {e}")))?;

        // Optimized query - only select id field, no decryption needed
        let query = "SELECT id FROM vault_entries WHERE namespace = $namespace";
        let db = self.dao.db();

        let mut result = db
            .query(query)
            .bind(("namespace", namespace))
            .await
            .map_err(|e| crate::db::dao::Error::Database(e.to_string()))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| crate::db::dao::Error::Database(e.to_string()))?;

        #[derive(Deserialize)]
        struct IdOnly {
            id: surrealdb::RecordId,
        }
        // Extract the first result set (index 0)
        let entries: Vec<IdOnly> = result
            .take(0)
            .map_err(|e| crate::db::dao::Error::Database(e.to_string()))?;

        let mut results = Vec::with_capacity(entries.len());
        for entry in entries {
            // Extract key from record ID - no decryption needed
            let key =
                key_utils::extract_key_from_record_id(&entry.id.to_string()).map_err(|e| {
                    crate::db::dao::Error::Database(format!(
                        "Failed to extract key from record ID: {}",
                        e
                    ))
                })?;
            results.push(key);
        }

        Ok(results)
    }

    /// Find entries matching a pattern in a specific namespace
    pub async fn find_in_namespace_impl(
        &self,
        namespace: &str,
        pattern: &str,
    ) -> Result<Vec<(String, crate::core::VaultValue)>, crate::db::dao::Error> {
        // Check if vault is unlocked
        self.check_unlocked()
            .await
            .map_err(|e| crate::db::dao::Error::Database(format!("Vault locked: {e}")))?;

        let query = "SELECT id, value, metadata FROM vault_entries WHERE namespace = $namespace";
        let db = self.dao.db();

        let mut result = db
            .query(query)
            .bind(("namespace", namespace.to_string()))
            .await
            .map_err(|e| crate::db::dao::Error::Database(e.to_string()))?
            .check()
            .map_err(|e| crate::db::dao::Error::Database(e.to_string()))?;

        #[derive(serde::Deserialize)]
        struct NamespaceEntry {
            id: surrealdb::RecordId,
            value: String,
            metadata: Option<serde_json::Value>,
        }

        let entries: Vec<NamespaceEntry> = result
            .take(0)
            .map_err(|e| crate::db::dao::Error::Database(e.to_string()))?;

        let regex = regex::Regex::new(pattern)
            .map_err(|e| crate::db::dao::Error::Database(format!("Invalid regex pattern: {e}")))?;

        let mut results = Vec::new();
        for entry in entries {
            // Extract key from record ID
            let key =
                key_utils::extract_key_from_record_id(&entry.id.to_string()).map_err(|e| {
                    crate::db::dao::Error::Database(format!(
                        "Failed to extract key from record ID: {}",
                        e
                    ))
                })?;

            if regex.is_match(&key) {
                // Decode and decrypt the value
                let encrypted_bytes = BASE64_STANDARD.decode(entry.value).map_err(|e| {
                    crate::db::dao::Error::Serialization(format!("Base64 decode error: {e}"))
                })?;
                let decrypted_bytes = self.decrypt_data(&encrypted_bytes).await.map_err(|e| {
                    crate::db::dao::Error::Database(format!("Decryption failed: {e}"))
                })?;

                let mut vault_value = crate::core::VaultValue::from_bytes(decrypted_bytes);

                // Restore metadata if present
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
        }

        Ok(results)
    }

    /// List all available namespaces
    pub async fn list_namespaces_impl(&self) -> Result<Vec<String>, crate::error::VaultError> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        // Get all entries and extract unique namespace values in Rust
        // Note: 'namespace' is a reserved keyword in SurrealDB, so we use backticks to escape it
        let query = "SELECT `namespace` FROM vault_entries WHERE `namespace` IS NOT NULL";
        let db = self.dao.db();

        let mut result = db
            .query(query)
            .await
            .map_err(|e| crate::error::VaultError::Provider(format!("DB query failed: {e}")))?
            .check()
            .map_err(|e| crate::error::VaultError::Provider(format!("DB check failed: {e}")))?;

        #[derive(serde::Deserialize)]
        struct NamespaceResult {
            namespace: Option<String>,
        }

        let namespace_entries: Vec<NamespaceResult> = result.take(0).map_err(|e| {
            crate::error::VaultError::Provider(format!("Failed to get namespaces: {e}"))
        })?;

        // Extract unique namespaces (filter out None values) and sort
        let mut namespaces: Vec<String> = namespace_entries
            .into_iter()
            .filter_map(|entry| entry.namespace)
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        namespaces.sort();

        Ok(namespaces)
    }
}
