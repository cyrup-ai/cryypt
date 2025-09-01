//! Namespace-specific vault operations

use super::super::super::{LocalVaultProvider, VaultEntry};
use crate::core::VaultValue;
use crate::db::dao::GenericDao;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::Utc;
use futures::StreamExt;
use serde::Deserialize;

impl LocalVaultProvider {
    /// Store a value with a specific namespace
    pub async fn put_with_namespace(
        &self,
        namespace: String,
        key: String,
        value: VaultValue, // Accept VaultValue
    ) -> Result<(), crate::db::dao::Error> {
        // Encrypt VaultValue bytes using AES encryption
        let encrypted_value = self
            .encrypt_data(value.expose_secret())
            .await
            .map_err(|e| crate::db::dao::Error::Database(format!("Encryption failed: {}", e)))?;
        let value_b64 = BASE64_STANDARD.encode(encrypted_value);

        let entry = VaultEntry {
            id: Some(format!("entry:{}:{}", namespace, key.replace('/', "_"))),
            key,
            value: value_b64, // Store encoded string
            metadata: value.metadata().cloned(), // Persist metadata from VaultValue
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            expires_at: None, // No expiry for namespace operations
            namespace: Some(namespace),
        };

        // Use the generic DAO trait
        let mut stream = GenericDao::create(&self.dao, entry);
        let mut items = Vec::new();

        while let Some(result) = stream.next().await {
            match result {
                Ok(item) => items.push(item),
                Err(e) => return Err(e),
            }
        }

        if items.is_empty() {
            return Err(crate::db::dao::Error::Database(
                "Failed to create vault entry".into(),
            ));
        }

        Ok(())
    }

    /// Get all entries in a namespace
    pub async fn get_by_namespace(
        &self,
        namespace: String,
    ) -> Result<Vec<(String, VaultValue)>, crate::db::dao::Error> {
        let query = "SELECT key, value FROM vault_entries WHERE namespace = $namespace";
        let db = self.dao.db();

        let mut result = db
            .query(query)
            .bind(("namespace", namespace))
            .await
            .map_err(|e| crate::db::dao::Error::Database(e.to_string()))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| crate::db::dao::Error::Database(e.to_string()))?;

        #[derive(Deserialize)]
        struct KeyValue {
            key: String,
            value: String,
        }
        // Extract the first result set (index 0)
        let entries: Vec<KeyValue> = result
            .take(0)
            .map_err(|e| crate::db::dao::Error::Database(e.to_string()))?;

        let mut results = Vec::with_capacity(entries.len());
        for entry in entries {
            // Decode base64 string back to encrypted bytes
            let encrypted_bytes = BASE64_STANDARD.decode(entry.value).map_err(|e| {
                crate::db::dao::Error::Serialization(format!("Base64 decode error: {}", e))
            })?;
            // Decrypt the bytes using AES decryption
            let decrypted_bytes = self.decrypt_data(&encrypted_bytes).await.map_err(|e| {
                crate::db::dao::Error::Database(format!("Decryption failed: {}", e))
            })?;
            results.push((entry.key, VaultValue::from_bytes(decrypted_bytes)));
        }

        Ok(results)
    }
}
