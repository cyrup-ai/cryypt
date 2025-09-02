//! Basic CRUD operations for vault entries

use super::super::super::{LocalVaultProvider, VaultEntry, map_dao_error};
use crate::core::VaultValue;
use crate::db::dao::GenericDao;
use crate::error::{VaultError, VaultResult};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::Utc;
use futures::StreamExt;
use serde::Deserialize;

impl LocalVaultProvider {
    /// Store a key-value pair in the vault (public API)
    pub async fn put(&self, key: &str, value: &VaultValue) -> VaultResult<()> {
        self.put_impl(key.to_string(), value.clone()).await
    }

    /// Store a key-value pair in the vault
    pub(crate) async fn put_impl(&self, key: String, value: VaultValue) -> VaultResult<()> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        // Encrypt VaultValue bytes using AES encryption
        let encrypted_value = self.encrypt_data(value.expose_secret()).await?;
        let value_b64 = BASE64_STANDARD.encode(encrypted_value);

        let entry = VaultEntry {
            id: Some(format!("entry:{}", key.replace('/', "_"))),
            key: key.clone(), // Clone key for entry
            value: value_b64,
            metadata: value.metadata().cloned(), // Persist metadata from VaultValue
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            expires_at: None, // No expiry for regular put operations
            namespace: None, // Namespace handled separately if needed
        };

        // Use the GenericDao trait
        let mut stream = GenericDao::create(&self.dao, entry);

        // Consume the stream to execute the create operation
        match stream.next().await {
            Some(Ok(_)) => Ok(()),
            Some(Err(e)) => Err(map_dao_error(e)),
            None => Err(VaultError::Provider(
                "Failed to create vault entry: No result from DAO".to_string(),
            )),
        }
    }

    /// Retrieve a value by key from the vault (public API)
    pub async fn get(&self, key: &str) -> VaultResult<Option<VaultValue>> {
        self.get_impl(key).await
    }

    /// Retrieve a value by key from the vault
    pub(crate) async fn get_impl(&self, key: &str) -> VaultResult<Option<VaultValue>> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        let query = "SELECT value, metadata FROM vault_entries WHERE key = $key LIMIT 1";
        let db = self.dao.db();
        let key = key.to_string(); // Clone to satisfy 'static lifetime

        let mut result = db
            .query(query)
            .bind(("key", key))
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {}", e)))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?;

        // Select both value and metadata
        #[derive(Deserialize)]
        struct ValueWithMetadata {
            value: String,
            metadata: Option<serde_json::Value>,
        }

        // Extract the first result set (index 0)
        let value_entry: Option<ValueWithMetadata> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;

        match value_entry {
            Some(entry) => {
                // Decode base64 string back to encrypted bytes
                let encrypted_bytes = BASE64_STANDARD.decode(entry.value)
                    .map_err(|e| VaultError::Decryption(format!("Base64 decode failed: {}", e)))?;
                // Decrypt the bytes using AES decryption
                let decrypted_bytes = self.decrypt_data(&encrypted_bytes).await?;
                
                // Create VaultValue from decrypted bytes
                let mut vault_value = VaultValue::from_bytes(decrypted_bytes);
                
                // If metadata exists, convert it back to the format VaultValue expects
                if let Some(metadata_json) = entry.metadata {
                    // VaultValue expects a HashMap<String, String> format for metadata
                    if let Some(metadata_obj) = metadata_json.as_object() {
                        let mut metadata_map = std::collections::HashMap::new();
                        for (key, value) in metadata_obj {
                            if let Some(value_str) = value.as_str() {
                                metadata_map.insert(key.clone(), value_str.to_string());
                            }
                        }
                        if !metadata_map.is_empty() {
                            vault_value = vault_value.with_metadata(metadata_map);
                        }
                    }
                }
                
                Ok(Some(vault_value))
            }
            None => Ok(None), // Key not found is not an error for get, return None
        }
    }

    /// Delete a key from the vault (public API)
    pub async fn delete(&self, key: &str) -> VaultResult<()> {
        self.delete_impl(key).await
    }

    /// Delete a key from the vault
    pub(crate) async fn delete_impl(&self, key: &str) -> VaultResult<()> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        let query = "DELETE FROM vault_entries WHERE key = $key";
        let db = self.dao.db();
        let key = key.to_string(); // Clone to satisfy 'static lifetime

        // Execute the delete query
        let mut result = db
            .query(query)
            .bind(("key", key))
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {}", e)))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?;

        // Check if any records were returned (indicates success, even if 0 deleted)
        let _: Option<()> = result
            .take(0) // We don't care about the actual deleted record data
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;

        Ok(())
        // Note: SurrealDB DELETE doesn't error if the key doesn't exist,
        // so we don't need special NotFound handling here.
    }
}