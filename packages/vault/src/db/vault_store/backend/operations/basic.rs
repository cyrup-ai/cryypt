//! Basic CRUD operations for vault entries

use super::super::super::{LocalVaultProvider, VaultEntry};
use crate::core::VaultValue;
use crate::error::{VaultError, VaultResult};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::Utc;


impl LocalVaultProvider {
    /// Store a key-value pair in the vault (public API)
    pub async fn put(&self, key: &str, value: &VaultValue) -> VaultResult<()> {
        log::debug!("PUT: Starting put operation for key='{}'", key);
        self.put_impl(key.to_string(), value.clone()).await
    }

    /// Store a key-value pair in the vault
    pub(crate) async fn put_impl(&self, key: String, value: VaultValue) -> VaultResult<()> {
        // Check if vault is unlocked
        self.check_unlocked().await?;
        
        // Validate key constraints
        if key.is_empty() {
            return Err(VaultError::InvalidKey("Key cannot be empty".to_string()));
        }
        if key.len() > 1024 {
            return Err(VaultError::InvalidKey("Key too long (max 1024 characters)".to_string()));
        }
        
        // Validate metadata size if present
        if let Some(metadata) = value.metadata() {
            let metadata_size = serde_json::to_string(metadata)
                .map_err(|e| VaultError::Serialization(e))?
                .len();
            if metadata_size > 64 * 1024 { // 64KB limit
                return Err(VaultError::InvalidInput("Metadata too large (max 64KB)".to_string()));
            }
        }

        // Encrypt VaultValue bytes using AES encryption
        let encrypted_value = self.encrypt_data(value.expose_secret()).await?;
        let value_b64 = BASE64_STANDARD.encode(encrypted_value);

        // Check if record exists to preserve created_at timestamp
        let db = self.dao.db();
        let now = Utc::now();
        
        // First check if record exists to preserve created_at
        let existing_query = "SELECT created_at FROM vault_entries WHERE key = $key LIMIT 1";
        let mut existing_result = db
            .query(existing_query)
            .bind(("key", key.clone()))
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to check existing record: {}", e)))?;
            
        #[derive(serde::Deserialize)]
        struct ExistingRecord {
            created_at: Option<chrono::DateTime<chrono::Utc>>,
        }
        
        let existing_record: Option<ExistingRecord> = existing_result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("Failed to deserialize existing record: {}", e)))?;
            
        // Use existing created_at or current time for new records
        let created_at = existing_record
            .and_then(|r| r.created_at)
            .unwrap_or(now);
        
        // Use UPSERT with WHERE clause to match existing codebase patterns
        let query = "UPSERT vault_entries SET key = $key, value = $value, metadata = $metadata, created_at = $created_at, updated_at = $updated_at, expires_at = $expires_at, namespace = $namespace WHERE key = $key";

        // Convert metadata from HashMap to serde_json::Value
        let metadata_json = value.metadata().cloned().map(|m| serde_json::to_value(m))
            .transpose()
            .map_err(|e| VaultError::Serialization(e))?;

        log::debug!("PUT: Executing query: {}", query);
        log::debug!("PUT: Binding key='{}', metadata={:?}", key, metadata_json);

        let mut result = db.query(query)
            .bind(("key", key.clone()))
            .bind(("value", value_b64))
            .bind(("metadata", metadata_json))
            .bind(("created_at", surrealdb::value::Datetime::from(created_at)))
            .bind(("updated_at", surrealdb::value::Datetime::from(now)))
            .bind(("expires_at", None::<surrealdb::value::Datetime>))
            .bind(("namespace", None::<String>))
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to upsert vault entry: {}", e)))?;

        // Consume the result to validate the operation succeeded
        let created: Vec<VaultEntry> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("Failed to check upsert result: {}", e)))?;

        log::debug!("PUT: UPSERT returned {} records", created.len());
        if !created.is_empty() {
            log::debug!("PUT: Upserted record with key='{}'", created[0].key);
        }

        if created.is_empty() {
            return Err(VaultError::Provider("Failed to upsert vault entry - no record returned".to_string()));
        }

        Ok(())
    }

    /// Retrieve a value by key from the vault (public API)
    pub async fn get(&self, key: &str) -> VaultResult<Option<VaultValue>> {
        self.get_impl(key).await
    }

    /// Retrieve a value by key from the vault
    pub(crate) async fn get_impl(&self, key: &str) -> VaultResult<Option<VaultValue>> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        let query = "SELECT * FROM vault_entries WHERE key = $key LIMIT 1";
        let db = self.dao.db();
        let key = key.to_string(); // Clone to satisfy 'static lifetime

        log::debug!("GET: Executing query: {}", query);
        log::debug!("GET: Searching for key='{}'", key);

        let mut result = db
            .query(query)
            .bind(("key", key))
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {}", e)))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?;

        // Extract the first result set (index 0)
        let value_entry: Option<VaultEntry> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;

        log::debug!("GET: Query returned entry: {:?}", value_entry.is_some());

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

        // SurrealDB 3.0 DELETE syntax: DELETE table WHERE condition
        let query = "DELETE vault_entries WHERE key = $key";
        let db = self.dao.db();
        let key = key.to_string(); // Clone to satisfy 'static lifetime

        log::info!("DELETE: Executing query: {}", query);
        log::info!("DELETE: Deleting key='{}'", key);
        
        // First, check if the key exists at all
        let check_query = "SELECT * FROM vault_entries WHERE key = $key";
        let mut check_result = db.query(check_query)
            .bind(("key", key.clone()))
            .await
            .map_err(|e| VaultError::Provider(format!("Check query failed: {}", e)))?;
        
        let existing: Vec<VaultEntry> = check_result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("Failed to check existing: {}", e)))?;
            
        log::info!("DELETE: Found {} existing records before delete", existing.len());

        // Execute the delete query following SurrealDB 3.0 patterns
        let mut result = db.query(query)
            .bind(("key", key.clone()))
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {}", e)))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?;

        // SurrealDB DELETE returns deleted records - extract them to check if operation succeeded
        let deleted_entries: Vec<VaultEntry> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("Failed to check delete result: {}", e)))?;

        log::debug!("DELETE: Query deleted {} records for key '{}'", deleted_entries.len(), key);

        // If no records were deleted, the key was not found
        if deleted_entries.is_empty() {
            log::debug!("DELETE: No records found to delete for key '{}'", key);
            return Err(VaultError::ItemNotFound);
        }

        log::debug!("DELETE: Successfully deleted key '{}'", key);
        Ok(())
    }
}