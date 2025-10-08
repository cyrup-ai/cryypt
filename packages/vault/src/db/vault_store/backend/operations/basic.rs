//! Basic CRUD operations for vault entries

use super::super::super::{LocalVaultProvider, VaultEntry};
use super::super::key_utils;
use crate::core::VaultValue;
use crate::error::{VaultError, VaultResult};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::Utc;

impl LocalVaultProvider {
    /// Store a key-value pair in the vault (public API)
    pub async fn put(&self, key: &str, value: &VaultValue) -> VaultResult<()> {
        log::info!("PUT_API: Starting put operation for key='{}'", key);
        log::debug!("PUT: Starting put operation for key='{}'", key);
        let result = self.put_impl(key.to_string(), value.clone(), None).await;
        log::info!(
            "PUT_API: put_impl result for key='{}': {:?}",
            key,
            result.is_ok()
        );
        result
    }

    /// Store a key-value pair in the vault
    pub(crate) async fn put_impl(
        &self,
        key: String,
        value: VaultValue,
        namespace: Option<&str>,
    ) -> VaultResult<()> {
        log::debug!("PUT_IMPL: Starting put_impl for key='{}'", key);

        // Check if vault is unlocked
        self.check_unlocked().await?;

        // Validate key constraints using key_utils
        key_utils::validate_key(&key)?;

        // Validate metadata size if present
        if let Some(metadata) = value.metadata() {
            let metadata_size = serde_json::to_string(metadata)
                .map_err(VaultError::Serialization)?
                .len();
            if metadata_size > 64 * 1024 {
                // 64KB limit
                return Err(VaultError::InvalidInput(
                    "Metadata too large (max 64KB)".to_string(),
                ));
            }
        }

        // Encrypt VaultValue bytes using AES encryption
        let encrypted_value = self.encrypt_data(value.expose_secret()).await?;
        let value_b64 = BASE64_STANDARD.encode(encrypted_value);

        // Create the natural key record ID
        let record_id = key_utils::create_record_id(&key);
        log::debug!(
            "PUT_IMPL: Created record ID: '{}' for key: '{}'",
            record_id,
            key
        );
        let db = self.dao.db();
        let now = Utc::now();

        // Check if record exists to preserve created_at timestamp
        let existing_query = format!("SELECT created_at FROM {record_id}");
        let mut existing_result = db
            .query(&existing_query)
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to check existing record: {e}")))?;

        #[derive(serde::Deserialize)]
        struct ExistingRecord {
            created_at: Option<chrono::DateTime<chrono::Utc>>,
        }

        let existing_record: Option<ExistingRecord> = existing_result.take(0).map_err(|e| {
            VaultError::Provider(format!("Failed to deserialize existing record: {e}"))
        })?;

        // Use existing created_at or current time for new records
        let created_at = existing_record.and_then(|r| r.created_at).unwrap_or(now);

        // Convert metadata from HashMap to serde_json::Value
        let metadata_json = value
            .metadata()
            .cloned()
            .map(serde_json::to_value)
            .transpose()
            .map_err(VaultError::Serialization)?;

        // Use proper UPSERT syntax for natural keys (following existing codebase pattern)
        // Also set the key field to match the record ID key portion
        let upsert_query = format!(
            "UPSERT {} SET key = $key, value = $value, metadata = $metadata, created_at = $created_at, updated_at = $updated_at, expires_at = $expires_at, namespace = $namespace",
            record_id
        );

        log::debug!("PUT: Executing UPSERT with record ID: {}", record_id);
        log::debug!("PUT: UPSERT query: {}", upsert_query);
        log::debug!(
            "PUT: Value length after base64 encoding: {} chars",
            value_b64.len()
        );

        let mut result = db
            .query(&upsert_query)
            .bind(("key", key.clone()))
            .bind(("value", value_b64))
            .bind(("metadata", metadata_json))
            .bind(("created_at", surrealdb::value::Datetime::from(created_at)))
            .bind(("updated_at", surrealdb::value::Datetime::from(now)))
            .bind(("expires_at", None::<surrealdb::value::Datetime>))
            .bind(("namespace", namespace.map(|s| s.to_string())))
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to upsert vault entry: {e}")))?;

        // Check the result to see what was actually stored
        let upsert_result: Vec<VaultEntry> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("Failed to parse upsert result: {e}")))?;

        log::debug!("PUT: UPSERT returned {} records", upsert_result.len());
        if let Some(stored_entry) = upsert_result.first() {
            log::debug!("PUT: Stored entry ID: {:?}", stored_entry.id);
            if let Some(ref record_id) = stored_entry.id
                && let Ok(extracted_key) =
                    key_utils::extract_key_from_record_id(&record_id.to_string())
            {
                log::debug!("PUT: Stored entry key: {}", extracted_key);
            }
            log::debug!(
                "PUT: Stored entry value length: {} chars",
                stored_entry.value.len()
            );
        }

        log::debug!(
            "PUT: UPSERT operation completed successfully for key: {}",
            key
        );

        Ok(())
    }

    /// Retrieve a value by key from the vault (public API)
    pub async fn get(&self, key: &str) -> VaultResult<Option<VaultValue>> {
        self.get_impl(key, None).await
    }

    /// Retrieve a value by key from the vault
    pub(crate) async fn get_impl(
        &self,
        key: &str,
        namespace: Option<&str>,
    ) -> VaultResult<Option<VaultValue>> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        // Create the natural key record ID
        let record_id = key_utils::create_record_id(key);
        log::debug!("GET: Created record ID: '{}' for key: '{}'", record_id, key);
        let db = self.dao.db();

        log::debug!(
            "GET: Attempting direct access with record ID: {}",
            record_id
        );

        // Use direct record ID access instead of WHERE query
        let query = format!("SELECT * FROM {record_id}");
        log::debug!("GET: Executing query: {}", query);
        let mut result = db
            .query(&query)
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {e}")))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| VaultError::Provider(format!("DB check failed: {e}")))?;

        // Extract the first result set (index 0) - try to deserialize as VaultEntry
        let value_entry: Option<VaultEntry> = match result.take(0) {
            Ok(entry) => entry,
            Err(e) => {
                log::debug!("GET: Failed to deserialize result as VaultEntry: {}", e);
                // If deserialization fails, assume no record found
                None
            }
        };

        log::debug!("GET: Query returned entry: {:?}", value_entry.is_some());

        match value_entry {
            Some(entry) => {
                // Check namespace filtering - since we're not using WHERE clause, we need to filter manually
                if let Some(expected_namespace) = namespace {
                    if entry.namespace.as_deref() != Some(expected_namespace) {
                        log::debug!(
                            "GET: Entry found but namespace mismatch: expected {:?}, got {:?}",
                            expected_namespace,
                            entry.namespace
                        );
                        return Ok(None);
                    }
                } else {
                    // If no namespace expected, entry should also have no namespace
                    if entry.namespace.is_some() {
                        log::debug!(
                            "GET: Entry found but has namespace when none expected: {:?}",
                            entry.namespace
                        );
                        return Ok(None);
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
        self.delete_impl(key, None).await
    }

    /// Delete a key from the vault
    pub(crate) async fn delete_impl(&self, key: &str, namespace: Option<&str>) -> VaultResult<()> {
        // Check if vault is unlocked (same as all other operations)
        self.check_unlocked().await?;

        // Create the natural key record ID (same pattern as GET/PUT)
        let record_id = key_utils::create_record_id(key);
        let db = self.dao.db();

        log::debug!("DELETE: Attempting deletion with record ID: {}", record_id);

        // First check if record exists (same pattern as GET)
        let check_query = format!("SELECT * FROM {record_id}");
        let mut check_result = db
            .query(&check_query)
            .await
            .map_err(|e| VaultError::Provider(format!("Check query failed: {e}")))?
            .check()
            .map_err(|e| VaultError::Provider(format!("Check failed: {e}")))?;

        let existing_record: Option<VaultEntry> = check_result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("Failed to check existing record: {e}")))?;

        match existing_record {
            Some(entry) => {
                // Check namespace filtering - same pattern as get_impl
                if let Some(expected_namespace) = namespace {
                    if entry.namespace.as_deref() != Some(expected_namespace) {
                        log::debug!(
                            "DELETE: Entry found but namespace mismatch: expected {:?}, got {:?}",
                            expected_namespace,
                            entry.namespace
                        );
                        return Err(VaultError::ItemNotFound);
                    }
                } else {
                    // If no namespace expected, entry should also have no namespace
                    if entry.namespace.is_some() {
                        log::debug!(
                            "DELETE: Entry found but has namespace when none expected: {:?}",
                            entry.namespace
                        );
                        return Err(VaultError::ItemNotFound);
                    }
                }
            }
            None => {
                log::debug!("DELETE: No record found for key '{}'", key);
                return Err(VaultError::ItemNotFound);
            }
        }

        log::debug!("DELETE: Record exists, proceeding with deletion");

        // Execute delete with RETURN BEFORE to get deleted record for verification
        let delete_query = format!("DELETE {} RETURN BEFORE", record_id);
        log::debug!("DELETE: Executing query: {}", delete_query);

        let mut delete_result = db
            .query(&delete_query)
            .await
            .map_err(|e| VaultError::Provider(format!("DELETE query failed: {e}")))?
            .check()
            .map_err(|e| VaultError::Provider(format!("DELETE check failed: {e}")))?;

        let deleted_records: Vec<VaultEntry> = delete_result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("Failed to process delete result: {e}")))?;

        log::debug!(
            "DELETE: Operation returned {} records",
            deleted_records.len()
        );

        if deleted_records.is_empty() {
            return Err(VaultError::ItemNotFound);
        }

        log::debug!("DELETE: Successfully deleted key '{}'", key);
        Ok(())
    }
}
