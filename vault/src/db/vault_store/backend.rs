//! Backend storage implementation for vault operations
//!
//! Contains the core database operations, schema initialization, and internal async helpers.

use super::{map_dao_error, SurrealDbVaultProvider, VaultEntry};
use crate::core::VaultValue;
use crate::db::dao::{Error as DaoError, GenericDao};
use crate::error::{VaultError, VaultResult};
use crate::operation::{
    Passphrase, VaultBoolRequest, VaultChangePassphraseRequest, VaultFindRequest, VaultGetRequest,
    VaultListRequest, VaultOperation, VaultPutAllRequest, VaultSaveRequest, VaultUnitRequest,
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use futures::StreamExt;
use serde::Deserialize;
use chrono::{DateTime, Utc};
use tokio::sync::{mpsc, oneshot};

impl SurrealDbVaultProvider {
    /// Initialize the vault schema (specific to this provider)
    pub async fn initialize_schema(&self) -> Result<(), DaoError> {
        // Define vault entries table
        let db = self.dao.db();
        db.query(
            "
            DEFINE TABLE IF NOT EXISTS vault_entries SCHEMAFULL;
            DEFINE FIELD key ON TABLE vault_entries TYPE string;
            DEFINE FIELD value ON TABLE vault_entries TYPE string;
            DEFINE FIELD created_at ON TABLE vault_entries TYPE datetime;
            DEFINE FIELD updated_at ON TABLE vault_entries TYPE datetime;
            DEFINE FIELD namespace ON TABLE vault_entries TYPE option<string>;
            DEFINE INDEX vault_key ON TABLE vault_entries COLUMNS key UNIQUE;
        ",
        )
        .await
        .map_err(|e| DaoError::Database(e.to_string()))?;

        Ok(())
    }

    // --- Internal Async Implementation Helpers ---

    pub(crate) async fn put_impl(&self, key: String, value: VaultValue) -> VaultResult<()> {
        // Encode VaultValue bytes as base64 string for storage
        let value_b64 = BASE64_STANDARD.encode(value.expose_secret());

        let entry = VaultEntry {
            id: Some(format!("entry:{}", key.replace('/', "_"))),
            key: key.clone(), // Clone key for entry
            value: value_b64,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
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

    pub(crate) async fn get_impl(&self, key: &str) -> VaultResult<Option<VaultValue>> {
        let query = "SELECT value FROM vault_entries WHERE key = $key LIMIT 1";
        let db = self.dao.db();
        let key = key.to_string(); // Clone to satisfy 'static lifetime

        let mut result = db
            .query(query)
            .bind(("key", key))
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {}", e)))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| VaultError::Provider(format!("DB check failed: {}", e)))?;

        // We only selected 'value', so deserialize into a struct holding just that.
        #[derive(Deserialize)]
        struct ValueOnly {
            value: String,
        }

        // Extract the first result set (index 0)
        let value_entry: Option<ValueOnly> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {}", e)))?;

        match value_entry {
            Some(entry) => {
                // Decode base64 string back to bytes
                let bytes = BASE64_STANDARD.decode(entry.value).map_err(|_| {
                    VaultError::Serialization(
                        serde_json::from_str::<()>("invalid base64").unwrap_err(),
                    )
                })?;
                Ok(Some(VaultValue::from_bytes(bytes)))
            }
            None => Ok(None), // Key not found is not an error for get, return None
        }
    }

    pub(crate) async fn delete_impl(&self, key: &str) -> VaultResult<()> {
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

    pub(crate) async fn find_impl(&self, pattern: &str) -> VaultResult<Vec<(String, VaultValue)>> {
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
            let bytes = BASE64_STANDARD.decode(entry.value).map_err(|_| {
                VaultError::Serialization(serde_json::from_str::<()>("invalid base64").unwrap_err())
            })?;
            results.push((entry.key, VaultValue::from_bytes(bytes)));
        }

        Ok(results)
    }

    pub(crate) async fn list_impl(&self, prefix: Option<&str>) -> VaultResult<Vec<String>> {
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

    pub(crate) async fn put_if_absent_impl(&self, key: String, value: VaultValue) -> VaultResult<bool> {
        // This is tricky to do atomically without transactions or specific SurrealDB features.
        // A common approach is to try to fetch first, then insert if not found.
        // This has a race condition but might be acceptable depending on requirements.
        // For a more robust solution, SurrealDB 1.x might need a custom function or
        // rely on unique index constraints during the insert.

        // Check existence first (non-atomic)
        let exists = self.get_impl(&key).await?;
        if exists.is_some() {
            return Ok(false); // Key already exists
        }

        // Attempt to put the value
        match self.put_impl(key, value).await {
            Ok(_) => Ok(true), // Inserted successfully
            Err(VaultError::Provider(e)) if e.contains("unique index") => {
                // If the error is due to the unique index (race condition hit), treat as non-insertion
                Ok(false)
            }
            Err(e) => Err(e), // Propagate other errors
        }
    }

    pub(crate) async fn put_all_impl(&self, entries: Vec<(String, VaultValue)>) -> VaultResult<()> {
        // Note: This is not atomic. If one put fails, others might have succeeded.
        // Consider using SurrealDB transactions if atomicity is required.
        for (key, value) in entries {
            // Need to clone key and value for each iteration if they are consumed by put_impl
            self.put_impl(key.clone(), value.clone()).await?;
        }
        Ok(())
    }

    // --- Namespace methods remain specific to this provider ---

    /// Creates a new namespace for vault entries
    pub async fn create_namespace(&self, namespace: String) -> Result<(), DaoError> {
        // Define namespace in SurrealDB
        let query = "DEFINE NAMESPACE $namespace";
        let db = self.dao.db();

        db.query(query)
            .bind(("namespace", namespace))
            .await
            .map_err(|e| DaoError::Database(e.to_string()))?;

        Ok(())
    }

    /// Store a value with a specific namespace
    pub async fn put_with_namespace(
        &self,
        namespace: String,
        key: String,
        value: VaultValue, // Accept VaultValue
    ) -> Result<(), DaoError> {
        // Encode VaultValue bytes as base64 string for storage
        let value_b64 = BASE64_STANDARD.encode(value.expose_secret());

        let entry = VaultEntry {
            id: Some(format!("entry:{}:{}", namespace, key.replace('/', "_"))),
            key,
            value: value_b64, // Store encoded string
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
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
            return Err(DaoError::Database("Failed to create vault entry".into()));
        }

        Ok(())
    }

    /// Get all entries in a namespace
    pub async fn get_by_namespace(
        &self,
        namespace: String,
    ) -> Result<Vec<(String, VaultValue)>, DaoError> {
        let query = "SELECT key, value FROM vault_entries WHERE namespace = $namespace";
        let db = self.dao.db();

        let mut result = db
            .query(query)
            .bind(("namespace", namespace))
            .await
            .map_err(|e| DaoError::Database(e.to_string()))?
            .check() // Check for SurrealDB errors in the response
            .map_err(|e| DaoError::Database(e.to_string()))?;

        #[derive(Deserialize)]
        struct KeyValue {
            key: String,
            value: String,
        }
        // Extract the first result set (index 0)
        let entries: Vec<KeyValue> = result
            .take(0)
            .map_err(|e| DaoError::Database(e.to_string()))?;

        let mut results = Vec::with_capacity(entries.len());
        for entry in entries {
            // Decode base64 string back to bytes
            let bytes = BASE64_STANDARD
                .decode(entry.value)
                .map_err(|e| DaoError::Serialization(format!("Base64 decode error: {}", e)))?;
            results.push((entry.key, VaultValue::from_bytes(bytes)));
        }

        Ok(results)
    }
}

// --- VaultOperation Implementation ---

impl VaultOperation for SurrealDbVaultProvider {
    fn name(&self) -> &str {
        "SurrealDB Vault Provider"
    }

    // SurrealDB doesn't have an explicit lock state managed by this provider
    fn is_locked(&self) -> bool {
        false
    }

    // Unlock is not supported as there's no passphrase concept here
    fn unlock(&self, _passphrase: &Passphrase) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Err(VaultError::UnsupportedOperation(
            "SurrealDB provider does not support unlock".to_string(),
        )));
        VaultUnitRequest::new(rx)
    }

    // Lock is not supported
    fn lock(&self) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Err(VaultError::UnsupportedOperation(
            "SurrealDB provider does not support lock".to_string(),
        )));
        VaultUnitRequest::new(rx)
    }

    fn put(&self, key: &str, value: VaultValue) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let key = key.to_string();
        // value is already owned, move it

        tokio::spawn(async move {
            let result = provider_clone.put_impl(key, value).await;
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    fn get(&self, key: &str) -> VaultGetRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let key = key.to_string();

        tokio::spawn(async move {
            let result = provider_clone.get_impl(&key).await;
            let _ = tx.send(result);
        });

        VaultGetRequest::new(rx)
    }

    fn delete(&self, key: &str) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let key = key.to_string();

        tokio::spawn(async move {
            let result = provider_clone.delete_impl(&key).await;
            // Don't treat NotFound as an error for delete
            let final_result = match result {
                Err(VaultError::ItemNotFound) => Ok(()),
                other => other,
            };
            let _ = tx.send(final_result);
        });

        VaultUnitRequest::new(rx)
    }

    fn list(&self, prefix: Option<&str>) -> VaultListRequest {
        let (tx, rx) = mpsc::channel(100); // Buffer size 100
        let provider_clone = self.clone();
        let prefix = prefix.map(|s| s.to_string()); // Clone prefix into an Option<String>

        tokio::spawn(async move {
            match provider_clone.list_impl(prefix.as_deref()).await {
                Ok(keys) => {
                    for key in keys {
                        if tx.send(Ok(key)).await.is_err() {
                            // Receiver dropped
                            break;
                        }
                    }
                    // Channel closes when tx drops
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                }
            }
        });

        VaultListRequest::new(rx)
    }

    // Change passphrase is not supported
    fn change_passphrase(
        &self,
        _old_passphrase: &Passphrase,
        _new_passphrase: &Passphrase,
    ) -> VaultChangePassphraseRequest {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Err(VaultError::UnsupportedOperation(
            "SurrealDB provider does not support change_passphrase".to_string(),
        )));
        VaultChangePassphraseRequest::new(rx)
    }

    // Save is not explicitly needed; operations are typically transactional per request
    fn save(&self) -> VaultSaveRequest {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Ok(())); // Assume success as operations are immediate
        VaultSaveRequest::new(rx)
    }

    fn put_if_absent(&self, key: &str, value: VaultValue) -> VaultBoolRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let key = key.to_string();
        // value is already owned

        tokio::spawn(async move {
            let result = provider_clone.put_if_absent_impl(key, value).await;
            let _ = tx.send(result);
        });

        VaultBoolRequest::new(rx)
    }

    fn put_all(&self, entries: Vec<(String, VaultValue)>) -> VaultPutAllRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        // entries is already owned

        tokio::spawn(async move {
            let result = provider_clone.put_all_impl(entries).await;
            let _ = tx.send(result);
        });

        VaultPutAllRequest::new(rx)
    }

    fn find(&self, pattern: &str) -> VaultFindRequest {
        let (tx, rx) = mpsc::channel(100); // Buffer size 100
        let provider_clone = self.clone();
        let pattern = pattern.to_string();

        tokio::spawn(async move {
            match provider_clone.find_impl(&pattern).await {
                Ok(results) => {
                    for item in results {
                        if tx.send(Ok(item)).await.is_err() {
                            // Receiver dropped
                            break;
                        }
                    }
                    // Channel closes when tx drops
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                }
            }
        });

        VaultFindRequest::new(rx)
    }
}