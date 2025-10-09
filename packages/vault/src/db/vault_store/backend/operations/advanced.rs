//! Advanced vault operations with transaction-based atomicity
//!
//! This module provides higher-level vault operations built on top of basic CRUD
//! operations. All operations in this module use SurrealDB transactions to ensure
//! atomicity and data consistency.

use super::super::super::LocalVaultProvider;
use super::super::key_utils;
use crate::core::VaultValue;
use crate::error::{VaultError, VaultResult};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use chrono::Utc;
use std::collections::HashSet;

impl LocalVaultProvider {
    /// Store a key-value pair only if the key doesn't already exist (atomic operation)
    ///
    /// This operation uses a SurrealDB transaction to ensure atomicity. The check for
    /// existence and the insert operation are performed atomically, preventing race
    /// conditions even under concurrent access.
    ///
    /// # Arguments
    /// * `key` - The key to store
    /// * `value` - The value to store (will be encrypted)
    /// * `namespace` - Optional namespace for the key
    ///
    /// # Returns
    /// * `Ok(true)` - Key was successfully inserted
    /// * `Ok(false)` - Key already exists (not inserted)
    /// * `Err(...)` - Operation failed (validation error, encryption error, database error)
    pub(crate) async fn put_if_absent_impl(
        &self,
        key: String,
        value: VaultValue,
        namespace: Option<&str>,
    ) -> VaultResult<bool> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        // Validate key constraints
        key_utils::validate_key(&key)?;

        // Validate metadata size if present
        if let Some(metadata) = value.metadata() {
            let metadata_size = serde_json::to_string(metadata)
                .map_err(VaultError::Serialization)?
                .len();
            if metadata_size > 64 * 1024 {
                return Err(VaultError::InvalidInput(
                    "Metadata too large (max 64KB)".to_string(),
                ));
            }
        }

        // Encrypt value before transaction
        let encrypted_value = self.encrypt_data(value.expose_secret()).await?;
        let value_b64 = BASE64_STANDARD.encode(encrypted_value);

        // Create record ID
        let record_id = key_utils::create_record_id(&key);
        let db = self.dao.db();
        let now = Utc::now();

        // Convert metadata to JSON
        let metadata_json = value
            .metadata()
            .cloned()
            .map(serde_json::to_value)
            .transpose()
            .map_err(VaultError::Serialization)?;

        // Build transaction SQL
        let transaction_sql = format!(
            "
            BEGIN TRANSACTION;
            LET $existing = (SELECT * FROM {} LIMIT 1);
            IF $existing != [] THEN
                THROW 'Key already exists';
            END;
            UPSERT {} SET 
                key = $key, 
                value = $value, 
                metadata = $metadata, 
                created_at = $created_at, 
                updated_at = $updated_at, 
                expires_at = $expires_at, 
                namespace = $namespace;
            COMMIT TRANSACTION;
            ",
            record_id, record_id
        );

        log::debug!(
            "PUT_IF_ABSENT: Executing atomic transaction for key: {}",
            key
        );

        let result = db
            .query(&transaction_sql)
            .bind(("key", key.clone()))
            .bind(("value", value_b64))
            .bind(("metadata", metadata_json))
            .bind(("created_at", surrealdb::value::Datetime::from(now)))
            .bind(("updated_at", surrealdb::value::Datetime::from(now)))
            .bind(("expires_at", None::<surrealdb::value::Datetime>))
            .bind(("namespace", namespace.map(|s| s.to_string())))
            .await;

        match result {
            Ok(_) => {
                log::debug!("PUT_IF_ABSENT: Successfully inserted key: {}", key);
                Ok(true)
            }
            Err(e) if e.to_string().contains("Key already exists") => {
                log::debug!("PUT_IF_ABSENT: Key already exists: {}", key);
                Ok(false)
            }
            Err(e) => {
                log::error!("PUT_IF_ABSENT: Transaction failed for key {}: {}", key, e);
                Err(VaultError::Provider(format!("Transaction failed: {}", e)))
            }
        }
    }

    /// Store multiple key-value pairs atomically (all-or-nothing operation)
    ///
    /// This operation uses a SurrealDB transaction to ensure all entries are inserted
    /// atomically. If any entry fails to insert, the entire batch is rolled back and
    /// no changes are made to the database.
    ///
    /// # Arguments
    /// * `entries` - Vector of (key, value) pairs to store
    /// * `namespace` - Optional namespace applied to all entries
    ///
    /// # Returns
    /// * `Ok(())` - All entries were successfully inserted
    /// * `Err(...)` - Operation failed, no entries were inserted (transaction rolled back)
    pub(crate) async fn put_all_impl(
        &self,
        entries: Vec<(String, VaultValue)>,
        namespace: Option<&str>,
    ) -> VaultResult<()> {
        // Check if vault is unlocked
        self.check_unlocked().await?;

        // Handle empty list
        if entries.is_empty() {
            return Ok(());
        }

        // Detect duplicate keys in batch
        let mut seen_keys = HashSet::new();
        for (key, _) in &entries {
            if !seen_keys.insert(key.clone()) {
                return Err(VaultError::InvalidInput(format!(
                    "Duplicate key in batch: {}",
                    key
                )));
            }
        }

        // Validate all keys and metadata before transaction
        for (key, value) in &entries {
            key_utils::validate_key(key)?;

            if let Some(metadata) = value.metadata() {
                let metadata_size = serde_json::to_string(metadata)
                    .map_err(VaultError::Serialization)?
                    .len();
                if metadata_size > 64 * 1024 {
                    return Err(VaultError::InvalidInput(format!(
                        "Metadata too large for key '{}' (max 64KB)",
                        key
                    )));
                }
            }
        }

        let db = self.dao.db();
        let now = Utc::now();

        // Encrypt all values before transaction
        let mut encrypted_entries = Vec::new();
        for (key, value) in &entries {
            let encrypted_value = self.encrypt_data(value.expose_secret()).await?;
            let value_b64 = BASE64_STANDARD.encode(encrypted_value);
            let record_id = key_utils::create_record_id(key);
            let metadata_json = value
                .metadata()
                .cloned()
                .map(serde_json::to_value)
                .transpose()
                .map_err(VaultError::Serialization)?;

            encrypted_entries.push((key.clone(), record_id, value_b64, metadata_json));
        }

        // Build transaction with all UPSERT statements
        let mut transaction_sql = String::from("BEGIN TRANSACTION;\n");

        for (i, (key, record_id, _, _)) in encrypted_entries.iter().enumerate() {
            transaction_sql.push_str(&format!(
                "UPSERT {} SET key = $key{}, value = $value{}, metadata = $metadata{}, created_at = $created_at{}, updated_at = $updated_at{}, expires_at = $expires_at{}, namespace = $namespace{};\n",
                record_id, i, i, i, i, i, i, i
            ));
        }

        transaction_sql.push_str("COMMIT TRANSACTION;");

        log::debug!(
            "PUT_ALL: Executing atomic transaction for {} entries",
            entries.len()
        );

        // Execute transaction with all bindings
        let mut query = db.query(&transaction_sql);

        for (i, (key, _, value_b64, metadata_json)) in encrypted_entries.iter().enumerate() {
            query = query
                .bind((format!("key{}", i), key.clone()))
                .bind((format!("value{}", i), value_b64.clone()))
                .bind((format!("metadata{}", i), metadata_json.clone()))
                .bind((
                    format!("created_at{}", i),
                    surrealdb::value::Datetime::from(now),
                ))
                .bind((
                    format!("updated_at{}", i),
                    surrealdb::value::Datetime::from(now),
                ))
                .bind((
                    format!("expires_at{}", i),
                    None::<surrealdb::value::Datetime>,
                ))
                .bind((format!("namespace{}", i), namespace.map(|s| s.to_string())));
        }

        query
            .await
            .map_err(|e| {
                log::error!("PUT_ALL: Transaction failed: {}", e);
                VaultError::Provider(format!("Batch insert transaction failed: {}", e))
            })?;

        log::debug!("PUT_ALL: Successfully inserted {} entries", entries.len());
        Ok(())
    }
}
