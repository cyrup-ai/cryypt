//! TTL (Time-To-Live) and expiry operations for vault entries

use super::super::super::{LocalVaultProvider, VaultEntry};
use crate::core::VaultValue;
use crate::error::{VaultError, VaultResult};
use chrono::{DateTime, Utc};

impl LocalVaultProvider {
    /// Store a key-value pair with expiry time
    pub async fn put_with_expiry(
        &self,
        key: &str,
        value: &VaultValue,
        expiry: std::time::SystemTime,
    ) -> VaultResult<()> {
        // Convert SystemTime to DateTime<Utc>
        let expires_at: DateTime<Utc> = expiry.into();

        // Encrypt the value data using the session key
        let encrypted_value = self.encrypt_data(value.expose_secret()).await?;
        let encoded_value =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, encrypted_value);

        // Create the vault entry with expiration using natural keys
        use super::super::key_utils;
        let record_id_str = key_utils::create_record_id(key);
        let record_id: surrealdb::RecordId = record_id_str
            .parse()
            .map_err(|e| VaultError::InvalidInput(format!("Failed to create record ID: {e}")))?;

        let entry = VaultEntry {
            id: Some(record_id),
            value: encoded_value,
            metadata: value.metadata().cloned(), // Persist metadata from VaultValue
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            expires_at: Some(expires_at),
            namespace: None,
        };

        // Use SurrealDB CREATE with natural keys (record ID contains the key)
        let db = self.dao.db();
        let record_id = entry.id.as_ref().ok_or_else(|| {
            VaultError::InvalidInput("Missing record ID in vault entry".to_string())
        })?;
        let query = format!(
            "CREATE {} SET 
                value = $value,
                metadata = $metadata,
                created_at = $created_at,
                updated_at = $updated_at,
                expires_at = $expires_at,
                namespace = $namespace
            ON DUPLICATE KEY UPDATE
                value = $value,
                metadata = $metadata,
                updated_at = $updated_at,
                expires_at = $expires_at",
            record_id
        );

        let mut result = db
            .query(query)
            .bind(("value", entry.value.clone()))
            .bind(("metadata", entry.metadata.clone()))
            .bind(("created_at", entry.created_at))
            .bind(("updated_at", entry.updated_at))
            .bind(("expires_at", entry.expires_at))
            .bind(("namespace", entry.namespace))
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to upsert with TTL: {e}")))?;

        // Verify the operation succeeded
        let _: Option<VaultEntry> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {e}")))?;

        Ok(())
    }

    /// Get value with expiry check - returns None if expired
    pub async fn get_with_expiry_check(&self, key: &str) -> VaultResult<Option<VaultValue>> {
        let db = self.dao.db();
        let now = Utc::now();

        // Query with expiry check - SurrealDB 2.3.7 time-based filtering
        let query = "
            SELECT * FROM vault_entries 
            WHERE key = $key 
            AND (expires_at IS NONE OR expires_at > $now)
            LIMIT 1
        ";

        let mut result = db
            .query(query)
            .bind(("key", key.to_string()))
            .bind(("now", now))
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to query with expiry check: {e}")))?;

        let entries: Vec<VaultEntry> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {e}")))?;

        match entries.into_iter().next() {
            Some(entry) => {
                // Decrypt the value
                let decoded_value = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    &entry.value,
                )
                .map_err(|e| VaultError::Decryption(format!("Base64 decode failed: {e}")))?;

                let decrypted_value = self.decrypt_data(&decoded_value).await?;

                // Convert to VaultValue with metadata restoration
                let mut vault_value = VaultValue::from_bytes(decrypted_value);

                // Restore metadata if present
                if let Some(metadata_json) = entry.metadata
                    && let Some(metadata_obj) = metadata_json.as_object()
                {
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

                Ok(Some(vault_value))
            }
            None => Ok(None), // Either doesn't exist or expired
        }
    }

    /// Update expiry time for a key
    pub async fn update_expiry(&self, key: &str, expiry: std::time::SystemTime) -> VaultResult<()> {
        let db = self.dao.db();
        let expiry_dt: DateTime<Utc> = expiry.into();

        let query = "UPDATE vault_entries SET expires_at = $expires_at WHERE key = $key";
        let key_owned = key.to_string();
        let mut result = db
            .query(query)
            .bind(("key", key_owned))
            .bind(("expires_at", expiry_dt))
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {e}")))?
            .check()
            .map_err(|e| VaultError::Provider(format!("DB check failed: {e}")))?;

        let _: Option<()> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {e}")))?;

        Ok(())
    }

    /// Remove expiry from a key
    pub async fn remove_expiry(&self, key: &str) -> VaultResult<()> {
        let db = self.dao.db();
        let query = "UPDATE vault_entries SET expires_at = NULL WHERE key = $key";
        let key_owned = key.to_string();

        let mut result = db
            .query(query)
            .bind(("key", key_owned))
            .await
            .map_err(|e| VaultError::Provider(format!("DB query failed: {e}")))?
            .check()
            .map_err(|e| VaultError::Provider(format!("DB check failed: {e}")))?;

        let _: Option<()> = result
            .take(0)
            .map_err(|e| VaultError::Provider(format!("DB result take failed: {e}")))?;

        Ok(())
    }
}
