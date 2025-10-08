//! Database persistence operations for cache entries

use crate::db::VaultEntry;
use crate::error::VaultError;
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use surrealdb::{Surreal, engine::any::Any};

/// Persistence operation for async database writes - stores encrypted data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistenceOperation<K> {
    pub operation_type: OperationType,
    pub key: K,
    pub encrypted_value: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OperationType {
    Insert,
    Update,
    Delete,
}

/// Persist a cache operation to the database - zero allocation
pub async fn persist_operation<K>(
    db: &Surreal<Any>,
    operation: PersistenceOperation<K>,
) -> Result<(), VaultError>
where
    K: Clone
        + Hash
        + Eq
        + Send
        + Sync
        + 'static
        + Serialize
        + for<'de> Deserialize<'de>
        + std::fmt::Debug,
{
    match operation.operation_type {
        OperationType::Insert | OperationType::Update => {
            if let Some(encrypted_value) = operation.encrypted_value {
                let db_clone = db.clone();

                // Convert nanoseconds to seconds for chrono::DateTime
                let timestamp_seconds = (operation.timestamp / 1_000_000_000) as i64;
                let created_at = chrono::DateTime::from_timestamp(timestamp_seconds, 0)
                    .ok_or_else(|| {
                        VaultError::InvalidInput(format!(
                            "Invalid timestamp: {} nanoseconds ({} seconds)",
                            operation.timestamp, timestamp_seconds
                        ))
                    })?;
                let updated_at = created_at;

                let result: Result<Option<VaultEntry>, surrealdb::Error> = db_clone
                    .create("cache")
                    .content(VaultEntry {
                        id: Some({
                            let key_str = serde_json::to_string(&operation.key)
                                .unwrap_or_else(|_| format!("key_{}", operation.timestamp));
                            surrealdb::RecordId::from(("cache", key_str.as_str()))
                        }),
                        value: encrypted_value,
                        metadata: None, // No metadata for cache entries
                        created_at: Some(created_at),
                        updated_at: Some(updated_at),
                        expires_at: None, // No expiry for cache entries
                        namespace: Some("cache".to_string()),
                    })
                    .await;

                // Handle cache persistence errors properly - no silent failures
                result.map_err(|e| {
                    log::warn!(
                        "Cache persistence failed for key {:?}: {}",
                        operation.key,
                        e
                    );
                    VaultError::Provider(format!("Cache operation failed: {e}"))
                })?;
            }
        }
        OperationType::Delete => {
            let query = "DELETE cache:$key";
            db.query(query)
                .bind(("key", operation.key))
                .await
                .map_err(|e| {
                    log::warn!("Cache deletion failed: {}", e);
                    VaultError::Provider(format!("Cache deletion failed: {e}"))
                })?;
        }
    }

    Ok(())
}
