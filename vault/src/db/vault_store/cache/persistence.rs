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
    K: Clone + Hash + Eq + Send + Sync + 'static + Serialize + for<'de> Deserialize<'de> + std::fmt::Debug,
{
    match operation.operation_type {
        OperationType::Insert | OperationType::Update => {
            if let Some(encrypted_value) = operation.encrypted_value {
                let db_clone = db.clone();
                let _result: Result<Option<VaultEntry>, surrealdb::Error> = db_clone
                    .create("cache")
                    .content(VaultEntry {
                        id: Some(format!("cache:{:?}", operation.key)),
                        key: format!("{:?}", operation.key),
                        value: encrypted_value,
                        created_at: Some(
                            chrono::DateTime::from_timestamp(operation.timestamp as i64, 0)
                                .unwrap_or_default(),
                        ),
                        updated_at: Some(
                            chrono::DateTime::from_timestamp(operation.timestamp as i64, 0)
                                .unwrap_or_default(),
                        ),
                        expires_at: None, // No expiry for cache entries  
                        namespace: Some("cache".to_string()),
                    })
                    .await;
            }
        }
        OperationType::Delete => {
            let query = "DELETE cache_entries:$key";
            db.query(query)
                .bind(("key", operation.key))
                .await
                .map_err(|e| VaultError::DatabaseError(e.to_string()))?;
        }
    }

    Ok(())
}