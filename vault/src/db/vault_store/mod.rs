//! Vault store trait and core types
//!
//! Contains the main store traits, types, and error handling for vault storage operations.

use crate::db::dao::{Error as DaoError, SurrealDbDao, TableType};
use crate::error::VaultError;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::any::Any;
use chrono::{DateTime, Utc};

// Declare submodules
pub mod backend;
pub mod cache;
pub mod transactions;

// Re-export key types from submodules would go here when needed

/// Vault entry stored in SurrealDB
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    /// Unique identifier
    pub id: Option<String>,
    /// Entry key
    pub key: String,
    /// Encrypted value
    pub value: String,
    /// Creation timestamp
    pub created_at: Option<DateTime<Utc>>,
    /// Last modification timestamp
    pub updated_at: Option<DateTime<Utc>>,
    /// Optional namespace for organizing entries
    pub namespace: Option<String>,
}

// Helper to map DAO errors to Vault errors
pub(crate) fn map_dao_error(e: DaoError) -> VaultError {
    match e {
        DaoError::NotFound => VaultError::ItemNotFound,
        DaoError::Database(msg) => VaultError::Provider(format!("SurrealDB error: {}", msg)),
        DaoError::Serialization(msg) => VaultError::Serialization(
            serde_json::from_str::<()>(&format!("serialization error: {}", msg)).unwrap_err(),
        ),
        DaoError::InvalidInput(msg) => VaultError::InvalidInput(msg),
        DaoError::Conflict(msg) => VaultError::Conflict(msg),
        DaoError::InvalidId => VaultError::InvalidInput("Invalid ID format".into()),
        DaoError::Other(msg) => VaultError::Provider(msg),
    }
}

/// Vault provider using SurrealDB for storage.
#[derive(Debug, Clone)]
pub struct SurrealDbVaultProvider {
    pub(crate) dao: SurrealDbDao<VaultEntry>,
}

impl SurrealDbVaultProvider {
    /// Create a new SurrealDbVaultProvider DAO
    pub fn new(db: Arc<Surreal<Any>>) -> Self {
        Self {
            dao: SurrealDbDao::new(db, "vault_entries", TableType::Document),
        }
    }
}