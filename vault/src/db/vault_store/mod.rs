//! Vault store trait and core types
//!
//! Contains the main store traits, types, and error handling for vault storage operations.

use crate::db::dao::{Error as DaoError, SurrealDbDao, TableType};
use crate::error::{VaultError, VaultResult};
use crate::config::VaultConfig;
use crate::operation::Passphrase;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
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

/// Local vault provider using SurrealDB for storage.
#[derive(Debug, Clone)]
pub struct LocalVaultProvider {
    pub(crate) dao: SurrealDbDao<VaultEntry>,
    pub(crate) config: VaultConfig,
    pub(crate) locked: Arc<Mutex<bool>>,
    pub(crate) passphrase: Arc<Mutex<Option<Passphrase>>>,
    pub(crate) session_token: Arc<Mutex<Option<String>>>,
    pub(crate) encryption_key: Arc<Mutex<Option<Vec<u8>>>>,
}

impl LocalVaultProvider {
    /// Create a new LocalVaultProvider with SurrealKV local storage
    pub async fn new(config: VaultConfig) -> VaultResult<Self> {
        // Create SurrealKV connection using the vault_path from config
        let db_url = format!("surrealkv://{}", config.vault_path.display());
        let db = surrealdb::engine::any::connect(&db_url)
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to connect to SurrealDB: {}", e)))?;
        
        // Use a default namespace and database
        db.use_ns("vault").use_db("vault").await
            .map_err(|e| VaultError::Provider(format!("Failed to set namespace/database: {}", e)))?;
        
        let db = Arc::new(db);
        
        Ok(Self {
            dao: SurrealDbDao::new(db, "vault_entries", TableType::Document),
            config,
            locked: Arc::new(Mutex::new(true)), // Start locked
            passphrase: Arc::new(Mutex::new(None)),
            session_token: Arc::new(Mutex::new(None)),
            encryption_key: Arc::new(Mutex::new(None)),
        })
    }
}