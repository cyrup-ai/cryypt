//! Vault store trait and core types
//!
//! Contains the main store traits, types, and error handling for vault storage operations.

use crate::auth::JwtHandler;
use crate::config::VaultConfig;
use crate::db::dao::{Error as DaoError, SurrealDbDao, TableType};
use crate::error::{VaultError, VaultResult};
use crate::operation::Passphrase;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex as SyncMutex};
use tokio::sync::Mutex;

/// Options for backup restore operations
#[derive(Debug, Clone, Default)]
pub struct BackupRestoreOptions {
    /// Whether to overwrite existing entries
    pub overwrite_existing: bool,
}

/// Statistics from backup restore operations
#[derive(Debug, Clone)]
pub struct BackupRestoreStats {
    pub entries_processed: u64,
    pub entries_restored: u64,
    pub entries_skipped: u64,
    pub entries_failed: u64,
}

/// Statistics from key rotation operations
#[derive(Debug, Clone)]
pub struct KeyRotationStats {
    pub entries_processed: u64,
    pub entries_rotated: u64,
    pub entries_failed: u64,
    pub old_salt_used: bool,
    pub new_salt_created: bool,
}

/// Statistics from key rotation testing
#[derive(Debug, Clone)]
pub struct KeyRotationTestStats {
    pub sample_entries_tested: u64,
    pub successful_decryptions: u64,
    pub successful_re_encryptions: u64,
    pub failed_operations: u64,
}

// Declare submodules
pub mod backend;
pub mod cache;
pub mod transactions;

// Re-export key types from submodules would go here when needed

/// Vault entry stored in SurrealDB
///
/// With natural keys, the key is embedded in the record ID rather than stored as a separate field.
/// Use backend::key_utils::extract_key_from_record_id() to get the key from the ID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    /// Unique identifier containing the key (format: "vault_entries:escaped_key")
    pub id: Option<surrealdb::RecordId>,
    /// Encrypted value
    pub value: String,
    /// Optional metadata associated with this entry
    pub metadata: Option<serde_json::Value>,
    /// Creation timestamp
    pub created_at: Option<DateTime<Utc>>,
    /// Last modification timestamp
    pub updated_at: Option<DateTime<Utc>>,
    /// Optional expiration timestamp for TTL support
    pub expires_at: Option<DateTime<Utc>>,
    /// Optional namespace for organizing entries
    pub namespace: Option<String>,
}

// Helper to map DAO errors to Vault errors
#[allow(dead_code)]
pub(crate) fn map_dao_error(e: DaoError) -> VaultError {
    match e {
        DaoError::NotFound => VaultError::ItemNotFound,
        DaoError::Database(msg) => VaultError::Provider(format!("SurrealDB error: {msg}")),
        DaoError::Serialization(msg) => {
            VaultError::Other(format!("DAO serialization error: {msg}"))
        }
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
    pub(crate) locked: Arc<SyncMutex<bool>>,
    pub(crate) passphrase: Arc<Mutex<Option<Passphrase>>>,
    pub(crate) session_token: Arc<Mutex<Option<String>>>,
    pub(crate) encryption_key: Arc<Mutex<Option<Vec<u8>>>>,
    pub(crate) jwt_key: Arc<Mutex<Option<Vec<u8>>>>,
    pub(crate) jwt_handler: Arc<JwtHandler>,
}

impl LocalVaultProvider {
    /// Create a new LocalVaultProvider with SurrealKV local storage
    pub async fn new(config: VaultConfig) -> VaultResult<Self> {
        // Create SurrealKV connection using the vault_path from config
        // Use the correct format for SurrealKV: just the file path
        let db_path = config.vault_path.to_string_lossy();

        // Ensure parent directory exists before connecting
        if let Some(parent) = config.vault_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                VaultError::Provider(format!("Failed to create vault directory: {e}"))
            })?;
        }

        // Use file database - match the working wallpapers example exactly
        let db = surrealdb::engine::any::connect(format!("surrealkv://{}", db_path))
            .await
            .map_err(|e| {
                VaultError::Provider(format!(
                    "Failed to connect to SurrealKV at {}: {}",
                    db_path, e
                ))
            })?;

        // Use a default namespace and database
        db.use_ns("vault")
            .use_db("vault")
            .await
            .map_err(|e| VaultError::Provider(format!("Failed to set namespace/database: {e}")))?;

        let db = Arc::new(db);

        // Create unique vault ID based on database path for JWT authentication
        let vault_id = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(db_path.as_bytes());
            let hash = hasher.finalize();
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&hash[..16]) // Use first 16 bytes as vault ID
        };

        // Initialize the vault provider
        let provider = Self {
            dao: SurrealDbDao::new(db, "vault_entries", TableType::Document),
            config,
            locked: Arc::new(SyncMutex::new(true)), // Start locked
            passphrase: Arc::new(Mutex::new(None)),
            session_token: Arc::new(Mutex::new(None)),
            encryption_key: Arc::new(Mutex::new(None)),
            jwt_key: Arc::new(Mutex::new(None)),
            jwt_handler: Arc::new(JwtHandler::new(vault_id)),
        };

        // Initialize the database schema
        provider.initialize_schema().await.map_err(|e| {
            VaultError::Provider(format!("Failed to initialize database schema: {e}"))
        })?;

        // Clean up expired JWT sessions
        provider.cleanup_expired_sessions().await.map_err(|e| {
            log::warn!("Failed to cleanup expired JWT sessions: {}", e);
            e
        })?;

        // Try to restore JWT session state (but keep vault locked until passphrase provided)
        if let Ok(Some((jwt_token, jwt_key))) = provider.restore_jwt_session().await {
            provider
                .populate_session_state(jwt_token, jwt_key)
                .await
                .map_err(|e| {
                    log::warn!("Failed to populate session state from restored JWT: {}", e);
                    e
                })?;
            log::info!(
                "Successfully restored JWT session state from secure storage (vault remains locked)"
            );
        } else {
            log::debug!("No valid JWT session found to restore");
        }

        Ok(provider)
    }

    /// Start TTL cleanup task if enabled in config
    pub fn start_ttl_cleanup_if_enabled(&self) {
        if self.config.ttl_cleanup_interval_seconds > 0 {
            let provider_clone = self.clone();
            let cleanup_interval = self.config.ttl_cleanup_interval_seconds;

            tokio::spawn(async move {
                provider_clone
                    .start_ttl_cleanup_task(cleanup_interval)
                    .await;
            });

            log::info!(
                "TTL cleanup task started with {} second intervals",
                cleanup_interval
            );
        } else {
            log::debug!("TTL cleanup disabled (interval = 0)");
        }
    }
}
