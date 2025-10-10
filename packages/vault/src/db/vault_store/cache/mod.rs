//! Lock-free caching layer for vault operations
//!
//! High-performance, lock-free LRU cache with atomic operations, SurrealDB persistence,
//! TTL-based expiration, metrics collection, and security features.

pub mod config;
pub mod entry;
pub mod invalidation;
pub mod metrics;
pub mod persistence;
pub mod security;
pub mod simd_hash;

// Decomposed functionality modules
pub mod background;
pub mod operations;
pub mod policies;

// Re-export main types
pub use config::{CacheConfig, PersistenceMode};
pub use entry::{CacheEntry, current_timestamp};
pub use invalidation::InvalidationStrategy;
pub use metrics::CacheMetrics;
pub use persistence::{OperationType, PersistenceOperation, persist_operation};
pub use security::SecureValue;
pub use simd_hash::fallback_hash::fast_hash;

// Main cache implementation
use crate::db::VaultEntry;
use crate::error::VaultError;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use cryypt_cipher::Cryypt;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;
use surrealdb::{Surreal, engine::any::Any};
use tokio::sync::mpsc;
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

/// Lock-free secure LRU cache with encrypted storage and atomic operations
pub struct LruCache<K>
where
    K: Clone + Hash + Eq + Send + Sync + 'static,
{
    /// Main cache storage using lock-free hash map - stores encrypted data only
    pub cache: Arc<DashMap<K, Arc<CacheEntry>>>,
    /// Cache configuration
    config: CacheConfig,
    /// Current cache size
    pub size: AtomicUsize,
    /// Cache metrics
    metrics: Arc<CacheMetrics>,
    /// Persistence channel sender
    persistence_tx: Option<mpsc::UnboundedSender<PersistenceOperation<K>>>,
    /// Cache running state
    running: Arc<AtomicBool>,
    /// Global access counter for LRU tracking (lock-free)
    global_access_counter: AtomicU64,
    /// Encryption key for real-time encrypt/decrypt operations
    encryption_key: Arc<tokio::sync::Mutex<Option<Vec<u8>>>>,
    /// Encryption service for value encryption
    encryption_service: crate::services::EncryptionService,
}

// Implementation modules are now separated into:
// - operations: Core CRUD, encryption, persistence coordination
// - policies: LRU eviction, hash optimization, invalidation strategies
// - background: Task management, cache warming, metrics reporting
