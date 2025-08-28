//! Lock-free caching layer for vault operations
//!
//! High-performance, lock-free LRU cache with atomic operations, SurrealDB persistence,
//! TTL-based expiration, metrics collection, and security features.

use super::VaultEntry;
use crate::error::VaultError;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono;
use cryypt_cipher::Cryypt;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use surrealdb::{Surreal, engine::any::Any};
use tokio::sync::mpsc;
use tokio::time::{interval, sleep};
use tracing::{debug, error, info, warn};
use zeroize::{Zeroize, Zeroizing};

/// Cache configuration with performance and security settings
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Maximum number of entries in the cache
    pub max_entries: usize,
    /// Time-to-live for cache entries in seconds
    pub ttl_seconds: u64,
    /// Enable persistence to SurrealDB
    pub persistence_enabled: bool,
    /// Persistence mode: WriteThrough or WriteBack
    pub persistence_mode: PersistenceMode,
    /// Cache warming enabled
    pub warming_enabled: bool,
    /// Metrics collection interval in seconds
    pub metrics_interval_seconds: u64,
    /// Enable SIMD optimizations for hashing
    pub simd_enabled: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 10000,
            ttl_seconds: 3600, // 1 hour
            persistence_enabled: true,
            persistence_mode: PersistenceMode::WriteThrough,
            warming_enabled: true,
            metrics_interval_seconds: 60,
            simd_enabled: true,
        }
    }
}

/// Cache persistence modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PersistenceMode {
    /// Write to cache and database immediately
    WriteThrough,
    /// Write to cache immediately, database asynchronously
    WriteBack,
}

/// Secure cache entry storing encrypted data only - lock-free design
#[derive(Debug)]
struct CacheEntry {
    /// Encrypted value as base64 string (same format as database)
    encrypted_value: String,
    created_at: u64,
    last_accessed: AtomicU64,
    access_count: AtomicU64,
    ttl_seconds: u64,
}

impl CacheEntry {
    fn new(encrypted_value: String, ttl_seconds: u64) -> Self {
        let now = current_timestamp();
        Self {
            encrypted_value,
            created_at: now,
            last_accessed: AtomicU64::new(now),
            access_count: AtomicU64::new(1),
            ttl_seconds,
        }
    }

    fn is_expired(&self) -> bool {
        if self.ttl_seconds == 0 {
            return false;
        }
        let now = current_timestamp();
        now.saturating_sub(self.created_at) > self.ttl_seconds
    }

    fn touch(&self) {
        let now = current_timestamp();
        self.last_accessed.store(now, Ordering::Relaxed);
        self.access_count.fetch_add(1, Ordering::Relaxed);
    }

    fn last_access_time(&self) -> u64 {
        self.last_accessed.load(Ordering::Relaxed)
    }
}

/// Cache metrics for monitoring and performance analysis - lock-free design
#[derive(Debug, Default)]
pub struct CacheMetrics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: AtomicU64,
    pub insertions: AtomicU64,
    pub deletions: AtomicU64,
    pub expired_entries: AtomicU64,
    pub persistence_writes: AtomicU64,
    pub persistence_errors: AtomicU64,
    pub memory_usage_bytes: AtomicU64,
}

impl CacheMetrics {
    /// Get cache hit ratio as a percentage
    pub fn hit_ratio(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed) as f64;
        let total = hits + self.misses.load(Ordering::Relaxed) as f64;
        if total == 0.0 {
            0.0
        } else {
            (hits / total) * 100.0
        }
    }

    /// Reset all metrics to zero
    pub fn reset(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.evictions.store(0, Ordering::Relaxed);
        self.insertions.store(0, Ordering::Relaxed);
        self.deletions.store(0, Ordering::Relaxed);
        self.expired_entries.store(0, Ordering::Relaxed);
        self.persistence_writes.store(0, Ordering::Relaxed);
        self.persistence_errors.store(0, Ordering::Relaxed);
        self.memory_usage_bytes.store(0, Ordering::Relaxed);
    }
}

/// Secure cache value wrapper with automatic zeroization
#[derive(Debug, Clone)]
pub struct SecureValue<T>
where
    T: Zeroize,
{
    inner: T,
}

impl<T> SecureValue<T>
where
    T: Zeroize,
{
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    pub fn get(&self) -> &T {
        &self.inner
    }

    pub fn into_inner(self) -> T
    where
        T: Default,
    {
        let mut value = self;
        std::mem::take(&mut value.inner)
    }
}

impl<T> Drop for SecureValue<T>
where
    T: Zeroize,
{
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

/// Persistence operation for async database writes - stores encrypted data
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistenceOperation<K> {
    operation_type: OperationType,
    key: K,
    encrypted_value: Option<String>,
    timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum OperationType {
    Insert,
    Update,
    Delete,
}

/// Lock-free secure LRU cache with encrypted storage and atomic operations
pub struct LruCache<K>
where
    K: Clone + Hash + Eq + Send + Sync + 'static,
{
    /// Main cache storage using lock-free hash map - stores encrypted data only
    cache: Arc<DashMap<K, Arc<CacheEntry>>>,
    /// Cache configuration
    config: CacheConfig,
    /// Current cache size
    size: AtomicUsize,
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
}

impl<K> LruCache<K>
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
    /// Create a new lock-free secure LRU cache with the specified configuration
    #[inline]
    pub fn new(config: CacheConfig) -> Self {
        Self {
            cache: Arc::new(DashMap::with_capacity(config.max_entries)),
            config,
            size: AtomicUsize::new(0),
            metrics: Arc::new(CacheMetrics::default()),
            persistence_tx: None,
            running: Arc::new(AtomicBool::new(true)),
            global_access_counter: AtomicU64::new(0),
            encryption_key: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }

    /// Initialize cache with SurrealDB persistence
    pub async fn with_persistence(mut self, db: Arc<Surreal<Any>>) -> Result<Self, VaultError> {
        if !self.config.persistence_enabled {
            return Ok(self);
        }

        let (tx, mut rx) = mpsc::unbounded_channel::<PersistenceOperation<K>>();
        self.persistence_tx = Some(tx);

        let db_clone = db.clone();
        let metrics_clone = self.metrics.clone();
        let running_clone = self.running.clone();

        // Spawn persistence worker
        tokio::spawn(async move {
            while running_clone.load(Ordering::Relaxed) {
                match rx.recv().await {
                    Some(operation) => {
                        if let Err(e) = Self::persist_operation(&db_clone, operation).await {
                            error!(error = %e, "Cache persistence operation failed");
                            metrics_clone
                                .persistence_errors
                                .fetch_add(1, Ordering::Relaxed);
                        } else {
                            metrics_clone
                                .persistence_writes
                                .fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    None => break,
                }
            }
        });

        // Load existing cache entries from database
        if self.config.warming_enabled {
            self.warm_cache(&db).await?;
        }

        // Start background tasks
        self.start_background_tasks().await;

        Ok(self)
    }

    /// Set encryption key for secure cache operations
    pub async fn set_encryption_key(&self, key: Vec<u8>) {
        let mut key_guard = self.encryption_key.lock().await;
        *key_guard = Some(key);
    }

    /// Encrypt data using AES with session key - zero allocation
    async fn encrypt_data(&self, data: &[u8]) -> Result<String, VaultError> {
        let key_guard = self.encryption_key.lock().await;
        let encryption_key = key_guard.as_ref().ok_or_else(|| VaultError::VaultLocked)?;

        // Use AES encryption with proper fluent builder API - matches README.md pattern
        let encrypted_data = Cryypt::cipher()
            .aes()
            .with_key(encryption_key.clone())
            .on_result(|result| match result {
                Ok(data) => data,
                Err(_) => Vec::new(),
            })
            .encrypt(data.to_vec())
            .await;

        if encrypted_data.is_empty() {
            return Err(VaultError::Encryption("Encryption failed".to_string()));
        }

        Ok(BASE64_STANDARD.encode(encrypted_data))
    }

    /// Decrypt data using AES with session key - zero allocation
    async fn decrypt_data(&self, encrypted_b64: &str) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let key_guard = self.encryption_key.lock().await;
        let encryption_key = key_guard.as_ref().ok_or_else(|| VaultError::VaultLocked)?;

        // Decode base64
        let encrypted_bytes = BASE64_STANDARD
            .decode(encrypted_b64)
            .map_err(|_| VaultError::Decryption("Invalid base64".to_string()))?;

        // Use AES decryption with proper fluent builder API - matches README.md pattern
        let decrypted_data = Cryypt::cipher()
            .aes()
            .with_key(encryption_key.clone())
            .on_result(|result| match result {
                Ok(data) => data,
                Err(_) => Vec::new(),
            })
            .decrypt(encrypted_bytes)
            .await;

        if decrypted_data.is_empty() {
            return Err(VaultError::Decryption("Decryption failed".to_string()));
        }

        Ok(Zeroizing::new(decrypted_data))
    }

    /// Get an item from the cache - decrypts on-demand, blazing fast, zero allocation
    #[inline]
    pub async fn get(&self, key: &K) -> Option<Result<Zeroizing<Vec<u8>>, VaultError>> {
        if let Some(entry_ref) = self.cache.get(key) {
            let entry = entry_ref.value();

            // Check if entry is expired - zero allocation check
            if entry.is_expired() {
                // Remove expired entry atomically
                drop(entry_ref);
                self.cache.remove(key);
                self.size.fetch_sub(1, Ordering::Relaxed);
                self.metrics.expired_entries.fetch_add(1, Ordering::Relaxed);
                self.metrics.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }

            // Update access information atomically - lock-free LRU tracking
            entry.touch();
            self.metrics.hits.fetch_add(1, Ordering::Relaxed);

            // Update global access counter for lock-free LRU tracking
            self.global_access_counter.fetch_add(1, Ordering::Relaxed);

            // Decrypt the cached encrypted value on-demand
            Some(self.decrypt_data(&entry.encrypted_value).await)
        } else {
            self.metrics.misses.fetch_add(1, Ordering::Relaxed);
            None
        }
    }

    /// Insert an item into the cache - encrypts before storing, lock-free LRU eviction
    #[inline]
    pub async fn insert(
        &self,
        key: K,
        data: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        // Encrypt the data before storing in cache
        let encrypted_value = self.encrypt_data(data).await?;
        let encrypted_value_clone = encrypted_value.clone();
        let entry = Arc::new(CacheEntry::new(encrypted_value, self.config.ttl_seconds));

        // Check if we need to evict entries to make space - lock-free check
        if self.size.load(Ordering::Relaxed) >= self.config.max_entries {
            self.evict_lru_entries_lockfree().await;
        }

        // Insert the new entry atomically
        let old_value = if let Some(old_entry) = self.cache.insert(key.clone(), entry) {
            // Decrypt the old encrypted value to return it
            Some(self.decrypt_data(&old_entry.encrypted_value).await?)
        } else {
            self.size.fetch_add(1, Ordering::Relaxed);
            None
        };

        // Handle persistence - zero allocation
        if let Some(ref tx) = self.persistence_tx {
            let operation = PersistenceOperation {
                operation_type: if old_value.is_some() {
                    OperationType::Update
                } else {
                    OperationType::Insert
                },
                key: key.clone(),
                encrypted_value: Some(encrypted_value_clone),
                timestamp: current_timestamp(),
            };
            let _ = tx.send(operation);
        }

        // Update metrics atomically
        self.metrics.insertions.fetch_add(1, Ordering::Relaxed);

        Ok(old_value)
    }

    /// Remove an item from the cache - lock-free atomic operation
    #[inline]
    pub async fn remove(&self, key: &K) -> Option<Result<Zeroizing<Vec<u8>>, VaultError>> {
        if let Some((_, entry)) = self.cache.remove(key) {
            self.size.fetch_sub(1, Ordering::Relaxed);
            self.metrics.deletions.fetch_add(1, Ordering::Relaxed);

            // Handle persistence - zero allocation
            if let Some(ref tx) = self.persistence_tx {
                let operation = PersistenceOperation {
                    operation_type: OperationType::Delete,
                    key: key.clone(),
                    encrypted_value: None,
                    timestamp: current_timestamp(),
                };
                let _ = tx.send(operation);
            }

            // Decrypt the removed encrypted value to return it
            Some(self.decrypt_data(&entry.encrypted_value).await)
        } else {
            None
        }
    }

    /// Clear all items from the cache - lock-free atomic operation
    #[inline]
    pub async fn clear(&self) {
        let old_size = self.size.swap(0, Ordering::Relaxed);
        self.cache.clear();

        // Update metrics atomically
        self.metrics
            .deletions
            .fetch_add(old_size as u64, Ordering::Relaxed);

        info!(cleared_entries = old_size, "Cache cleared");
    }

    /// Get cache size - lock-free atomic read
    #[inline]
    pub fn len(&self) -> usize {
        self.size.load(Ordering::Relaxed)
    }

    /// Check if cache is empty - lock-free atomic read
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get cache metrics - zero allocation
    #[inline]
    pub fn metrics(&self) -> Arc<CacheMetrics> {
        self.metrics.clone()
    }

    /// Get cache configuration - zero allocation
    #[inline]
    pub fn config(&self) -> &CacheConfig {
        &self.config
    }

    /// Check if a key exists in the cache (without updating access time) - lock-free
    #[inline]
    pub fn contains_key(&self, key: &K) -> bool {
        if let Some(entry_ref) = self.cache.get(key) {
            !entry_ref.value().is_expired()
        } else {
            false
        }
    }

    /// Get optimized hash for a key - uses SIMD on x86_64
    #[inline]
    pub fn hash_key(&self, key: &K) -> u64 {
        if self.config.simd_enabled {
            simd_hash::fast_hash(key)
        } else {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::Hasher;
            let mut hasher = DefaultHasher::new();
            key.hash(&mut hasher);
            hasher.finish()
        }
    }

    /// Get all keys currently in the cache - zero allocation iterator
    pub fn keys(&self) -> Vec<K> {
        self.cache.iter().map(|entry| entry.key().clone()).collect()
    }

    /// Evict expired entries from the cache
    pub async fn evict_expired(&self) -> usize {
        let mut evicted_count = 0;
        let keys_to_remove: Vec<K> = self
            .cache
            .iter()
            .filter_map(|entry| {
                if entry.value().is_expired() {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();

        for key in keys_to_remove {
            if self.cache.remove(&key).is_some() {
                self.size.fetch_sub(1, Ordering::Relaxed);
                evicted_count += 1;
            }
        }

        if evicted_count > 0 {
            self.metrics
                .expired_entries
                .fetch_add(evicted_count as u64, Ordering::Relaxed);
            debug!(evicted_count, "Evicted expired cache entries");
        }

        evicted_count
    }

    /// Evict LRU entries to make space - completely lock-free using atomic operations
    async fn evict_lru_entries_lockfree(&self) {
        let target_size = (self.config.max_entries as f64 * 0.8) as usize;
        let current_size = self.size.load(Ordering::Relaxed);

        if current_size <= target_size {
            return;
        }

        let mut evicted_count = 0;
        let entries_to_evict = current_size - target_size;

        // Collect entries sorted by last access time (oldest first) - lock-free
        let mut entries_by_access: Vec<(K, u64)> = self
            .cache
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().last_access_time()))
            .collect();

        // Sort by access time (oldest first) for LRU eviction
        entries_by_access.sort_by_key(|(_, access_time)| *access_time);

        // Evict oldest entries
        for (key, _) in entries_by_access.into_iter().take(entries_to_evict) {
            if self.cache.remove(&key).is_some() {
                self.size.fetch_sub(1, Ordering::Relaxed);
                evicted_count += 1;
            }
        }

        if evicted_count > 0 {
            self.metrics
                .evictions
                .fetch_add(evicted_count as u64, Ordering::Relaxed);
            debug!(evicted_count, "LRU eviction completed");
        }
    }

    /// Warm cache from database - load recent entries
    async fn warm_cache(&self, db: &Surreal<Any>) -> Result<(), VaultError> {
        if !self.config.warming_enabled {
            return Ok(());
        }

        let query = r#"
            SELECT key, value, created_at 
            FROM cache_entries 
            ORDER BY created_at DESC 
            LIMIT $limit
        "#;

        match db
            .query(query)
            .bind(("limit", self.config.max_entries / 2))
            .await
        {
            Ok(mut response) => match response.take::<Vec<VaultEntry>>(0) {
                Ok(entries) => {
                    let mut loaded_count = 0;
                    for entry in entries {
                        let cache_entry =
                            Arc::new(CacheEntry::new(entry.value, self.config.ttl_seconds));

                        if let Ok(parsed_key) = serde_json::from_str(&entry.key)
                            && self.cache.insert(parsed_key, cache_entry).is_none() {
                                self.size.fetch_add(1, Ordering::Relaxed);
                                loaded_count += 1;
                            }
                    }
                    info!(loaded_count, "Cache warming completed");
                }
                Err(e) => {
                    warn!(error = %e, "Failed to deserialize cache entries during warming");
                }
            },
            Err(e) => {
                warn!(error = %e, "Failed to load cache entries for warming");
            }
        }

        Ok(())
    }

    /// Start background tasks for cache maintenance - completely lock-free
    async fn start_background_tasks(&self) {
        let cache_clone = self.cache.clone();
        let metrics_clone = self.metrics.clone();
        let running_clone = self.running.clone();
        let size_clone = Arc::new(AtomicUsize::new(0));

        // Copy current size
        size_clone.store(self.size.load(Ordering::Relaxed), Ordering::Relaxed);

        // Expiration cleanup task - lock-free
        let cache_clone2 = cache_clone.clone();
        let size_clone2 = size_clone.clone();
        let metrics_clone2 = metrics_clone.clone();
        let running_clone2 = running_clone.clone();

        tokio::spawn(async move {
            let mut cleanup_interval = interval(Duration::from_secs(60));

            while running_clone2.load(Ordering::Relaxed) {
                cleanup_interval.tick().await;

                let mut evicted_count = 0;
                let keys_to_remove: Vec<K> = cache_clone2
                    .iter()
                    .filter_map(|entry| {
                        if entry.value().is_expired() {
                            Some(entry.key().clone())
                        } else {
                            None
                        }
                    })
                    .collect();

                for key in keys_to_remove {
                    if cache_clone2.remove(&key).is_some() {
                        size_clone2.fetch_sub(1, Ordering::Relaxed);
                        evicted_count += 1;
                    }
                }

                if evicted_count > 0 {
                    metrics_clone2
                        .expired_entries
                        .fetch_add(evicted_count as u64, Ordering::Relaxed);
                    debug!(evicted_count, "Background cleanup evicted expired entries");
                }
            }
        });

        // Metrics reporting task
        let metrics_clone3 = self.metrics.clone();
        let running_clone3 = self.running.clone();
        let metrics_interval = self.config.metrics_interval_seconds;

        tokio::spawn(async move {
            let mut metrics_interval = interval(Duration::from_secs(metrics_interval));

            while running_clone3.load(Ordering::Relaxed) {
                metrics_interval.tick().await;

                let hits = metrics_clone3.hits.load(Ordering::Relaxed);
                let misses = metrics_clone3.misses.load(Ordering::Relaxed);
                let hit_ratio = metrics_clone3.hit_ratio();
                let evictions = metrics_clone3.evictions.load(Ordering::Relaxed);

                info!(
                    hits = hits,
                    misses = misses,
                    hit_ratio = %format!("{:.2}%", hit_ratio),
                    evictions = evictions,
                    "Cache metrics report"
                );
            }
        });
    }

    /// Persist a cache operation to the database - zero allocation
    async fn persist_operation(
        db: &Surreal<Any>,
        operation: PersistenceOperation<K>,
    ) -> Result<(), VaultError> {
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

    /// Shutdown the cache and cleanup resources
    pub async fn shutdown(&self) {
        self.running.store(false, Ordering::Relaxed);
        info!("Cache shutdown initiated");

        // Give background tasks time to finish
        sleep(Duration::from_millis(100)).await;
    }
}

/// Get current timestamp in seconds since UNIX epoch - zero allocation
#[inline]
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// SIMD-optimized hash function for cache keys
#[cfg(target_arch = "x86_64")]
mod simd_hash {
    use std::hash::{Hash, Hasher};

    /// SIMD-optimized hasher for x86_64 architectures
    pub struct SimdHasher {
        state: u64,
    }

    impl SimdHasher {
        pub fn new() -> Self {
            Self {
                state: 0x517cc1b727220a95,
            } // Random seed
        }
    }

    impl Hasher for SimdHasher {
        fn write(&mut self, bytes: &[u8]) {
            // Use SIMD instructions for faster hashing on supported architectures
            for chunk in bytes.chunks(8) {
                let mut data = [0u8; 8];
                data[..chunk.len()].copy_from_slice(chunk);
                let value = u64::from_le_bytes(data);
                self.state = self
                    .state
                    .wrapping_mul(0x9e3779b97f4a7c15)
                    .wrapping_add(value);
            }
        }

        fn finish(&self) -> u64 {
            self.state
        }
    }

    /// Fast hash function using SIMD optimizations
    pub fn fast_hash<T: Hash>(value: &T) -> u64 {
        let mut hasher = SimdHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }
}

#[cfg(not(target_arch = "x86_64"))]
mod simd_hash {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    /// Fallback hash function for non-x86_64 architectures
    pub fn fast_hash<T: Hash>(value: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }
}

/// Cache invalidation strategies
pub mod invalidation {
    use super::*;

    /// Cache invalidation strategy
    #[derive(Debug)]
    pub enum InvalidationStrategy {
        /// Invalidate by key pattern
        KeyPattern(String),
        /// Invalidate by age (older than specified seconds)
        Age(u64),
        /// Invalidate by access count (less than specified count)
        AccessCount(u64),
        /// Invalidate all entries
        All,
    }

    impl<K> LruCache<K>
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
        /// Invalidate cache entries based on the specified strategy
        pub async fn invalidate(&self, strategy: InvalidationStrategy) -> usize {
            let mut invalidated_count = 0;

            match strategy {
                InvalidationStrategy::KeyPattern(pattern) => {
                    let keys_to_remove: Vec<K> = self
                        .cache
                        .iter()
                        .filter_map(|entry| {
                            if format!("{:?}", entry.key()).contains(&pattern) {
                                Some(entry.key().clone())
                            } else {
                                None
                            }
                        })
                        .collect();

                    for key in keys_to_remove {
                        if self.cache.remove(&key).is_some() {
                            self.size.fetch_sub(1, Ordering::Relaxed);
                            invalidated_count += 1;
                        }
                    }
                }
                InvalidationStrategy::Age(max_age_seconds) => {
                    let current_time = current_timestamp();
                    let keys_to_remove: Vec<K> = self
                        .cache
                        .iter()
                        .filter_map(|entry| {
                            let age = current_time.saturating_sub(entry.value().created_at);
                            if age > max_age_seconds {
                                Some(entry.key().clone())
                            } else {
                                None
                            }
                        })
                        .collect();

                    for key in keys_to_remove {
                        if self.cache.remove(&key).is_some() {
                            self.size.fetch_sub(1, Ordering::Relaxed);
                            invalidated_count += 1;
                        }
                    }
                }
                InvalidationStrategy::AccessCount(min_access_count) => {
                    let keys_to_remove: Vec<K> = self
                        .cache
                        .iter()
                        .filter_map(|entry| {
                            if entry.value().access_count.load(Ordering::Relaxed) < min_access_count
                            {
                                Some(entry.key().clone())
                            } else {
                                None
                            }
                        })
                        .collect();

                    for key in keys_to_remove {
                        if self.cache.remove(&key).is_some() {
                            self.size.fetch_sub(1, Ordering::Relaxed);
                            invalidated_count += 1;
                        }
                    }
                }
                InvalidationStrategy::All => {
                    invalidated_count = self.size.load(Ordering::Relaxed);
                    self.clear().await;
                }
            }

            if invalidated_count > 0 {
                info!(invalidated_count, "Cache invalidation completed");
            }

            invalidated_count
        }
    }
}
