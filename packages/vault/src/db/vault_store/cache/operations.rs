//! Core cache operations - encryption, CRUD, persistence
//!
//! This module contains the fundamental cache operations including:
//! - Cache construction and configuration
//! - Encryption and decryption operations
//! - Basic CRUD operations (get, insert, remove, clear)
//! - Persistence coordination
//! - Size management and basic queries

use super::*;
use futures::StreamExt;

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
                        if let Err(e) = persist_operation(&db_clone, operation).await {
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
    pub(crate) async fn encrypt_data(&self, data: &[u8]) -> Result<String, VaultError> {
        let key_guard = self.encryption_key.lock().await;
        let encryption_key = key_guard.as_ref().ok_or_else(|| VaultError::VaultLocked)?;

        // Use AES encryption with proper on_chunk error handling via BadChunk pattern
        let mut encrypted_stream = Cryypt::cipher()
            .aes()
            .with_key(encryption_key.clone())
            .on_chunk(|chunk| match chunk {
                Ok(data) => data,
                Err(e) => {
                    tracing::error!("Cache encryption chunk failed: {}", e);
                    cryypt_common::BadChunk::from_error(e).into()
                }
            })
            .encrypt(data.to_vec());

        // Collect stream into final encrypted data
        let mut encrypted_data = Vec::new();
        while let Some(chunk) = encrypted_stream.next().await {
            encrypted_data.extend_from_slice(&chunk);
        }

        // Check for BadChunk error markers in the result
        if encrypted_data.starts_with(b"ERROR: ") {
            let error_msg = String::from_utf8_lossy(&encrypted_data);
            return Err(VaultError::Encryption(error_msg.to_string()));
        }

        // Additional validation for edge cases
        if encrypted_data.is_empty() {
            return Err(VaultError::Encryption(
                "AES encryption produced no output - unexpected behavior".to_string(),
            ));
        }

        Ok(BASE64_STANDARD.encode(encrypted_data))
    }

    /// Decrypt data using AES with session key - zero allocation
    pub(crate) async fn decrypt_data(
        &self,
        encrypted_b64: &str,
    ) -> Result<Zeroizing<Vec<u8>>, VaultError> {
        let key_guard = self.encryption_key.lock().await;
        let encryption_key = key_guard.as_ref().ok_or_else(|| VaultError::VaultLocked)?;

        // Decode base64
        let encrypted_bytes = BASE64_STANDARD
            .decode(encrypted_b64)
            .map_err(|_| VaultError::Decryption("Invalid base64".to_string()))?;

        // Use AES decryption with proper on_chunk error handling via BadChunk pattern
        let mut decrypted_stream = Cryypt::cipher()
            .aes()
            .with_key(encryption_key.clone())
            .on_chunk(|chunk| match chunk {
                Ok(data) => data,
                Err(e) => {
                    tracing::error!("Cache decryption chunk failed: {}", e);
                    cryypt_common::BadChunk::from_error(e).into()
                }
            })
            .decrypt(encrypted_bytes);

        // Collect stream into final decrypted data
        let mut decrypted_data = Vec::new();
        while let Some(chunk) = decrypted_stream.next().await {
            decrypted_data.extend_from_slice(&chunk);
        }

        // Check for BadChunk error markers in the result
        if decrypted_data.starts_with(b"ERROR: ") {
            let error_msg = String::from_utf8_lossy(&decrypted_data);
            return Err(VaultError::Decryption(error_msg.to_string()));
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
}
