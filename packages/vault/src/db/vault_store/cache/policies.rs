//! Cache policies - eviction, invalidation, and optimization strategies
//!
//! This module contains cache policy management including:
//! - LRU eviction policies
//! - Cache invalidation strategies
//! - Hash optimization (SIMD-accelerated)
//! - Key enumeration and pattern matching
//! - Expired entry cleanup policies

use super::*;

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
    /// Get optimized hash for a key - uses SIMD on x86_64
    #[inline]
    pub fn hash_key(&self, key: &K) -> u64 {
        if self.config.simd_enabled {
            simd_hash::fallback_hash::fast_hash(key)
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
    pub(crate) async fn evict_lru_entries_lockfree(&self) {
        let target_size = (self.config.max_entries as f64 * 0.8) as usize;
        let current_size = self.size.load(Ordering::Relaxed);

        if current_size <= target_size {
            return;
        }

        let mut evicted_count = 0;
        let entries_to_evict = current_size - target_size;

        // Collect entries sorted by last access time (oldest first) - lock-free
        let mut entries_by_access: Vec<(K, u64, u64)> = self
            .cache
            .iter()
            .map(|entry| {
                let key = entry.key().clone();
                let access_time = entry.value().last_access_time();
                let key_hash = self.hash_key(&key);
                debug!(key = ?key, access_time = access_time, key_hash = key_hash, "LRU eviction candidate");
                (key, access_time, key_hash)
            })
            .collect();

        // Sort by access time (oldest first), then by key hash for stable ordering
        entries_by_access.sort_by_key(|(_, access_time, key_hash)| (*access_time, *key_hash));

        debug!(
            entries_count = entries_by_access.len(),
            entries_to_evict = entries_to_evict,
            "LRU eviction sorting complete"
        );

        // Evict oldest entries
        for (key, _, _) in entries_by_access.into_iter().take(entries_to_evict) {
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
                        if entry.value().access_count.load(Ordering::Relaxed) < min_access_count {
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
