//! Background task management and cache warming
//!
//! This module handles background operations including:
//! - Cache warming from persistent storage
//! - Background cleanup task scheduling
//! - Metrics reporting tasks
//! - Graceful shutdown coordination
//! - Task lifecycle management

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
    /// Warm cache from database - load recent entries
    pub(crate) async fn warm_cache(&self, db: &Surreal<Any>) -> Result<(), VaultError> {
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

                        // Extract key from record ID for natural keys
                        use crate::db::vault_store::backend::key_utils;
                        if let Some(record_id) = &entry.id
                            && let Ok(extracted_key) =
                                key_utils::extract_key_from_record_id(&record_id.to_string())
                            && let Ok(parsed_key) = serde_json::from_str(&extracted_key)
                            && self.cache.insert(parsed_key, cache_entry).is_none()
                        {
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
    pub(crate) async fn start_background_tasks(&self) {
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

    /// Shutdown the cache and cleanup resources
    pub async fn shutdown(&self) {
        self.running.store(false, Ordering::Relaxed);
        info!("Cache shutdown initiated");

        // Give background tasks time to finish
        sleep(Duration::from_millis(100)).await;
    }
}
