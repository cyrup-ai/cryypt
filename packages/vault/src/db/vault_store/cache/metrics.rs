//! Cache metrics for monitoring and performance analysis

use std::sync::atomic::{AtomicU64, Ordering};

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
