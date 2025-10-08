//! Cache entry management with atomic operations

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Secure cache entry storing encrypted data only - lock-free design
#[derive(Debug)]
pub struct CacheEntry {
    /// Encrypted value as base64 string (same format as database)
    pub encrypted_value: String,
    pub created_at: u64,
    pub last_accessed: AtomicU64,
    pub access_count: AtomicU64,
    pub ttl_seconds: u64,
}

impl CacheEntry {
    pub fn new(encrypted_value: String, ttl_seconds: u64) -> Self {
        let now = current_timestamp();
        Self {
            encrypted_value,
            created_at: now,
            last_accessed: AtomicU64::new(now),
            access_count: AtomicU64::new(1),
            ttl_seconds,
        }
    }

    pub fn is_expired(&self) -> bool {
        if self.ttl_seconds == 0 {
            return false;
        }
        let now = current_timestamp();
        let ttl_nanoseconds = self.ttl_seconds * 1_000_000_000; // Convert seconds to nanoseconds
        now.saturating_sub(self.created_at) > ttl_nanoseconds
    }

    pub fn touch(&self) {
        let now = current_timestamp();
        self.last_accessed.store(now, Ordering::Relaxed);
        self.access_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn last_access_time(&self) -> u64 {
        self.last_accessed.load(Ordering::Relaxed)
    }
}

/// Get current timestamp in nanoseconds since UNIX epoch - zero allocation
#[inline]
pub fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
