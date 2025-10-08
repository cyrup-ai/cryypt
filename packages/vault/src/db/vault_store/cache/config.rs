//! Cache configuration with performance and security settings

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
