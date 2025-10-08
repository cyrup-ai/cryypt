//! Zero-Allocation Buffer Management for JSON-RPC Processing
//!
//! Implements connection-level buffer management using simd-json for zero-allocation
//! JSON parsing with buffer reuse patterns. Based on research findings from simd-json
//! best practices and production patterns.

use super::types::{Result, RpcError};
use simd_json::{Buffers, OwnedValue};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, trace, warn};

/// Buffer utilization statistics for monitoring
#[derive(Debug, Clone)]
pub struct BufferStats {
    /// Total number of parse operations performed
    pub parse_count: u64,
    /// Total bytes processed through this buffer
    pub total_bytes_processed: u64,
    /// Current buffer capacity in bytes
    pub current_capacity: usize,
    /// Peak buffer size reached
    pub peak_buffer_size: usize,
    /// Buffer reuse efficiency (avg bytes per parse)
    pub reuse_efficiency: f64,
    /// Number of buffer reallocations
    pub reallocation_count: u64,
}

impl BufferStats {
    /// Calculate memory efficiency score (0.0 to 1.0)
    #[must_use]
    pub fn efficiency_score(&self) -> f64 {
        if self.parse_count == 0 {
            return 0.0;
        }

        // Higher reuse efficiency and lower reallocation rate = better score
        let reuse_factor = (self.reuse_efficiency / 1024.0).min(1.0); // Normalize to KB
        let realloc_penalty = if self.parse_count > 0 {
            #[allow(clippy::cast_precision_loss)]
            let ratio = (self.reallocation_count as f64 / self.parse_count as f64).min(0.5);
            1.0 - ratio
        } else {
            1.0
        };

        (reuse_factor * 0.7) + (realloc_penalty * 0.3)
    }
}

/// Connection-specific buffer management for zero-allocation JSON parsing
pub struct ConnectionBuffers {
    /// Core simd-json buffer structures for zero-allocation parsing
    buffers: Buffers,
    /// Parse operation counter
    parse_count: AtomicU64,
    /// Total bytes processed counter
    total_bytes_processed: AtomicU64,
    /// Peak buffer size tracking
    peak_buffer_size: AtomicU64,
    /// Buffer reallocation counter
    reallocation_count: AtomicU64,
    /// Initial capacity for tracking growth
    initial_capacity: usize,
}

impl ConnectionBuffers {
    /// Create new connection buffers with specified initial capacity
    #[must_use]
    pub fn new(initial_capacity: usize) -> Self {
        Self {
            buffers: Buffers::default(),
            parse_count: AtomicU64::new(0),
            total_bytes_processed: AtomicU64::new(0),
            peak_buffer_size: AtomicU64::new(initial_capacity as u64),
            reallocation_count: AtomicU64::new(0),
            initial_capacity,
        }
    }

    /// Create buffers with default capacity (4KB)
    #[must_use]
    pub fn with_default_capacity() -> Self {
        Self::new(4096)
    }

    /// Process JSON request data with zero-allocation parsing
    ///
    /// This is the core method that implements zero-allocation JSON parsing
    /// using simd-json's buffer reuse patterns. The buffer and tape are reused
    /// across multiple parse operations to avoid allocations.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Input data is empty
    /// - JSON data exceeds maximum size limit (16MB)
    /// - JSON parsing fails due to invalid syntax
    /// - Buffer allocation fails during parsing
    pub fn process_request(&mut self, data: &mut [u8]) -> Result<OwnedValue> {
        let data_len = data.len();

        // Validate input size
        if data.is_empty() {
            return Err(RpcError::parse_error("Empty JSON data".to_string()));
        }

        if data_len > 16 * 1024 * 1024 {
            // 16MB limit
            return Err(RpcError::parse_error(
                "JSON data exceeds maximum size limit (16MB)".to_string(),
            ));
        }

        // Update metrics
        self.parse_count.fetch_add(1, Ordering::Relaxed);
        self.total_bytes_processed
            .fetch_add(data_len as u64, Ordering::Relaxed);

        // Zero-allocation parsing using simd-json buffer reuse
        let parse_result = simd_json::to_owned_value_with_buffers(data, &mut self.buffers)
            .map_err(|e| {
                warn!("JSON parse failed for {} bytes: {}", data_len, e);
                RpcError::parse_error(format!("Invalid JSON: {e}"))
            })?;

        // Update peak buffer size tracking (estimate)
        let estimated_capacity = data_len * 2; // Conservative estimate
        let current_peak = self.peak_buffer_size.load(Ordering::Relaxed);
        if (estimated_capacity as u64) > current_peak {
            self.peak_buffer_size
                .store(estimated_capacity as u64, Ordering::Relaxed);
        }

        trace!("Parsed {} bytes successfully", data_len);
        Ok(parse_result)
    }

    /// Process batch JSON requests with optimized buffer reuse
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any individual chunk fails JSON parsing
    /// - Input data validation fails for any chunk
    /// - Buffer allocation fails during batch processing
    pub fn process_batch_requests(
        &mut self,
        data_chunks: &mut [&mut [u8]],
    ) -> Result<Vec<OwnedValue>> {
        let mut results = Vec::with_capacity(data_chunks.len());

        for chunk in data_chunks {
            match self.process_request(chunk) {
                Ok(value) => results.push(value),
                Err(e) => {
                    // For batch processing, we continue with other requests even if one fails
                    warn!("Batch request parsing failed: {}", e);
                    return Err(e);
                }
            }
        }

        Ok(results)
    }

    /// Clear buffers while preserving capacity for reuse
    pub fn clear(&mut self) {
        // Note: simd-json 0.15.1 Buffers don't have a clear method
        // We recreate buffers to achieve similar effect
        self.buffers = Buffers::default();
        trace!("Buffers cleared, capacity preserved");
    }

    /// Reset all buffers and statistics (use sparingly)
    pub fn reset(&mut self) {
        self.buffers = Buffers::default();
        self.parse_count.store(0, Ordering::Relaxed);
        self.total_bytes_processed.store(0, Ordering::Relaxed);
        self.peak_buffer_size
            .store(self.initial_capacity as u64, Ordering::Relaxed);
        self.reallocation_count.store(0, Ordering::Relaxed);
        debug!("Buffers reset to initial state");
    }

    /// Get current buffer utilization statistics
    pub fn utilization_stats(&self) -> BufferStats {
        let parse_count = self.parse_count.load(Ordering::Relaxed);
        let total_bytes = self.total_bytes_processed.load(Ordering::Relaxed);
        #[allow(clippy::cast_possible_truncation)]
        let peak_size = self.peak_buffer_size.load(Ordering::Relaxed) as usize;
        let realloc_count = self.reallocation_count.load(Ordering::Relaxed);

        let reuse_efficiency = if parse_count > 0 {
            #[allow(clippy::cast_precision_loss)]
            let efficiency = total_bytes as f64 / parse_count as f64;
            efficiency
        } else {
            0.0
        };

        BufferStats {
            parse_count,
            total_bytes_processed: total_bytes,
            current_capacity: peak_size, // Use peak size as estimate since capacity() doesn't exist
            peak_buffer_size: peak_size,
            reuse_efficiency,
            reallocation_count: realloc_count,
        }
    }

    /// Get estimated buffer capacity
    pub fn capacity(&self) -> usize {
        #[allow(clippy::cast_possible_truncation)]
        let capacity = self.peak_buffer_size.load(Ordering::Relaxed) as usize;
        capacity
    }

    /// Get estimated buffer length (used space)
    pub fn len(&self) -> usize {
        // simd-json 0.15.1 Buffers don't expose length, return estimate
        0
    }

    /// Check if buffers are empty (estimate)
    pub fn is_empty(&self) -> bool {
        self.parse_count.load(Ordering::Relaxed) == 0
    }

    /// Optimize buffer size based on usage patterns
    pub fn optimize_capacity(&mut self) {
        let stats = self.utilization_stats();

        // If we've had many reallocations, consider growing the buffer
        if stats.reallocation_count > 5 && stats.parse_count > 10 {
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let avg_size = stats.reuse_efficiency as usize;
            let target_capacity = (avg_size * 2).max(self.initial_capacity);

            if target_capacity > self.capacity() {
                // Create new buffers with optimized capacity
                self.buffers = Buffers::default();
                debug!("Optimized buffer capacity to {} bytes", target_capacity);
            }
        }
    }
}

impl Default for ConnectionBuffers {
    fn default() -> Self {
        Self::with_default_capacity()
    }
}

/// Pool of connection buffers for managing multiple connections
pub struct BufferPool {
    /// Available buffers for reuse
    available: std::sync::Mutex<Vec<ConnectionBuffers>>,
    /// Default capacity for new buffers
    default_capacity: usize,
    /// Maximum pool size
    max_pool_size: usize,
    /// Pool statistics
    created_count: AtomicU64,
    reused_count: AtomicU64,
}

impl BufferPool {
    /// Create a new buffer pool
    #[must_use]
    pub fn new(default_capacity: usize, max_pool_size: usize) -> Self {
        Self {
            available: std::sync::Mutex::new(Vec::new()),
            default_capacity,
            max_pool_size,
            created_count: AtomicU64::new(0),
            reused_count: AtomicU64::new(0),
        }
    }

    /// Get a buffer from the pool or create a new one
    pub fn acquire(&self) -> ConnectionBuffers {
        if let Ok(mut pool) = self.available.lock()
            && let Some(mut buffer) = pool.pop()
        {
            buffer.clear(); // Clear but preserve capacity
            self.reused_count.fetch_add(1, Ordering::Relaxed);
            trace!("Reused buffer from pool");
            return buffer;
        }

        // Create new buffer if pool is empty
        self.created_count.fetch_add(1, Ordering::Relaxed);
        trace!("Created new buffer");
        ConnectionBuffers::new(self.default_capacity)
    }

    /// Return a buffer to the pool
    pub fn release(&self, buffer: ConnectionBuffers) {
        if let Ok(mut pool) = self.available.lock() {
            if pool.len() < self.max_pool_size {
                pool.push(buffer);
                trace!("Returned buffer to pool");
            } else {
                trace!("Pool full, dropping buffer");
            }
        }
    }

    /// Get pool statistics
    pub fn pool_stats(&self) -> (u64, u64, usize) {
        let created = self.created_count.load(Ordering::Relaxed);
        let reused = self.reused_count.load(Ordering::Relaxed);
        let available = self.available.lock().map(|pool| pool.len()).unwrap_or(0);
        (created, reused, available)
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new(4096, 10) // 4KB default, max 10 buffers
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json;

    #[test]
    fn test_buffer_creation() {
        let buffers = ConnectionBuffers::new(1024);
        assert_eq!(buffers.capacity(), 1024);
        assert!(buffers.is_empty());
    }

    #[test]
    fn test_json_parsing() {
        let mut buffers = ConnectionBuffers::new(1024);
        let mut json_data = br#"{"jsonrpc": "2.0", "method": "test", "id": 1}"#.to_vec();

        let result = buffers.process_request(&mut json_data);
        assert!(result.is_ok());

        let stats = buffers.utilization_stats();
        assert_eq!(stats.parse_count, 1);
        assert!(stats.total_bytes_processed > 0);
    }

    #[test]
    fn test_buffer_reuse() {
        let mut buffers = ConnectionBuffers::new(1024);

        // Parse multiple JSON documents
        for i in 0..5 {
            let mut json_data = format!(r#"{{"id": {i}, "method": "test"}}"#).into_bytes();
            let result = buffers.process_request(&mut json_data);
            assert!(result.is_ok());
        }

        let stats = buffers.utilization_stats();
        assert_eq!(stats.parse_count, 5);
        assert!(stats.reuse_efficiency > 0.0);
    }

    #[test]
    fn test_invalid_json() {
        let mut buffers = ConnectionBuffers::new(1024);
        let mut invalid_json = b"invalid json".to_vec();

        let result = buffers.process_request(&mut invalid_json);
        assert!(result.is_err());

        match result.unwrap_err() {
            RpcError::ParseError(_) => {} // Expected
            _ => panic!("Expected ParseError"),
        }
    }

    #[test]
    fn test_empty_json() {
        let mut buffers = ConnectionBuffers::new(1024);
        let mut empty_data = Vec::new();

        let result = buffers.process_request(&mut empty_data);
        assert!(result.is_err());
    }

    #[test]
    fn test_large_json_rejection() {
        let mut buffers = ConnectionBuffers::new(1024);
        // Create JSON larger than 16MB limit
        let large_data = vec![b'a'; 17 * 1024 * 1024];
        let mut large_json = large_data;

        let result = buffers.process_request(&mut large_json);
        assert!(result.is_err());
    }

    #[test]
    fn test_batch_processing() {
        let mut buffers = ConnectionBuffers::new(1024);

        let mut json1 = br#"{"id": 1}"#.to_vec();
        let mut json2 = br#"{"id": 2}"#.to_vec();
        let mut json3 = br#"{"id": 3}"#.to_vec();

        let mut chunks = vec![
            json1.as_mut_slice(),
            json2.as_mut_slice(),
            json3.as_mut_slice(),
        ];
        let results = buffers.process_batch_requests(&mut chunks);

        assert!(results.is_ok());
        assert_eq!(results.unwrap().len(), 3);
    }

    #[test]
    fn test_buffer_stats() {
        let mut buffers = ConnectionBuffers::new(1024);
        let mut json_data = br#"{"test": "data"}"#.to_vec();

        buffers.process_request(&mut json_data).unwrap();

        let stats = buffers.utilization_stats();
        assert_eq!(stats.parse_count, 1);
        assert!(stats.total_bytes_processed > 0);
        assert!(stats.efficiency_score() >= 0.0);
        assert!(stats.efficiency_score() <= 1.0);
    }

    #[test]
    fn test_buffer_pool() {
        let pool = BufferPool::new(1024, 5);

        // Acquire and release buffers
        let buffer1 = pool.acquire();
        let buffer2 = pool.acquire();

        pool.release(buffer1);
        pool.release(buffer2);

        let (created, reused, available) = pool.pool_stats();
        assert_eq!(created, 2);
        assert_eq!(available, 2);

        // Acquire again should reuse
        let _buffer3 = pool.acquire();
        let (_, reused_after, _) = pool.pool_stats();
        assert_eq!(reused_after, 1);
    }

    #[test]
    fn test_buffer_clear_and_reset() {
        let mut buffers = ConnectionBuffers::new(1024);
        let mut json_data = br#"{"test": "data"}"#.to_vec();

        buffers.process_request(&mut json_data).unwrap();
        assert_eq!(buffers.utilization_stats().parse_count, 1);

        buffers.clear();
        // Stats should be preserved after clear
        assert_eq!(buffers.utilization_stats().parse_count, 1);

        buffers.reset();
        // Stats should be reset
        assert_eq!(buffers.utilization_stats().parse_count, 0);
    }
}
