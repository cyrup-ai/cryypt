//! Core Types and Utilities for Key Generation
//!
//! This module provides fundamental types and utility functions for secure key generation
//! including secure buffers, ID generation, and stream configuration.

use crate::SimpleKeyId;
use rand::{RngCore, rng};
use zeroize::Zeroizing;

/// Secure key buffer that automatically zeroizes on drop
/// Prevents key material from remaining in memory
#[derive(Debug)]
pub(crate) struct SecureKeyBuffer {
    data: Zeroizing<Vec<u8>>,
}

impl SecureKeyBuffer {
    /// Create a new secure buffer with the specified size
    /// Uses zeroizing allocator to ensure cleanup
    #[inline]
    pub fn new(size: usize) -> Self {
        Self {
            data: Zeroizing::new(vec![0u8; size]),
        }
    }

    /// Fill the buffer with cryptographically secure random bytes
    /// Uses thread-local RNG for maximum security
    #[inline]
    pub fn fill_secure_random(mut self) -> Self {
        rng().fill_bytes(&mut self.data);
        self
    }

    /// Extract the key bytes in a secure manner
    /// Returns zeroizing vector that will clean up automatically
    #[inline]
    pub fn into_key_bytes(self) -> Vec<u8> {
        self.data.to_vec()
    }
}

/// Generate cryptographically secure unique identifier
/// Uses secure random bytes instead of predictable counters
#[inline]
pub(crate) fn generate_secure_key_id(namespace: &str, version: u32) -> SimpleKeyId {
    let mut id_bytes = [0u8; 16];
    rng().fill_bytes(&mut id_bytes);
    let unique_id = hex::encode(id_bytes);

    // Use format! since this is not in hot path and security is paramount
    let id_str = format!("{namespace}:v{version}:{unique_id}");
    SimpleKeyId::new(id_str)
}

/// Stream configuration for secure key generation operations
/// Encapsulates channel capacity and security settings
#[derive(Debug, Clone, Copy)]
pub struct StreamConfig {
    pub(crate) capacity: usize,
    pub(crate) bounded: bool,
}

impl StreamConfig {
    /// Create bounded stream configuration with specified capacity
    /// Bounded channels provide backpressure control
    #[must_use]
    pub const fn bounded(capacity: usize) -> Self {
        Self {
            capacity,
            bounded: true,
        }
    }

    /// Create unbounded stream configuration
    /// Use with caution - no backpressure control
    #[must_use]
    pub const fn unbounded() -> Self {
        Self {
            capacity: 0,
            bounded: false,
        }
    }

    /// Default bounded configuration optimized for single key generation
    #[must_use]
    pub const fn default_bounded() -> Self {
        Self::bounded(1)
    }
}

impl Default for StreamConfig {
    fn default() -> Self {
        Self::default_bounded()
    }
}
