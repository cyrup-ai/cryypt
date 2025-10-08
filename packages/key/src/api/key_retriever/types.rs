//! Core types and wrappers for secure key retrieval

use crate::SimpleKeyId;
use zeroize::Zeroizing;

/// Secure wrapper for retrieved key material with automatic cleanup
#[derive(Debug)]
pub struct SecureRetrievedKey {
    id: SimpleKeyId,
    pub(crate) data: Zeroizing<Vec<u8>>,
}

impl SecureRetrievedKey {
    /// Create a new secure wrapper for retrieved key
    #[inline]
    pub(crate) fn new(id: SimpleKeyId, data: Vec<u8>) -> Self {
        Self {
            id,
            data: Zeroizing::new(data),
        }
    }

    /// Get the key identifier
    #[inline]
    #[must_use]
    pub fn id(&self) -> &SimpleKeyId {
        &self.id
    }

    /// Extract the key bytes in a secure manner
    #[inline]
    #[must_use]
    pub fn into_key_bytes(self) -> Vec<u8> {
        self.data.to_vec()
    }

    /// Get a reference to the key bytes
    #[inline]
    #[must_use]
    pub fn key_bytes(&self) -> &[u8] {
        &self.data
    }
}

/// Stream configuration for secure key retrieval operations
#[derive(Debug, Clone, Copy)]
pub struct StreamConfig {
    pub(crate) capacity: usize,
    pub(crate) bounded: bool,
}

impl StreamConfig {
    /// Create bounded stream configuration with specified capacity
    #[must_use]
    pub const fn bounded(capacity: usize) -> Self {
        Self {
            capacity,
            bounded: true,
        }
    }

    /// Create unbounded stream configuration
    #[must_use]
    pub const fn unbounded() -> Self {
        Self {
            capacity: 0,
            bounded: false,
        }
    }

    /// Default bounded configuration optimized for single key retrieval
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
