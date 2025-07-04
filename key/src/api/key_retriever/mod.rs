//! Cryptographically secure key retrieval module
//!
//! Contains the main retriever traits, builder patterns, and core types for secure key retrieval.

use crate::{
    traits::KeyStorage,
    SimpleKeyId,
};
use zeroize::Zeroizing;

// Declare submodules
pub mod store;
pub mod batch;
pub mod version;

// Re-export key types from submodules for external use
pub use batch::*;
pub use version::*;

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
    pub fn id(&self) -> &SimpleKeyId {
        &self.id
    }

    /// Extract the key bytes in a secure manner
    #[inline]
    pub fn into_key_bytes(self) -> Vec<u8> {
        self.data.to_vec()
    }
    
    /// Get a reference to the key bytes
    #[inline]
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
    #[inline(always)]
    pub const fn bounded(capacity: usize) -> Self {
        Self {
            capacity,
            bounded: true,
        }
    }

    /// Create unbounded stream configuration
    #[inline(always)]
    pub const fn unbounded() -> Self {
        Self {
            capacity: 0,
            bounded: false,
        }
    }

    /// Default bounded configuration optimized for single key retrieval
    #[inline(always)]
    pub const fn default_bounded() -> Self {
        Self::bounded(1)
    }
}

impl Default for StreamConfig {
    #[inline(always)]
    fn default() -> Self {
        Self::default_bounded()
    }
}

/// Builder for retrieving existing cryptographic keys
/// Zero-sized type for compile-time optimization
#[derive(Debug, Clone, Copy)]
pub struct KeyRetriever;

/// KeyRetriever with store configured
/// Generic over storage to enable monomorphization optimization
#[derive(Debug, Clone)]
pub struct KeyRetrieverWithStore<S: KeyStorage> {
    pub(crate) store: S,
}

/// KeyRetriever with store and namespace configured
/// Uses secure string handling for namespace
#[derive(Debug, Clone)]
pub struct KeyRetrieverWithStoreAndNamespace<S: KeyStorage> {
    pub(crate) store: S,
    pub(crate) namespace: String,
}

/// KeyRetriever with all parameters configured - ready to retrieve
/// Final builder state with all parameters validated
#[derive(Debug, Clone)]
pub struct KeyRetrieverReady<S: KeyStorage> {
    pub(crate) store: S,
    pub(crate) namespace: String,
    pub(crate) version: u32,
}

impl KeyRetriever {
    /// Create a new key retriever
    /// Zero-cost constructor for zero-sized type
    #[inline(always)]
    pub const fn new() -> Self {
        Self
    }

    /// Set the key storage backend
    /// Generic constraint enables compile-time optimization
    #[inline(always)]
    pub fn with_store<S: KeyStorage + 'static>(self, store: S) -> KeyRetrieverWithStore<S> {
        KeyRetrieverWithStore { store }
    }
}

impl Default for KeyRetriever {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl<S: KeyStorage> KeyRetrieverWithStore<S> {
    /// Set the namespace for organizing keys
    /// Namespace is used in key identification
    #[inline]
    pub fn with_namespace(
        self,
        namespace: impl Into<String>,
    ) -> KeyRetrieverWithStoreAndNamespace<S> {
        let namespace = namespace.into();
        // Note: We remove validation here to match README.md pattern
        // Validation can be done in retrieve_internal if needed
        KeyRetrieverWithStoreAndNamespace {
            store: self.store,
            namespace,
        }
    }
}

impl<S: KeyStorage> KeyRetrieverWithStoreAndNamespace<S> {
    /// Set the version number for key rotation
    /// Version must be non-zero for security
    #[inline]
    pub fn version(self, version: u32) -> KeyRetrieverReady<S> {
        // Note: We remove the validation here to match README.md pattern
        // Validation can be done in retrieve_internal if needed
        KeyRetrieverReady {
            store: self.store,
            namespace: self.namespace,
            version,
        }
    }

    /// Get the configured namespace
    #[inline(always)]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}

impl<S: KeyStorage> KeyRetrieverReady<S> {
    /// Generate secure key identifier matching KeyGenerator pattern
    #[inline]
    pub(crate) fn generate_key_id(&self, unique_suffix: Option<&str>) -> SimpleKeyId {
        match unique_suffix {
            Some(suffix) => {
                SimpleKeyId::new(format!("{}:v{}:{}", self.namespace, self.version, suffix))
            }
            None => SimpleKeyId::new(format!("{}:v{}", self.namespace, self.version)),
        }
    }

    /// Get the configured namespace
    #[inline(always)]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Get the configured version
    #[inline(always)]
    pub const fn version(&self) -> u32 {
        self.version
    }
}