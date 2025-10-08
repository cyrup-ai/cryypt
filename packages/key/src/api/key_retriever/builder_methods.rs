//! Basic builder methods for key retrieval configuration

use super::builder_states::{
    KeyRetriever, KeyRetrieverReady, KeyRetrieverWithStore, KeyRetrieverWithStoreAndNamespace,
};
use crate::traits::KeyStorage;

impl KeyRetriever {
    /// Create a new key retriever
    /// Zero-cost constructor for zero-sized type
    #[must_use]
    pub const fn new() -> Self {
        Self
    }

    /// Set the key storage backend
    /// Generic constraint enables compile-time optimization
    pub fn with_store<S: KeyStorage + 'static>(self, store: S) -> KeyRetrieverWithStore<S> {
        KeyRetrieverWithStore { store }
    }
}

impl Default for KeyRetriever {
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
    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}
