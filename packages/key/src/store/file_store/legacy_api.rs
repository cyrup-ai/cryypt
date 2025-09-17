//! Legacy `KeyStore` API Implementation
//!
//! This module provides backward compatibility functions and utilities
//! that were part of the original `file_store` implementation.

use super::core::FileKeyStore;
use crate::api::KeyStore;

impl FileKeyStore {
    /// Legacy constructor for backward compatibility
    pub fn new_legacy<P: AsRef<std::path::Path>>(base_path: P, master_key: [u8; 32]) -> Self {
        Self::new(base_path, master_key)
    }

    /// Legacy key generation method (kept for compatibility)
    #[must_use]
    pub fn generate_key_legacy(
        &self,
        size_bits: u32,
        namespace: &str,
        version: u32,
    ) -> crate::KeyResult {
        <Self as KeyStore>::generate_key(self, size_bits, namespace, version)
    }

    /// Legacy key retrieval method (kept for compatibility)
    #[must_use]
    pub fn retrieve_key_legacy(&self, namespace: &str, version: u32) -> crate::KeyResult {
        <Self as KeyStore>::retrieve_key(self, namespace, version)
    }
}
