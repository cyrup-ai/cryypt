//! Core Types and Builder for File-based Key Storage
//!
//! This module provides the fundamental types and builder pattern for creating
//! file-based key stores with master key encryption.

use std::path::{Path, PathBuf};
use std::sync::Arc;

/// File-based key store that encrypts keys with a master key
#[derive(Clone)]
pub struct FileKeyStore {
    pub(super) base_path: PathBuf,
    pub(super) master_key: Arc<[u8; 32]>,
}

/// Builder for file-based key store
pub struct FileKeyStoreBuilder {
    base_path: PathBuf,
}

impl FileKeyStore {
    /// Create a new file-based key store builder
    pub fn at<P: AsRef<Path>>(base_path: P) -> FileKeyStoreBuilder {
        FileKeyStoreBuilder {
            base_path: base_path.as_ref().to_path_buf(),
        }
    }

    /// Create a new file-based key store (legacy API)
    pub fn new<P: AsRef<Path>>(base_path: P, master_key: [u8; 32]) -> Self {
        Self {
            base_path: base_path.as_ref().to_path_buf(),
            master_key: Arc::new(master_key),
        }
    }

    /// Derive a file path from namespace and version
    pub(super) fn key_path(&self, namespace: &str, version: u32) -> PathBuf {
        let safe_id = format!("{}_{version}", namespace.replace(['/', ':'], "_"));
        self.base_path.join(format!("{safe_id}.key"))
    }
}

impl FileKeyStoreBuilder {
    /// Set the master key and build the store
    #[must_use]
    pub fn with_master_key(self, master_key: [u8; 32]) -> FileKeyStore {
        FileKeyStore {
            base_path: self.base_path,
            master_key: Arc::new(master_key),
        }
    }
}
