//! Key store builders

use crate::store::{FileKeyStore, KeychainStore};
use crate::KeyStorage;

/// Builder for file-based key store
pub struct FileKeyStoreBuilder {
    base_path: String,
}

impl FileKeyStoreBuilder {
    pub fn new(base_path: impl Into<String>) -> Self {
        Self {
            base_path: base_path.into(),
        }
    }
}

/// Trait for types that can build a key store
pub trait KeyStoreBuilder: Send + Sync {
    type Store: KeyStorage;

    /// Build the key store with the given master key
    fn build(self, master_key: [u8; 32]) -> Self::Store;
}

impl KeyStoreBuilder for FileKeyStoreBuilder {
    type Store = FileKeyStore;

    fn build(self, master_key: [u8; 32]) -> Self::Store {
        FileKeyStore::new(&self.base_path, master_key)
    }
}

/// Builder for keychain store
pub struct KeychainStoreBuilder {
    service_name: String,
}

impl KeychainStoreBuilder {
    pub fn new(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }
}

impl KeyStoreBuilder for KeychainStoreBuilder {
    type Store = KeychainStore;

    fn build(self, _master_key: [u8; 32]) -> Self::Store {
        // Keychain doesn't need master key
        KeychainStore::new(self.service_name)
    }
}
