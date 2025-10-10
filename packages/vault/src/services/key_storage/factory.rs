//! Factory for creating appropriate key storage

use super::{KeyStorage, KeychainStorage, FileStorage};
use crate::error::VaultResult;
use std::path::PathBuf;

pub enum KeyStorageSource {
    Keychain(String),
    File(PathBuf),
}

/// Enum to hold different key storage backends
///
/// This enum allows us to abstract over different storage types
/// while avoiding trait object limitations with async traits.
pub enum KeyStorageBackend {
    Keychain(KeychainStorage),
    File(FileStorage),
}

impl KeyStorage for KeyStorageBackend {
    async fn store(&self, namespace: &str, version: u32, keypair: &[u8]) -> VaultResult<()> {
        match self {
            KeyStorageBackend::Keychain(storage) => storage.store(namespace, version, keypair).await,
            KeyStorageBackend::File(storage) => storage.store(namespace, version, keypair).await,
        }
    }

    async fn retrieve(&self, namespace: &str, version: u32) -> VaultResult<Vec<u8>> {
        match self {
            KeyStorageBackend::Keychain(storage) => storage.retrieve(namespace, version).await,
            KeyStorageBackend::File(storage) => storage.retrieve(namespace, version).await,
        }
    }

    async fn delete(&self, namespace: &str, version: u32) -> VaultResult<()> {
        match self {
            KeyStorageBackend::Keychain(storage) => storage.delete(namespace, version).await,
            KeyStorageBackend::File(storage) => storage.delete(namespace, version).await,
        }
    }

    async fn list_versions(&self, namespace: &str) -> VaultResult<Vec<u32>> {
        match self {
            KeyStorageBackend::Keychain(storage) => storage.list_versions(namespace).await,
            KeyStorageBackend::File(storage) => storage.list_versions(namespace).await,
        }
    }
}

pub fn create_key_storage(source: KeyStorageSource) -> KeyStorageBackend {
    match source {
        KeyStorageSource::Keychain(app) => KeyStorageBackend::Keychain(KeychainStorage::new(app)),
        KeyStorageSource::File(path) => {
            let base = path.parent()
                .map(|p| p.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("."));
            KeyStorageBackend::File(FileStorage::new(base))
        }
    }
}
