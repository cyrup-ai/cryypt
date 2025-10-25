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
    async fn store(&self, key_id: &str, keypair: &[u8]) -> VaultResult<()> {
        match self {
            KeyStorageBackend::Keychain(storage) => storage.store(key_id, keypair).await,
            KeyStorageBackend::File(storage) => storage.store(key_id, keypair).await,
        }
    }

    async fn retrieve(&self, key_id: &str) -> VaultResult<Vec<u8>> {
        match self {
            KeyStorageBackend::Keychain(storage) => storage.retrieve(key_id).await,
            KeyStorageBackend::File(storage) => storage.retrieve(key_id).await,
        }
    }

    async fn delete(&self, key_id: &str) -> VaultResult<()> {
        match self {
            KeyStorageBackend::Keychain(storage) => storage.delete(key_id).await,
            KeyStorageBackend::File(storage) => storage.delete(key_id).await,
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
