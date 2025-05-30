//! OS Keychain-based key storage (macOS Keychain, Windows Credential Store, Linux Secret Service)

use crate::CryptError;
use crate::key::{
    AsyncDeleteResult, AsyncExistsResult, AsyncListResult, AsyncRetrieveResult, AsyncStoreResult,
    KeyEnumeration, KeyId, KeyImport, KeyRetrieval, KeyStorage,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use zeroize::Zeroizing;

/// OS Keychain store
#[derive(Clone)]
pub struct KeychainStore {
    service_name: String,
}

impl KeychainStore {
    /// Create a new keychain store for the specified app
    pub fn for_app(service_name: impl Into<String>) -> Self {
        Self {
            service_name: service_name.into(),
        }
    }

    /// Create a new keychain store (legacy API)
    pub fn new(service_name: impl Into<String>) -> Self {
        Self::for_app(service_name)
    }
}

impl KeyStorage for KeychainStore {
    fn exists(&self, key_id: &dyn KeyId) -> impl AsyncExistsResult {
        let service_name = self.service_name.clone();
        let key_id_str = key_id.full_id();

        async move {
            tokio::task::spawn_blocking(move || {
                let keyring = keyring::Entry::new(&service_name, &key_id_str)
                    .map_err(|e| CryptError::Io(format!("Keychain error: {}", e)))?;

                match keyring.get_password() {
                    Ok(_) => Ok(true),
                    Err(keyring::Error::NoEntry) => Ok(false),
                    Err(e) => Err(CryptError::Io(format!("Keychain error: {}", e))),
                }
            })
            .await
            .map_err(|e| CryptError::internal(format!("Task failed: {}", e)))?
        }
    }

    fn delete(&self, key_id: &dyn KeyId) -> impl AsyncDeleteResult {
        let service_name = self.service_name.clone();
        let key_id_str = key_id.full_id();

        async move {
            tokio::task::spawn_blocking(move || {
                let keyring = keyring::Entry::new(&service_name, &key_id_str)
                    .map_err(|e| CryptError::Io(format!("Keychain error: {}", e)))?;

                keyring.delete_credential().map_err(|e| {
                    CryptError::Io(format!("Failed to delete from keychain: {}", e))
                })?;

                Ok(())
            })
            .await
            .map_err(|e| CryptError::internal(format!("Task failed: {}", e)))?
        }
    }
}

impl KeyImport for KeychainStore {
    fn store(&self, key_id: &dyn KeyId, key_material: &[u8]) -> impl AsyncStoreResult {
        let service_name = self.service_name.clone();
        let key_id_str = key_id.full_id();
        let encoded = Zeroizing::new(STANDARD.encode(key_material));

        async move {
            tokio::task::spawn_blocking(move || {
                let keyring = keyring::Entry::new(&service_name, &key_id_str)
                    .map_err(|e| CryptError::Io(format!("Keychain error: {}", e)))?;

                keyring
                    .set_password(&encoded)
                    .map_err(|e| CryptError::Io(format!("Failed to store in keychain: {}", e)))?;

                Ok(())
            })
            .await
            .map_err(|e| CryptError::internal(format!("Task failed: {}", e)))?
        }
    }
}

impl KeyRetrieval for KeychainStore {
    fn retrieve(&self, key_id: &dyn KeyId) -> impl AsyncRetrieveResult {
        let service_name = self.service_name.clone();
        let key_id_str = key_id.full_id();

        async move {
            tokio::task::spawn_blocking(move || {
                let keyring = keyring::Entry::new(&service_name, &key_id_str)
                    .map_err(|e| CryptError::Io(format!("Keychain error: {}", e)))?;

                let encoded = keyring
                    .get_password()
                    .map_err(|e| CryptError::Io(format!("Failed to read from keychain: {}", e)))?;

                STANDARD
                    .decode(&encoded)
                    .map_err(|e| CryptError::Io(format!("Invalid key format: {}", e)))
            })
            .await
            .map_err(|e| CryptError::internal(format!("Task failed: {}", e)))?
        }
    }
}

impl KeyEnumeration for KeychainStore {
    fn list(&self, _namespace_pattern: &str) -> impl AsyncListResult {
        async move {
            // Most OS keychains don't support listing
            Err(CryptError::Io(
                "Keychain does not support listing keys".into(),
            ))
        }
    }
}
