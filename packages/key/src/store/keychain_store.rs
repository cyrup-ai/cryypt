//! OS Keychain-based key storage (macOS Keychain, Windows Credential Store, Linux Secret Service)
//!
//! Uses channel-based async keychain service for "True async with channels" architecture compliance.

use super::keychain_service::get_keychain_service;
use crate::{
    KeyId,
    store_results::{DeleteResult, ExistsResult, ListResult, RetrieveResult, StoreResult},
    traits::{KeyEnumeration, KeyImport, KeyRetrieval, KeyStorage},
};

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
    fn exists(&self, key_id: &dyn KeyId) -> ExistsResult {
        let service_name = self.service_name.clone();
        let key_id_str = key_id.full_id();

        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let result = match get_keychain_service().await {
                Ok(service) => service.exists(service_name, key_id_str).await,
                Err(e) => Err(e),
            };
            let _ = tx.send(result);
        });

        ExistsResult::new(rx)
    }

    fn delete(&self, key_id: &dyn KeyId) -> DeleteResult {
        let service_name = self.service_name.clone();
        let key_id_str = key_id.full_id();

        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let result = match get_keychain_service().await {
                Ok(service) => service.delete(service_name, key_id_str).await,
                Err(e) => Err(e),
            };
            let _ = tx.send(result);
        });

        DeleteResult::new(rx)
    }
}

impl KeyImport for KeychainStore {
    fn store(&self, key_id: &dyn KeyId, key_material: &[u8]) -> StoreResult {
        let service_name = self.service_name.clone();
        let key_id_str = key_id.full_id();
        let key_material = key_material.to_vec();

        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let result = match get_keychain_service().await {
                Ok(service) => service.store(service_name, key_id_str, key_material).await,
                Err(e) => Err(e),
            };
            let _ = tx.send(result);
        });

        StoreResult::new(rx)
    }
}

impl KeyRetrieval for KeychainStore {
    fn retrieve(&self, key_id: &dyn KeyId) -> RetrieveResult {
        let service_name = self.service_name.clone();
        let key_id_str = key_id.full_id();

        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let result = match get_keychain_service().await {
                Ok(service) => service.retrieve(service_name, key_id_str).await,
                Err(e) => Err(e),
            };
            let _ = tx.send(result);
        });

        RetrieveResult::new(rx)
    }
}

impl KeyEnumeration for KeychainStore {
    fn list(&self, namespace_pattern: &str) -> ListResult {
        let service_name = self.service_name.clone();
        let namespace_pattern = namespace_pattern.to_string();

        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let result = match get_keychain_service().await {
                Ok(_service) => super::keychain_service::KeychainServiceManager::list(
                    service_name,
                    namespace_pattern,
                ),
                Err(e) => Err(e),
            };
            let _ = tx.send(result);
        });

        ListResult::new(rx)
    }
}
