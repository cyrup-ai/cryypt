//! OS Keychain storage implementation for PQCrypto keys
//!
//! Uses the operating system's secure credential storage:
//! - macOS: Keychain Access
//! - Windows: Credential Manager
//! - Linux: Secret Service API (GNOME Keyring, KWallet)

use super::KeyStorage;
use crate::error::{VaultError, VaultResult};
use cryypt_key::{
    api::KeyRetriever,
    store::KeychainStore,
    traits::{KeyImport, KeyStorage as CryyptKeyStorage},
    KeyId, SimpleKeyId,
};
use std::sync::{Arc, Mutex};

/// OS Keychain storage backend for PQCrypto keys
///
/// This implementation stores keys in the operating system's secure credential store,
/// providing hardware-backed encryption on supported platforms (macOS Secure Enclave,
/// Windows TPM, Linux TPM).
///
/// # Security
/// - Keys are encrypted at rest by the OS
/// - Access controlled by OS permissions
/// - Keys persist across application restarts
/// - Supports biometric authentication on macOS/Windows
#[derive(Debug, Clone)]
pub struct KeychainStorage {
    app_name: String,
}

impl KeychainStorage {
    /// Create a new keychain storage instance
    ///
    /// # Arguments
    /// * `app_name` - Application identifier for keychain entries (typically "vault")
    pub fn new(app_name: impl Into<String>) -> Self {
        Self {
            app_name: app_name.into(),
        }
    }

    /// Create keychain storage with default app name "vault"
    pub fn default_app() -> Self {
        Self::new("vault")
    }
}

impl KeyStorage for KeychainStorage {
    async fn store(&self, key_id: &str, keypair: &[u8]) -> VaultResult<()> {
        let keychain_store = KeychainStore::for_app(&self.app_name);
        let simple_key_id = SimpleKeyId::new(key_id);

        // Use Arc<Mutex> to capture errors from the callback
        let error_state = Arc::new(Mutex::new(None::<String>));
        let error_state_clone = Arc::clone(&error_state);

        keychain_store
            .store(&simple_key_id, keypair)
            .on_result(move |result| match result {
                Ok(()) => (),
                Err(e) => {
                    log::error!("Failed to store PQCrypto keypair in keychain: {}", e);
                    if let Ok(mut error_guard) = error_state_clone.lock() {
                        *error_guard = Some(format!(
                            "Failed to store PQCrypto keypair in keychain: {}",
                            e
                        ));
                    }
                }
            })
            .await;

        // Check if an error occurred
        if let Ok(error_guard) = error_state.lock()
            && let Some(error) = error_guard.as_ref() {
            return Err(VaultError::Provider(error.clone()));
        }

        log::debug!("Successfully stored PQCrypto keypair: {}", key_id);
        Ok(())
    }

    async fn retrieve(&self, key_id: &str) -> VaultResult<Vec<u8>> {
        let keychain_store = KeychainStore::for_app(&self.app_name);

        // Use KeyRetriever with dummy namespace/version since we pass full key_id
        let key_data = KeyRetriever::new()
            .with_store(keychain_store)
            .with_namespace("_") // Dummy, overridden by key_id parameter
            .version(1)          // Dummy, overridden by key_id parameter
            .retrieve(key_id)
            .await;

        if key_data.is_empty() {
            return Err(VaultError::ItemNotFound);
        }

        log::debug!(
            "Successfully retrieved PQCrypto keypair: {} ({} bytes)",
            key_id,
            key_data.len()
        );
        Ok(key_data)
    }

    async fn delete(&self, key_id: &str) -> VaultResult<()> {
        let keychain_store = KeychainStore::for_app(&self.app_name);
        let simple_key_id = SimpleKeyId::new(key_id);

        // Use Arc<Mutex> to capture errors from the callback
        let error_state = Arc::new(Mutex::new(None::<String>));
        let error_state_clone = Arc::clone(&error_state);

        keychain_store
            .delete(&simple_key_id)
            .on_result(move |result| match result {
                Ok(()) => (),
                Err(e) => {
                    log::error!("Failed to delete PQCrypto keypair from keychain: {}", e);
                    if let Ok(mut error_guard) = error_state_clone.lock() {
                        *error_guard = Some(format!(
                            "Failed to delete PQCrypto keypair from keychain: {}",
                            e
                        ));
                    }
                }
            })
            .await;

        // Check if an error occurred
        if let Ok(error_guard) = error_state.lock()
            && let Some(error) = error_guard.as_ref() {
            return Err(VaultError::Provider(error.clone()));
        }

        log::debug!("Successfully deleted PQCrypto keypair: {}", key_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_keychain_storage_lifecycle() {
        let storage = KeychainStorage::new("vault_test");
        let test_key_id = "test_namespace:12345678-1234-1234-1234-123456789abc:pq_keypair";

        // Generate test keypair data
        let test_keypair = vec![0x42; 2400]; // 2400 bytes for ML-KEM-768

        // Clean up any existing test key
        let _ = storage.delete(test_key_id).await;

        // Test store
        storage
            .store(test_key_id, &test_keypair)
            .await
            .expect("Failed to store test keypair");

        // Test retrieve
        let retrieved = storage
            .retrieve(test_key_id)
            .await
            .expect("Failed to retrieve test keypair");
        assert_eq!(retrieved, test_keypair);

        // Test delete
        storage
            .delete(test_key_id)
            .await
            .expect("Failed to delete test keypair");

        // Verify deletion - should fail to retrieve
        let result = storage.retrieve(test_key_id).await;
        assert!(result.is_err());
    }
}
