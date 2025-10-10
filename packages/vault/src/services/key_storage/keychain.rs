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

    /// Create key identifier for storage
    fn create_key_id(&self, namespace: &str, version: u32) -> SimpleKeyId {
        SimpleKeyId::new(format!("{}:v{}:pq_keypair", namespace, version))
    }
}

impl KeyStorage for KeychainStorage {
    async fn store(&self, namespace: &str, version: u32, keypair: &[u8]) -> VaultResult<()> {
        let keychain_store = KeychainStore::for_app(&self.app_name);
        let key_id = self.create_key_id(namespace, version);

        // Use Arc<Mutex> to capture errors from the callback
        let error_state = Arc::new(Mutex::new(None::<String>));
        let error_state_clone = Arc::clone(&error_state);

        keychain_store
            .store(&key_id, keypair)
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
        if let Ok(error_guard) = error_state.lock() {
            if let Some(error) = error_guard.as_ref() {
                return Err(VaultError::Provider(error.clone()));
            }
        }

        log::debug!(
            "Successfully stored PQCrypto keypair: {}:v{}",
            namespace,
            version
        );
        Ok(())
    }

    async fn retrieve(&self, namespace: &str, version: u32) -> VaultResult<Vec<u8>> {
        let keychain_store = KeychainStore::for_app(&self.app_name);
        let key_id = self.create_key_id(namespace, version);

        let key_data = KeyRetriever::new()
            .with_store(keychain_store)
            .with_namespace(namespace)
            .version(version)
            .retrieve(key_id.to_string())
            .await;

        if key_data.is_empty() {
            return Err(VaultError::ItemNotFound);
        }

        log::debug!(
            "Successfully retrieved PQCrypto keypair: {}:v{} ({} bytes)",
            namespace,
            version,
            key_data.len()
        );
        Ok(key_data)
    }

    async fn delete(&self, namespace: &str, version: u32) -> VaultResult<()> {
        let keychain_store = KeychainStore::for_app(&self.app_name);
        let key_id = self.create_key_id(namespace, version);

        // Use Arc<Mutex> to capture errors from the callback
        let error_state = Arc::new(Mutex::new(None::<String>));
        let error_state_clone = Arc::clone(&error_state);

        keychain_store
            .delete(&key_id)
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
        if let Ok(error_guard) = error_state.lock() {
            if let Some(error) = error_guard.as_ref() {
                return Err(VaultError::Provider(error.clone()));
            }
        }

        log::debug!(
            "Successfully deleted PQCrypto keypair: {}:v{}",
            namespace,
            version
        );
        Ok(())
    }

    async fn list_versions(&self, namespace: &str) -> VaultResult<Vec<u32>> {
        let mut versions = Vec::new();
        let mut version = 1u32;

        // Iterate through versions until we find one that doesn't exist
        loop {
            match self.retrieve(namespace, version).await {
                Ok(_) => {
                    versions.push(version);
                    version += 1;
                }
                Err(VaultError::ItemNotFound) => break,
                Err(e) => return Err(e),
            }

            // Safety limit to prevent infinite loops
            if version > 1000 {
                log::warn!(
                    "Reached safety limit of 1000 versions for namespace: {}",
                    namespace
                );
                break;
            }
        }

        Ok(versions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_keychain_storage_lifecycle() {
        let storage = KeychainStorage::new("vault_test");
        let test_namespace = "test_namespace";
        let test_version = 999u32; // Use high version to avoid conflicts

        // Generate test keypair data
        let test_keypair = vec![0x42; 2400]; // 2400 bytes for ML-KEM-768

        // Clean up any existing test key
        let _ = storage.delete(test_namespace, test_version).await;

        // Test store
        storage
            .store(test_namespace, test_version, &test_keypair)
            .await
            .expect("Failed to store test keypair");

        // Test retrieve
        let retrieved = storage
            .retrieve(test_namespace, test_version)
            .await
            .expect("Failed to retrieve test keypair");
        assert_eq!(retrieved, test_keypair);

        // Test exists
        assert!(storage.exists(test_namespace, test_version).await);

        // Test delete
        storage
            .delete(test_namespace, test_version)
            .await
            .expect("Failed to delete test keypair");

        // Verify deletion
        assert!(!storage.exists(test_namespace, test_version).await);
    }
}
