//! VaultOperation trait implementation for LocalVaultProvider
//!
//! Contains the main trait implementation that provides the public vault interface.

use super::super::LocalVaultProvider;
use crate::core::VaultValue;
use crate::error::VaultError;
use crate::operation::{
    Passphrase, VaultBoolRequest, VaultChangePassphraseRequest, VaultFindRequest, VaultGetRequest,
    VaultListNamespacesRequest, VaultListRequest, VaultOperation, VaultPutAllRequest,
    VaultSaveRequest, VaultUnitRequest,
};
use tokio::sync::{mpsc, oneshot};

impl VaultOperation for LocalVaultProvider {
    fn name(&self) -> &str {
        "Local Vault Provider"
    }

    // Check if the vault is locked
    fn is_locked(&self) -> bool {
        // Use sync mutex to avoid runtime issues
        match self.locked.lock() {
            Ok(guard) => *guard,
            Err(_) => {
                // If mutex is poisoned, assume locked for safety
                true
            }
        }
    }

    // Unlock the vault with a passphrase
    fn unlock(&self, passphrase: &Passphrase) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let passphrase_clone = passphrase.clone();

        tokio::spawn(async move {
            let result = provider_clone.unlock_impl(passphrase_clone).await;
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    // Lock the vault
    fn lock(&self) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();

        tokio::spawn(async move {
            let result = provider_clone.lock_impl().await;
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    fn put(&self, key: &str, value: VaultValue) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let key = key.to_string();
        // value is already owned, move it

        tokio::spawn(async move {
            let result = provider_clone.put_impl(key, value, None).await;
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    fn get(&self, key: &str) -> VaultGetRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let key = key.to_string();

        tokio::spawn(async move {
            let result = provider_clone.get_impl(&key, None).await;
            let _ = tx.send(result);
        });

        VaultGetRequest::new(rx)
    }

    fn delete(&self, key: &str) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let key = key.to_string();

        tokio::spawn(async move {
            // Use the existing delete_impl method which handles authentication internally
            // The JWT validation deadlock has been fixed in session.rs
            log::debug!("PROVIDER: Starting delete_impl for key: {}", key);
            let result = provider_clone.delete_impl(&key, None).await;
            log::debug!("PROVIDER: delete_impl result: {:?}", result);
            // Don't treat NotFound as an error for delete
            let final_result = match result {
                Err(VaultError::ItemNotFound) => {
                    log::debug!("PROVIDER: Converting ItemNotFound to Ok() for delete operation");
                    Ok(())
                },
                other => other,
            };
            log::debug!("PROVIDER: Sending final result: {:?}", final_result);
            let _ = tx.send(final_result);
        });

        VaultUnitRequest::new(rx)
    }

    fn list(&self, prefix: Option<&str>) -> VaultListRequest {
        let (tx, rx) = mpsc::channel(100); // Buffer size 100
        let provider_clone = self.clone();
        let prefix = prefix.map(|s| s.to_string()); // Clone prefix into an Option<String>

        tokio::spawn(async move {
            match provider_clone.list_impl(prefix.as_deref()).await {
                Ok(keys) => {
                    for key in keys {
                        if tx.send(Ok(key)).await.is_err() {
                            // Receiver dropped
                            break;
                        }
                    }
                    // Channel closes when tx drops
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                }
            }
        });

        VaultListRequest::new(rx)
    }

    // Change passphrase
    fn change_passphrase(
        &self,
        old_passphrase: &Passphrase,
        new_passphrase: &Passphrase,
    ) -> VaultChangePassphraseRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let old_passphrase_clone = old_passphrase.clone();
        let new_passphrase_clone = new_passphrase.clone();

        tokio::spawn(async move {
            let result = provider_clone
                .change_passphrase_impl(old_passphrase_clone, new_passphrase_clone)
                .await;
            let _ = tx.send(result);
        });

        VaultChangePassphraseRequest::new(rx)
    }

    // Save is not explicitly needed; operations are typically transactional per request
    fn save(&self) -> VaultSaveRequest {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(Ok(())); // Assume success as operations are immediate
        VaultSaveRequest::new(rx)
    }

    fn put_if_absent(&self, key: &str, value: VaultValue) -> VaultBoolRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let key = key.to_string();
        // value is already owned

        tokio::spawn(async move {
            let result = provider_clone.put_if_absent_impl(key, value).await;
            let _ = tx.send(result);
        });

        VaultBoolRequest::new(rx)
    }

    fn put_all(&self, entries: Vec<(String, VaultValue)>) -> VaultPutAllRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        // entries is already owned

        tokio::spawn(async move {
            let result = provider_clone.put_all_impl(entries).await;
            let _ = tx.send(result);
        });

        VaultPutAllRequest::new(rx)
    }

    fn find(&self, pattern: &str) -> VaultFindRequest {
        let (tx, rx) = mpsc::channel(100); // Buffer size 100
        let provider_clone = self.clone();
        let pattern = pattern.to_string();

        tokio::spawn(async move {
            match provider_clone.find_impl(&pattern).await {
                Ok(results) => {
                    for item in results {
                        if tx.send(Ok(item)).await.is_err() {
                            // Receiver dropped
                            break;
                        }
                    }
                    // Channel closes when tx drops
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                }
            }
        });

        VaultFindRequest::new(rx)
    }

    fn is_new_vault(&self) -> bool {
        // For sync context, check if vault database file exists
        // Synchronous filesystem check prevents async runtime conflicts
        !self.config.vault_path.exists()
    }

    fn supports_namespaces(&self) -> bool {
        true
    }

    fn create_namespace(&self, _namespace: &str) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        // Namespaces are implicit in this implementation - created when first key is stored
        let _ = tx.send(Ok(()));
        VaultUnitRequest::new(rx)
    }

    // Namespace-aware operations

    fn put_with_namespace(
        &self,
        namespace: &str,
        key: &str,
        value: VaultValue,
    ) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let namespace = namespace.to_string();
        let key = key.to_string();

        tokio::spawn(async move {
            let result = provider_clone
                .put_with_namespace(namespace, key, value)
                .await
                .map_err(|e| crate::error::VaultError::Provider(e.to_string()));
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    fn get_by_namespace(&self, namespace: &str) -> VaultListRequest {
        let (tx, rx) = mpsc::channel(100);
        let provider_clone = self.clone();
        let namespace = namespace.to_string();

        tokio::spawn(async move {
            match provider_clone.get_keys_by_namespace(namespace).await {
                Ok(keys) => {
                    for key in keys {
                        if tx.send(Ok(key)).await.is_err() {
                            break;
                        }
                    }
                }
                Err(e) => {
                    let _ = tx
                        .send(Err(crate::error::VaultError::Provider(e.to_string())))
                        .await;
                }
            }
        });

        VaultListRequest::new(rx)
    }

    fn get_from_namespace(&self, namespace: &str, key: &str) -> VaultGetRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let namespace = namespace.to_string();
        let key = key.to_string();

        tokio::spawn(async move {
            let result = provider_clone.get_impl(&key, Some(&namespace)).await;
            let _ = tx.send(result);
        });

        VaultGetRequest::new(rx)
    }

    fn delete_from_namespace(&self, namespace: &str, key: &str) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();
        let namespace = namespace.to_string();
        let key = key.to_string();

        tokio::spawn(async move {
            let result = provider_clone.delete_impl(&key, Some(&namespace)).await;
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    fn find_in_namespace(&self, namespace: &str, pattern: &str) -> VaultFindRequest {
        let (tx, rx) = mpsc::channel(100);
        let provider_clone = self.clone();
        let namespace = namespace.to_string();
        let pattern = pattern.to_string();

        tokio::spawn(async move {
            match provider_clone
                .find_in_namespace_impl(&namespace, &pattern)
                .await
            {
                Ok(results) => {
                    for item in results {
                        if tx.send(Ok(item)).await.is_err() {
                            break;
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(super::super::map_dao_error(e))).await;
                }
            }
        });

        VaultFindRequest::new(rx)
    }

    fn list_namespaces(&self) -> VaultListNamespacesRequest {
        let (tx, rx) = oneshot::channel();
        let provider_clone = self.clone();

        tokio::spawn(async move {
            let result = provider_clone.list_namespaces_impl().await;
            let _ = tx.send(result);
        });

        VaultListNamespacesRequest::new(rx)
    }
}
