mod vault;
mod storage;
mod encryption;
mod search;
mod batch;

pub use vault::LocalVaultProvider;

// Re-export the trait implementation
use tokio::spawn;
use tokio::sync::{mpsc, oneshot};
use secrecy::ExposeSecret;

use crate::operation::*;

// Implement the trait using the request/stream pattern
impl VaultOperation for LocalVaultProvider {
    fn name(&self) -> &str {
        self.name()
    }

    // Additional capability checking methods
    fn supports_encryption(&self) -> bool {
        self.supports_encryption()
    }

    fn encryption_type(&self) -> &str {
        self.encryption_type()
    }

    fn supports_defense_in_depth(&self) -> bool {
        self.supports_defense_in_depth()
    }

    fn is_locked(&self) -> bool {
        self.is_locked()
    }

    fn unlock(&self, passphrase: &Passphrase) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let op_clone = self.clone();
        let passphrase = passphrase.expose_secret().to_string(); // Clone passphrase for the task

        spawn(async move {
            let result = op_clone.unlock_impl(&passphrase).await;
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    fn lock(&self) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let op_clone = self.clone();

        spawn(async move {
            let result = op_clone.lock_impl().await;
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    // Updated signature to accept VaultValue
    fn put(&self, key: &str, value: crate::core::VaultValue) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let op_clone = self.clone();
        let key = key.to_string();
        // value is already VaultValue, clone it for the task
        let value = value.clone();

        spawn(async move {
            let result = op_clone.put_impl(&key, value).await;
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    fn get(&self, key: &str) -> VaultGetRequest {
        let (tx, rx) = oneshot::channel();
        let op_clone = self.clone();
        let key = key.to_string();

        spawn(async move {
            // get_impl returns VaultResult<VaultValue>, map ItemNotFound to Ok(None)
            let result = match op_clone.get_impl(&key).await {
                Ok(value) => Ok(Some(value)),
                Err(crate::error::VaultError::ItemNotFound) => Ok(None),
                Err(e) => Err(e),
            };
            let _ = tx.send(result);
        });

        VaultGetRequest::new(rx)
    }

    // Updated signature to accept VaultValue
    fn put_if_absent(&self, key: &str, value: crate::core::VaultValue) -> VaultBoolRequest {
        let (tx, rx) = oneshot::channel();
        let op_clone = self.clone();
        let key = key.to_string();
        // value is already VaultValue, clone it for the task
        let value = value.clone();

        spawn(async move {
            let result = op_clone.put_if_absent_impl(&key, value).await;
            let _ = tx.send(result);
        });

        VaultBoolRequest::new(rx)
    }

    // Updated signature to accept Vec<(String, VaultValue)>
    fn put_all(&self, entries: Vec<(String, crate::core::VaultValue)>) -> VaultPutAllRequest {
        let (tx, rx) = oneshot::channel();
        let op_clone = self.clone();
        // entries is already Vec<(String, VaultValue)>, clone it for the task
        let entries = entries.clone();

        spawn(async move {
            // Pass the cloned entries directly
            let result = op_clone.put_all_impl(&entries).await;
            let _ = tx.send(result);
        });

        VaultPutAllRequest::new(rx)
    }

    fn delete(&self, key: &str) -> VaultUnitRequest {
        let (tx, rx) = oneshot::channel();
        let op_clone = self.clone();
        let key = key.to_string();

        spawn(async move {
            let result = op_clone.delete_impl(&key).await;
            let _ = tx.send(result);
        });

        VaultUnitRequest::new(rx)
    }

    fn find(&self, pattern: &str) -> VaultFindRequest {
        let (tx, rx) = mpsc::channel(100); // Use mpsc for streaming
        let op_clone = self.clone();
        let pattern = pattern.to_string();

        spawn(async move {
            match op_clone.find_impl(&pattern).await {
                Ok(results) => {
                    for item in results {
                        if tx.send(Ok(item)).await.is_err() {
                            // Receiver dropped, stop sending
                            break;
                        }
                    }
                    // Channel closes when tx drops here
                }
                Err(e) => {
                    // Send the error through the channel
                    let _ = tx.send(Err(e)).await;
                }
            }
        });

        VaultFindRequest::new(rx)
    }

    fn list(&self, _prefix: Option<&str>) -> VaultListRequest {
        // Note: LocalVaultProvider's list_impl doesn't currently support prefix filtering.
        // It lists all keys. We'll implement the streaming part but ignore the prefix for now.
        // A future enhancement could add prefix filtering to list_impl.
        let (tx, rx) = mpsc::channel(100); // Use mpsc for streaming
        let op_clone = self.clone();
        // let _prefix = prefix.map(|s| s.to_string()); // Keep prefix if needed later

        spawn(async move {
            match op_clone.list_impl().await {
                Ok(keys) => {
                    for key in keys {
                        // TODO: Add prefix filtering here if list_impl is enhanced
                        if tx.send(Ok(key)).await.is_err() {
                            // Receiver dropped, stop sending
                            break;
                        }
                    }
                    // Channel closes when tx drops here
                }
                Err(e) => {
                    // Send the error through the channel
                    let _ = tx.send(Err(e)).await;
                }
            }
        });

        VaultListRequest::new(rx)
    }

    fn change_passphrase(
        &self,
        old_passphrase: &Passphrase,
        new_passphrase: &Passphrase,
    ) -> VaultChangePassphraseRequest {
        let (tx, rx) = oneshot::channel();
        let op_clone = self.clone();
        let old_passphrase = old_passphrase.expose_secret().to_string();
        let new_passphrase = new_passphrase.expose_secret().to_string();

        spawn(async move {
            let result = op_clone
                .change_passphrase_impl(&old_passphrase, &new_passphrase)
                .await;
            let _ = tx.send(result);
        });

        VaultChangePassphraseRequest::new(rx)
    }

    // Implement the missing save method
    fn save(&self) -> VaultSaveRequest {
        let (tx, rx) = oneshot::channel();
        let op_clone = self.clone();

        spawn(async move {
            let result = op_clone.save_impl().await;
            let _ = tx.send(result);
        });

        VaultSaveRequest::new(rx)
    }
}