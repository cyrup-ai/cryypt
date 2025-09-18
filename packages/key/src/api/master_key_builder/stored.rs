//! Stored master key implementation
//!
//! Contains the StoredMasterKey type for keys managed in storage backends.

use super::MasterKeyProvider;
use crate::{SimpleKeyId, traits::{KeyImport, KeyRetrieval, KeyStorage}};
use async_task::AsyncTask;
use rand::RngCore;
use tokio::sync::oneshot;

/// Represents a master key stored in a key store
pub struct StoredMasterKey<S: KeyStorage + KeyRetrieval + Send + Sync> {
    pub(crate) store: S,
    pub(crate) key_id: SimpleKeyId,
}

impl<S: KeyStorage + KeyRetrieval + KeyImport + Send + Sync + Clone + 'static> StoredMasterKey<S> {
    /// Async version of resolve for use in async contexts
    pub async fn resolve_async(&self) -> crate::Result<[u8; 32]> {
        let store = self.store.clone();
        let key_id = self.key_id.clone();

        // Try to retrieve existing key first
        match store.retrieve(&key_id).await {
            Ok(existing_key) => {
                let mut key = [0u8; 32];
                key.copy_from_slice(&existing_key[..32]);
                Ok(key)
            }
            Err(_) => {
                // Generate new master key
                let mut key = [0u8; 32];
                rand::rng().fill_bytes(&mut key);

                // Store it
                store.store(&key_id, &key).await.map_err(|e| {
                    crate::KeyError::InvalidKey(format!("Failed to store master key: {e}"))
                })?;

                Ok(key)
            }
        }
    }
}

impl<S: KeyStorage + KeyRetrieval + KeyImport + Send + Sync + Clone + 'static> MasterKeyProvider
    for StoredMasterKey<S>
{
    fn resolve(&self) -> crate::Result<[u8; 32]> {
        // Use channel-based coordination for sync interface
        let (tx, rx) = oneshot::channel();
        let store = self.store.clone();
        let key_id = self.key_id.clone();

        tokio::spawn(async move {
            let result = async {
                // Try to retrieve existing key first
                match store.retrieve(&key_id).await {
                    Ok(existing_key) => {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&existing_key[..32]);
                        Ok(key)
                    }
                    Err(_) => {
                        // Generate new master key
                        let mut key = [0u8; 32];
                        rand::rng().fill_bytes(&mut key);

                        // Store it
                        store.store(&key_id, &key).await.map_err(|e| {
                            crate::KeyError::InvalidKey(format!("Failed to store master key: {e}"))
                        })?;

                        Ok(key)
                    }
                }
            }.await;
            let _ = tx.send(result);
        });

        rx.blocking_recv()
            .map_err(|_| crate::KeyError::InvalidKey("Key resolution failed".to_string()))?
    }
}