//! Stored master key implementation
//!
//! Contains the StoredMasterKey type for keys managed in storage backends.

use super::MasterKeyProvider;
use crate::{KeyImport, KeyRetrieval, KeyStorage, SimpleKeyId};
use rand::RngCore;

/// Represents a master key stored in a key store
pub struct StoredMasterKey<S: KeyStorage + KeyRetrieval + Send + Sync> {
    pub(crate) store: S,
    pub(crate) key_id: SimpleKeyId,
}

impl<S: KeyStorage + KeyRetrieval + KeyImport + Send + Sync + Clone + 'static> MasterKeyProvider
    for StoredMasterKey<S>
{
    fn resolve(&self) -> crate::Result<[u8; 32]> {
        // Block on async to provide sync interface for master key
        let store = self.store.clone();
        let key_id = self.key_id.clone();

        let rt = tokio::runtime::Handle::try_current().unwrap_or_else(|_| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .handle()
                .clone()
        });

        rt.block_on(async move {
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
                        crate::KeyError::InvalidKey(format!("Failed to store master key: {}", e))
                    })?;

                    Ok(key)
                }
            }
        })
    }
}