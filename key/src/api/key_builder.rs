//! Minimal key builder implementation

use crate::{KeyImport, KeyResult, KeyRetrieval, KeyStorage, SimpleKeyId, traits::KeyProviderBuilder};

/// 256-bit key builder
pub struct Key256Builder;

/// 256-bit key builder with store configured
pub struct Key256BuilderWithStore<S: KeyStorage> {
    store: S,
}

/// 256-bit key builder with store and namespace configured  
pub struct Key256BuilderWithStoreAndNamespace<S: KeyStorage> {
    store: S,
    namespace: String,
}

/// 256-bit key builder with store, namespace, and version configured
pub struct Key256BuilderWithStoreNamespaceAndVersion<S: KeyStorage> {
    store: S,
    namespace: String,
    version: u32,
}

impl Key256Builder {
    /// Set the key storage backend for this key builder
    pub fn with_store<S: KeyStorage + 'static>(self, store: S) -> Key256BuilderWithStore<S> {
        Key256BuilderWithStore { store }
    }
}

impl<S: KeyStorage> Key256BuilderWithStore<S> {
    /// Set the namespace for organizing keys
    pub fn with_namespace(
        self,
        namespace: impl Into<String>,
    ) -> Key256BuilderWithStoreAndNamespace<S> {
        Key256BuilderWithStoreAndNamespace {
            store: self.store,
            namespace: namespace.into(),
        }
    }
}

impl<S: KeyStorage> Key256BuilderWithStoreAndNamespace<S> {
    /// Set the version number for key rotation
    pub fn version(self, version: u32) -> Key256BuilderWithStoreNamespaceAndVersion<S> {
        Key256BuilderWithStoreNamespaceAndVersion {
            store: self.store,
            namespace: self.namespace,
            version,
        }
    }
}

impl KeyProviderBuilder for Key256Builder {
    fn resolve(&self) -> KeyResult {
        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                use rand::RngCore;
                let mut key = vec![0u8; 32];
                rand::rng().fill_bytes(&mut key);
                Ok(key)
            })
            .await;

            let _ = tx.send(result.unwrap_or_else(|e| {
                Err(crate::KeyError::internal(format!(
                    "Key generation task failed: {}",
                    e
                )))
            }));
        });

        KeyResult::new(rx)
    }
}

impl<S: KeyStorage + KeyRetrieval + KeyImport + Send + Sync + Clone + 'static> KeyProviderBuilder
    for Key256BuilderWithStoreNamespaceAndVersion<S>
{
    fn resolve(&self) -> KeyResult {
        let store = self.store.clone();
        let namespace = self.namespace.clone();
        let version = self.version;

        let (tx, rx) = tokio::sync::oneshot::channel();

        // Key generation/retrieval from store logic here
        let key_id = SimpleKeyId::new(format!("{}:v{}", namespace, version));

        tokio::spawn(async move {
            // Try to retrieve existing key first
            match store.retrieve(&key_id).await {
                Ok(existing_key) => {
                    let _ = tx.send(Ok(existing_key));
                }
                Err(_) => {
                    // Generate new key and store it
                    let result = tokio::task::spawn_blocking(move || {
                        use rand::RngCore;
                        let mut key = vec![0u8; 32];
                        rand::rng().fill_bytes(&mut key);
                        Ok(key)
                    })
                    .await;

                    match result {
                        Ok(Ok(new_key)) => {
                            // Store the key
                            if let Err(e) = store.store(&key_id, &new_key).await {
                                let _ = tx.send(Err(crate::KeyError::internal(format!(
                                    "Failed to store key: {}",
                                    e
                                ))));
                            } else {
                                let _ = tx.send(Ok(new_key));
                            }
                        }
                        Ok(Err(e)) => {
                            let _ = tx.send(Err(e));
                        }
                        Err(e) => {
                            let _ = tx.send(Err(crate::KeyError::internal(format!(
                                "Key generation task failed: {}",
                                e
                            ))));
                        }
                    }
                }
            }
        });

        KeyResult::new(rx)
    }
}
