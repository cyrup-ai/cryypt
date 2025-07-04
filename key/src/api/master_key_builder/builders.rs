//! Master key builder implementations
//!
//! Contains the implementation methods for all master key builder types.

use super::{MasterKeyBuilder, MasterKeyBuilderWithStore, MasterKeyBuilderWithStoreAndNamespace, MasterKeyBuilderWithStoreNamespaceAndVersion};
use super::{PassphraseMasterKey, RawMasterKey, EnvMasterKey};
use crate::{KeyImport, KeyRetrieval, KeyStorage, SimpleKeyId};
use base64::{engine::general_purpose::STANDARD, Engine};
use hex;
use rand::RngCore;
use zeroize::Zeroizing;

impl MasterKeyBuilder {
    /// Set the key storage backend for this master key builder
    pub fn with_store<S: KeyStorage + 'static>(self, store: S) -> MasterKeyBuilderWithStore<S> {
        MasterKeyBuilderWithStore { store }
    }

    /// Direct passphrase-based master key (no storage)
    pub fn from_passphrase(passphrase: &str) -> PassphraseMasterKey {
        PassphraseMasterKey {
            passphrase: Zeroizing::new(passphrase.to_string()),
        }
    }

    /// From raw bytes (no storage)
    pub fn from_bytes(key: [u8; 32]) -> RawMasterKey {
        RawMasterKey { key }
    }

    /// From hex string (no storage)
    pub fn from_hex(hex_str: &str) -> crate::Result<RawMasterKey> {
        let decoded = hex::decode(hex_str)
            .map_err(|e| crate::KeyError::InvalidKey(format!("Invalid hex string: {}", e)))?;

        if decoded.len() != 32 {
            return Err(crate::KeyError::InvalidKey(format!(
                "Hex key must be exactly 32 bytes, got {}",
                decoded.len()
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(RawMasterKey { key })
    }

    /// From base64 string (no storage)
    pub fn from_base64(base64_str: &str) -> crate::Result<RawMasterKey> {
        let decoded = STANDARD
            .decode(base64_str)
            .map_err(|e| crate::KeyError::InvalidKey(format!("Invalid base64 string: {}", e)))?;

        if decoded.len() != 32 {
            return Err(crate::KeyError::InvalidKey(format!(
                "Base64 key must be exactly 32 bytes, got {}",
                decoded.len()
            )));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&decoded);
        Ok(RawMasterKey { key })
    }

    /// From environment variable (no storage)
    pub fn from_env(var_name: &str) -> EnvMasterKey {
        EnvMasterKey {
            var_name: var_name.to_string(),
        }
    }
}

impl<S: KeyStorage> MasterKeyBuilderWithStore<S> {
    pub fn with_namespace(
        self,
        namespace: impl Into<String>,
    ) -> MasterKeyBuilderWithStoreAndNamespace<S> {
        MasterKeyBuilderWithStoreAndNamespace {
            store: self.store,
            namespace: namespace.into(),
        }
    }
}

impl<S: KeyStorage> MasterKeyBuilderWithStoreAndNamespace<S> {
    pub fn version(self, version: u32) -> MasterKeyBuilderWithStoreNamespaceAndVersion<S> {
        MasterKeyBuilderWithStoreNamespaceAndVersion {
            store: self.store,
            namespace: self.namespace,
            version,
        }
    }
}

impl<S: KeyStorage + KeyRetrieval + KeyImport + Send + Sync + Clone + 'static>
    MasterKeyBuilderWithStoreNamespaceAndVersion<S>
{
    /// Generate the master key and store it, returning hex-encoded key
    pub fn generate(&self) -> crate::Result<String> {
        let store = self.store.clone();
        let namespace = self.namespace.clone();
        let version = self.version;

        // Key ID for master key
        let key_id = SimpleKeyId::new(format!("master:{}:v{}", namespace, version));

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
                Ok(existing_key) => Ok(hex::encode(&existing_key)),
                Err(_) => {
                    // Generate new master key
                    let mut key = [0u8; 32];
                    rand::rng().fill_bytes(&mut key);

                    // Store it
                    store.store(&key_id, &key).await.map_err(|e| {
                        crate::KeyError::InvalidKey(format!("Failed to store master key: {}", e))
                    })?;

                    Ok(hex::encode(&key))
                }
            }
        })
    }
}