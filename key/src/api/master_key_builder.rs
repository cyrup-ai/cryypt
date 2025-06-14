//! Master key builder

use crate::bits_macro::BitSize;
use crate::{KeyImport, KeyRetrieval, KeyStorage, SimpleKeyId};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use base64::{engine::general_purpose::STANDARD, Engine};
use hex;
use rand::RngCore;
use zeroize::Zeroizing;

/// Master key entry point
pub struct MasterKey;

impl MasterKey {
    /// Create a master key of specified size
    pub fn size(size: BitSize) -> MasterKeyBuilder {
        match size.bits {
            256 => MasterKeyBuilder,
            _ => panic!("Master keys must be 256 bits"),
        }
    }

    /// Create master key from hex string
    pub fn from_hex(hex_str: &str) -> crate::Result<RawMasterKey> {
        MasterKeyBuilder::from_hex(hex_str)
    }

    /// Create master key from base64 string
    pub fn from_base64(base64_str: &str) -> crate::Result<RawMasterKey> {
        MasterKeyBuilder::from_base64(base64_str)
    }

    /// Create master key from passphrase
    pub fn from_passphrase(passphrase: &str) -> PassphraseMasterKey {
        MasterKeyBuilder::from_passphrase(passphrase)
    }

    /// Create master key from environment variable
    pub fn from_env(var_name: &str) -> EnvMasterKey {
        MasterKeyBuilder::from_env(var_name)
    }
}

/// Builder for master key
pub struct MasterKeyBuilder;

/// Master key builder with store configured
pub struct MasterKeyBuilderWithStore<S: KeyStorage> {
    store: S,
}

/// Master key builder with store and namespace configured  
pub struct MasterKeyBuilderWithStoreAndNamespace<S: KeyStorage> {
    store: S,
    namespace: String,
}

/// Master key builder with store, namespace, and version configured
pub struct MasterKeyBuilderWithStoreNamespaceAndVersion<S: KeyStorage> {
    store: S,
    namespace: String,
    version: u32,
}

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

/// Represents a master key stored in a key store
pub struct StoredMasterKey<S: KeyStorage + KeyRetrieval + Send + Sync> {
    store: S,
    key_id: SimpleKeyId,
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

/// Trait for types that can provide a master key
pub trait MasterKeyProvider: Send + Sync {
    /// Resolve to the actual master key
    fn resolve(&self) -> crate::Result<[u8; 32]>;
}

/// Master key derived from a user passphrase
pub struct PassphraseMasterKey {
    passphrase: Zeroizing<String>,
}

impl MasterKeyProvider for PassphraseMasterKey {
    fn resolve(&self) -> crate::Result<[u8; 32]> {
        // Use Argon2 for secure key derivation from passphrase
        let argon2 = Argon2::default();

        // Use a fixed salt for deterministic key derivation
        // In production, you might want configurable salts
        let salt = SaltString::from_b64("YourFixedSaltHere1234567890")
            .map_err(|e| crate::KeyError::InvalidKey(format!("Invalid salt: {}", e)))?;

        let password_hash = argon2
            .hash_password(self.passphrase.as_bytes(), &salt)
            .map_err(|e| {
                crate::KeyError::InvalidKey(format!("Password hashing failed: {}", e))
            })?;

        let hash_output = password_hash
            .hash
            .ok_or_else(|| crate::KeyError::InvalidKey("No hash generated".into()))?;
        let hash_bytes = hash_output.as_bytes();

        if hash_bytes.len() < 32 {
            return Err(crate::KeyError::InvalidKey("Hash too short".into()));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_bytes[..32]);
        Ok(key)
    }
}

/// Master key using raw key material directly
pub struct RawMasterKey {
    key: [u8; 32],
}

impl MasterKeyProvider for RawMasterKey {
    fn resolve(&self) -> crate::Result<[u8; 32]> {
        Ok(self.key)
    }
}

/// Master key loaded from environment variables
pub struct EnvMasterKey {
    var_name: String,
}

impl MasterKeyProvider for EnvMasterKey {
    fn resolve(&self) -> crate::Result<[u8; 32]> {
        let value = std::env::var(&self.var_name)
            .map_err(|_| crate::KeyError::InvalidKey("Master key env var not found".into()))?;

        // Try to decode from hex first
        if let Ok(decoded) = hex::decode(&value) {
            if decoded.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&decoded);
                return Ok(key);
            }
        }

        // Try to decode from base64
        if let Ok(decoded) = STANDARD.decode(&value) {
            if decoded.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&decoded);
                return Ok(key);
            }
        }

        // If neither hex nor base64 worked, derive from the string using Argon2
        let argon2 = Argon2::default();
        let salt = SaltString::from_b64("EnvVarSaltHere1234567890123")
            .map_err(|e| crate::KeyError::InvalidKey(format!("Invalid salt: {}", e)))?;

        let password_hash = argon2.hash_password(value.as_bytes(), &salt).map_err(|e| {
            crate::KeyError::InvalidKey(format!("Password hashing failed: {}", e))
        })?;

        let hash_output = password_hash
            .hash
            .ok_or_else(|| crate::KeyError::InvalidKey("No hash generated".into()))?;
        let hash_bytes = hash_output.as_bytes();

        if hash_bytes.len() < 32 {
            return Err(crate::KeyError::InvalidKey("Hash too short".into()));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_bytes[..32]);
        Ok(key)
    }
}
