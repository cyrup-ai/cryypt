//! File-based key storage implementation

use crate::{KeyResult, KeyError, Result};
use crate::api::KeyStore;
use aes_gcm::{
    aead::{generic_array::GenericArray, Aead, KeyInit},
    Aes256Gcm,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

/// File-based key store that encrypts keys with a master key
#[derive(Clone)]
pub struct FileKeyStore {
    base_path: PathBuf,
    master_key: Arc<[u8; 32]>,
}

/// Builder for file-based key store
pub struct FileKeyStoreBuilder {
    base_path: PathBuf,
}

impl FileKeyStore {
    /// Create a new file-based key store builder
    pub fn at<P: AsRef<Path>>(base_path: P) -> FileKeyStoreBuilder {
        FileKeyStoreBuilder {
            base_path: base_path.as_ref().to_path_buf(),
        }
    }

    /// Create a new file-based key store (legacy API)
    pub fn new<P: AsRef<Path>>(base_path: P, master_key: [u8; 32]) -> Self {
        Self {
            base_path: base_path.as_ref().to_path_buf(),
            master_key: Arc::new(master_key),
        }
    }

    /// Derive a file path from namespace and version
    fn key_path(&self, namespace: &str, version: u32) -> PathBuf {
        let safe_id = format!("{}_{}", namespace.replace('/', "_").replace(':', "_"), version);
        self.base_path.join(format!("{}.key", safe_id))
    }
}

impl FileKeyStoreBuilder {
    /// Set the master key and build the store
    pub fn with_master_key(self, master_key: [u8; 32]) -> FileKeyStore {
        FileKeyStore {
            base_path: self.base_path,
            master_key: Arc::new(master_key),
        }
    }
}

impl KeyStore for FileKeyStore {
    /// Generate a new key
    fn generate_key(&self, size_bits: u32, namespace: &str, version: u32) -> KeyResult {
        let key_size_bytes = (size_bits / 8) as usize;
        let path = self.key_path(namespace, version);
        let master_key = self.master_key.clone();

        let (tx, rx) = tokio::sync::oneshot::channel();
        
        tokio::spawn(async move {
            let result = async move {
                let (key_material, encrypted_data) =
                    tokio::task::spawn_blocking(move || -> Result<(Vec<u8>, Vec<u8>)> {
                        use rand::RngCore;

                        // Generate random key material
                        let mut key_material = Zeroizing::new(vec![0u8; key_size_bytes]);
                        rand::rng().fill_bytes(&mut key_material);

                        // Generate random nonce
                        let mut nonce = vec![0u8; 12];
                        rand::rng().fill_bytes(&mut nonce);
                        let nonce_array = GenericArray::from_slice(&nonce);

                        // Create cipher with master key
                        let cipher = Aes256Gcm::new_from_slice(master_key.as_ref())
                            .map_err(|e| KeyError::InvalidKey(format!("Invalid master key: {}", e)))?;

                        // Encrypt key material
                        let ciphertext = cipher
                            .encrypt(nonce_array, key_material.as_ref())
                            .map_err(|_| KeyError::EncryptionFailed("Key encryption failed".into()))?;

                        // Combine nonce + ciphertext
                        let mut encrypted_data = nonce;
                        encrypted_data.extend_from_slice(&ciphertext);

                        Ok((key_material.to_vec(), encrypted_data))
                    })
                    .await
                    .map_err(|e| KeyError::internal(format!("Key generation task failed: {}", e)))??;

                // Ensure directory exists
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent)
                        .await
                        .map_err(|e| KeyError::Io(format!("Failed to create directory: {}", e)))?;
                }

                // Write encrypted data to file
                fs::write(&path, &encrypted_data)
                    .await
                    .map_err(|e| KeyError::Io(format!("Failed to write key file: {}", e)))?;

                Ok(key_material)
            }.await;
            
            let _ = tx.send(result);
        });
        
        KeyResult::new(rx)
    }
    
    /// Retrieve an existing key
    fn retrieve_key(&self, namespace: &str, version: u32) -> KeyResult {
        let path = self.key_path(namespace, version);
        let master_key = self.master_key.clone();

        let (tx, rx) = tokio::sync::oneshot::channel();
        
        tokio::spawn(async move {
            let result = async move {
                // Read encrypted data
                let mut file = fs::File::open(&path)
                    .await
                    .map_err(|e| KeyError::Io(format!("Key not found: {}", e)))?;

                let mut encrypted_data = Zeroizing::new(Vec::new());
                file.read_to_end(&mut encrypted_data)
                    .await
                    .map_err(|e| KeyError::Io(format!("Failed to read key: {}", e)))?;

                tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                    // Validate minimum size (12 bytes nonce + at least 16 bytes ciphertext)
                    if encrypted_data.len() < 28 {
                        return Err(KeyError::DecryptionFailed(
                            "Invalid encrypted key format".into(),
                        ));
                    }

                    // Extract nonce and ciphertext
                    let nonce = &encrypted_data[..12];
                    let ciphertext = &encrypted_data[12..];
                    let nonce_array = GenericArray::from_slice(nonce);

                    // Create cipher with master key
                    let cipher = Aes256Gcm::new_from_slice(master_key.as_ref())
                        .map_err(|e| KeyError::InvalidKey(format!("Invalid master key: {}", e)))?;

                    // Decrypt key material
                    let decrypted = cipher
                        .decrypt(nonce_array, ciphertext)
                        .map_err(|_| KeyError::DecryptionFailed("Key decryption failed".into()))?;

                    Ok(decrypted)
                })
                .await
                .map_err(|e| KeyError::internal(format!("Decryption task failed: {}", e)))?
            }.await;
            
            let _ = tx.send(result);
        });
        
        KeyResult::new(rx)
    }
}

