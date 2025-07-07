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

// Implement KeyStorage trait family for FileKeyStore
use crate::traits::{KeyStorage, KeyRetrieval, KeyImport, KeyGeneration, KeyEnumeration};
use crate::store_results::*;
use crate::KeyId;

impl KeyStorage for FileKeyStore {
    fn exists(&self, key_id: &dyn KeyId) -> ExistsResult {
        let namespace = key_id.namespace().unwrap_or("default");
        let path = self.base_path.join(format!(
            "{}/{}.key", 
            namespace, 
            key_id.version()
        ));
        
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = Ok(tokio::fs::metadata(&path).await.is_ok());
            let _ = tx.send(result);
        });
        
        ExistsResult::new(rx)
    }
    
    fn delete(&self, key_id: &dyn KeyId) -> DeleteResult {
        let namespace = key_id.namespace().unwrap_or("default");
        let path = self.base_path.join(format!(
            "{}/{}.key", 
            namespace, 
            key_id.version()
        ));
        
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = match tokio::fs::remove_file(&path).await {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    Err(KeyError::internal("Key file not found"))
                }
                Err(e) => Err(KeyError::Io(e.to_string())),
            };
            let _ = tx.send(result);
        });
        
        DeleteResult::new(rx)
    }
}

impl KeyRetrieval for FileKeyStore {
    fn retrieve(&self, key_id: &dyn KeyId) -> RetrieveResult {
        // Use the existing retrieve_key implementation
        let namespace = key_id.namespace().unwrap_or("default");
        let key_result = self.retrieve_key(namespace, key_id.version());
        
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = key_result.await;
            let _ = tx.send(result);
        });
        
        RetrieveResult::new(rx)
    }
}

impl KeyImport for FileKeyStore {
    fn store(&self, key_id: &dyn KeyId, key_material: &[u8]) -> StoreResult {
        let namespace = key_id.namespace().unwrap_or("default");
        let path = self.key_path(namespace, key_id.version());
        let key_data = key_material.to_vec();
        let master_key = self.master_key.clone();
        
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = async move {
                // Ensure directory exists
                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent).await
                        .map_err(|e| KeyError::Io(e.to_string()))?;
                }
                
                let encrypted_data = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                    use rand::RngCore;
                    use aes_gcm::{Aes256Gcm, KeyInit};
                    use aes_gcm::aead::Aead;
                    use aes_gcm::aead::generic_array::GenericArray;
                    
                    // Generate random nonce
                    let mut nonce = vec![0u8; 12];
                    rand::rng().fill_bytes(&mut nonce);
                    let nonce_array = GenericArray::from_slice(&nonce);
                    
                    // Create cipher with master key
                    let cipher = Aes256Gcm::new_from_slice(master_key.as_ref())
                        .map_err(|e| KeyError::InvalidKey(format!("Invalid master key: {}", e)))?;
                    
                    // Encrypt key material
                    let ciphertext = cipher
                        .encrypt(nonce_array, key_data.as_ref())
                        .map_err(|_| KeyError::EncryptionFailed("Key encryption failed".into()))?;
                    
                    // Combine nonce and ciphertext
                    let mut encrypted_data = nonce;
                    encrypted_data.extend_from_slice(&ciphertext);
                    
                    Ok(encrypted_data)
                })
                .await
                .map_err(|e| KeyError::internal(format!("Encryption task failed: {}", e)))??;
                
                // Write encrypted data to file
                tokio::fs::write(&path, encrypted_data).await
                    .map_err(|e| KeyError::Io(e.to_string()))?;
                
                Ok(())
            }.await;
            
            let _ = tx.send(result);
        });
        
        StoreResult::new(rx)
    }
}

impl KeyGeneration for FileKeyStore {
    fn generate(&self, key_id: &dyn KeyId, key_size_bytes: usize) -> RetrieveResult {
        // Use the existing generate_key implementation 
        let key_result = self.generate_key(
            (key_size_bytes * 8) as u32, // Convert bytes to bits
            key_id.namespace().unwrap_or("default"), 
            key_id.version()
        );
        
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = key_result.await;
            let _ = tx.send(result);
        });
        
        RetrieveResult::new(rx)
    }
}

impl KeyEnumeration for FileKeyStore {
    fn list(&self, namespace_pattern: &str) -> ListResult {
        let store_path = self.base_path.clone();
        let pattern = namespace_pattern.to_string();
        
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let result = async move {
                
                let mut key_ids: Vec<String> = Vec::new();
                
                // Read namespace directory
                let namespace_path = store_path.join(&pattern);
                if !namespace_path.exists() {
                    return Ok(key_ids); // Empty result for non-existent namespace
                }
                
                let mut entries = tokio::fs::read_dir(&namespace_path).await
                    .map_err(|e| KeyError::Io(e.to_string()))?;
                
                while let Some(entry) = entries.next_entry().await
                    .map_err(|e| KeyError::Io(e.to_string()))? {
                    
                    let file_name = entry.file_name();
                    let file_name_str = file_name.to_string_lossy();
                    
                    // Parse version from filename (format: "<version>.key")
                    if let Some(version_str) = file_name_str.strip_suffix(".key") {
                        if let Ok(version) = version_str.parse::<u32>() {
                            key_ids.push(format!("{}:{}", pattern, version));
                        }
                    }
                }
                
                Ok(key_ids)
            }.await;
            
            let _ = tx.send(result);
        });
        
        ListResult::new(rx)
    }
}
