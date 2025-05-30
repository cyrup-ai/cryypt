//! File-based key storage implementation

use crate::key::{
    AsyncGenerateResult, AsyncListResult, AsyncRetrieveResult, AsyncStoreResult, KeyEnumeration,
    KeyGeneration, KeyId, KeyImport, KeyRetrieval, KeyStorage,
};
use crate::{CryptError, Result};
use aes_gcm::{aead::{Aead, KeyInit, generic_array::GenericArray}, Aes256Gcm};
use rand::RngCore;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

    /// Derive a file path from a key ID
    fn key_path(&self, key_id: &dyn KeyId) -> PathBuf {
        let safe_id = key_id.full_id().replace('/', "_").replace(':', "_");
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

impl KeyStorage for FileKeyStore {
    fn exists(&self, key_id: &dyn KeyId) -> impl Future<Output = Result<bool>> + Send {
        let path = self.key_path(key_id);
        async move { Ok(path.exists()) }
    }

    fn delete(&self, key_id: &dyn KeyId) -> impl Future<Output = Result<()>> + Send {
        let path = self.key_path(key_id);
        async move {
            fs::remove_file(&path)
                .await
                .map_err(|e| CryptError::Io(format!("Failed to delete key: {}", e)))?;
            Ok(())
        }
    }
}

impl KeyImport for FileKeyStore {
    fn store(&self, key_id: &dyn KeyId, key_material: &[u8]) -> impl AsyncStoreResult {
        let path = self.key_path(key_id);
        let master_key = self.master_key.clone();
        let key_data = Zeroizing::new(key_material.to_vec());

        async move {
            let result = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                // Generate random nonce
                let mut nonce = vec![0u8; 12];
                rand::rng().fill_bytes(&mut nonce);
                let nonce_array = GenericArray::from_slice(&nonce);

                // Create cipher with master key
                let cipher = Aes256Gcm::new_from_slice(master_key.as_ref())
                    .map_err(|e| CryptError::InvalidKey(format!("Invalid master key: {}", e)))?;

                // Encrypt key material
                let ciphertext = cipher
                    .encrypt(nonce_array, key_data.as_ref())
                    .map_err(|_| CryptError::EncryptionFailed("Key encryption failed".into()))?;

                // Combine nonce + ciphertext
                let mut encrypted_data = nonce;
                encrypted_data.extend_from_slice(&ciphertext);
                
                Ok(encrypted_data)
            }).await
            .map_err(|e| CryptError::internal(format!("Encryption task failed: {}", e)))??;

            // Ensure directory exists
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .await
                    .map_err(|e| CryptError::Io(format!("Failed to create directory: {}", e)))?;
            }

            // Write encrypted data to file
            let mut file = fs::File::create(&path)
                .await
                .map_err(|e| CryptError::Io(format!("Failed to create key file: {}", e)))?;

            file.write_all(&result)
                .await
                .map_err(|e| CryptError::Io(format!("Failed to write key: {}", e)))?;

            file.sync_all()
                .await
                .map_err(|e| CryptError::Io(format!("Failed to sync key file: {}", e)))?;

            Ok(())
        }
    }
}

impl KeyRetrieval for FileKeyStore {
    fn retrieve(&self, key_id: &dyn KeyId) -> impl AsyncRetrieveResult {
        let path = self.key_path(key_id);
        let master_key = self.master_key.clone();

        async move {
            // Read encrypted data
            let mut file = fs::File::open(&path)
                .await
                .map_err(|e| CryptError::Io(format!("Key not found: {}", e)))?;

            let mut encrypted_data = Zeroizing::new(Vec::new());
            file.read_to_end(&mut encrypted_data)
                .await
                .map_err(|e| CryptError::Io(format!("Failed to read key: {}", e)))?;

            tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                // Validate minimum size (12 bytes nonce + at least 16 bytes ciphertext)
                if encrypted_data.len() < 28 {
                    return Err(CryptError::DecryptionFailed("Invalid encrypted key format".into()));
                }

                // Extract nonce and ciphertext
                let nonce = &encrypted_data[..12];
                let ciphertext = &encrypted_data[12..];
                let nonce_array = GenericArray::from_slice(nonce);

                // Create cipher with master key
                let cipher = Aes256Gcm::new_from_slice(master_key.as_ref())
                    .map_err(|e| CryptError::InvalidKey(format!("Invalid master key: {}", e)))?;

                // Decrypt key material
                let decrypted = cipher
                    .decrypt(nonce_array, ciphertext)
                    .map_err(|_| CryptError::DecryptionFailed("Key decryption failed".into()))?;

                Ok(decrypted)
            }).await
            .map_err(|e| CryptError::internal(format!("Decryption task failed: {}", e)))?
        }
    }
}

impl KeyGeneration for FileKeyStore {
    fn generate(&self, key_id: &dyn KeyId, key_size_bytes: usize) -> impl AsyncGenerateResult {
        let path = self.key_path(key_id);
        let master_key = self.master_key.clone();

        async move {
            let (key_material, encrypted_data) = tokio::task::spawn_blocking(move || -> Result<(Vec<u8>, Vec<u8>)> {
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
                    .map_err(|e| CryptError::InvalidKey(format!("Invalid master key: {}", e)))?;

                // Encrypt key material
                let ciphertext = cipher
                    .encrypt(nonce_array, key_material.as_ref())
                    .map_err(|_| CryptError::EncryptionFailed("Key encryption failed".into()))?;

                // Combine nonce + ciphertext
                let mut encrypted_data = nonce;
                encrypted_data.extend_from_slice(&ciphertext);

                Ok((key_material.to_vec(), encrypted_data))
            }).await
            .map_err(|e| CryptError::internal(format!("Key generation task failed: {}", e)))??;

            // Ensure directory exists
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .await
                    .map_err(|e| CryptError::Io(format!("Failed to create directory: {}", e)))?;
            }

            // Write encrypted data to file
            fs::write(&path, &encrypted_data)
                .await
                .map_err(|e| CryptError::Io(format!("Failed to write key file: {}", e)))?;

            Ok(key_material)
        }
    }
}

impl KeyEnumeration for FileKeyStore {
    fn list(&self, namespace_pattern: &str) -> impl AsyncListResult {
        let base_path = self.base_path.clone();
        let pattern = namespace_pattern.to_string();

        async move {
            let mut entries = fs::read_dir(&base_path)
                .await
                .map_err(|e| CryptError::Io(format!("Failed to read directory: {}", e)))?;

            let mut keys = Vec::new();
            while let Some(entry) = entries
                .next_entry()
                .await
                .map_err(|e| CryptError::Io(format!("Failed to read entry: {}", e)))?
            {
                if let Some(name) = entry.file_name().to_str() {
                    if name.ends_with(".key") && name.contains(&pattern) {
                        keys.push(name.trim_end_matches(".key").to_string());
                    }
                }
            }

            Ok(keys)
        }
    }
}
