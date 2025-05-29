//! File-based key storage implementation

use crate::key::{
    KeyStorage, KeyRetrieval, KeyImport, KeyGeneration, KeyEnumeration, 
    KeyId, AsyncStoreResult, AsyncRetrieveResult, AsyncGenerateResult, AsyncListResult
};
use crate::{Result, CryptError};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::future::Future;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        let safe_id = key_id.full_id()
            .replace('/', "_")
            .replace(':', "_");
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
        async move {
            Ok(path.exists())
        }
    }
    
    fn delete(&self, key_id: &dyn KeyId) -> impl Future<Output = Result<()>> + Send {
        let path = self.key_path(key_id);
        async move {
            fs::remove_file(&path).await
                .map_err(|e| CryptError::Io(format!("Failed to delete key: {}", e)))?;
            Ok(())
        }
    }
}

impl KeyImport for FileKeyStore {
    fn store(&self, key_id: &dyn KeyId, key_material: &[u8]) -> impl AsyncStoreResult {
        let path = self.key_path(key_id);
        let master_key = self.master_key.clone();
        let key_data = key_material.to_vec();
        
        async move {
            // Ensure directory exists
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).await
                    .map_err(|e| CryptError::Io(format!("Failed to create directory: {}", e)))?;
            }
            
            // Encrypt the key inline (simple XOR for now)
            let mut encrypted = key_data;
            for (i, byte) in encrypted.iter_mut().enumerate() {
                *byte ^= master_key[i % 32];
            }
            
            // Write to file
            let mut file = fs::File::create(&path).await
                .map_err(|e| CryptError::Io(format!("Failed to create key file: {}", e)))?;
            
            file.write_all(&encrypted).await
                .map_err(|e| CryptError::Io(format!("Failed to write key: {}", e)))?;
            
            file.sync_all().await
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
            // Read encrypted key
            let mut file = fs::File::open(&path).await
                .map_err(|e| CryptError::Io(format!("Key not found: {}", e)))?;
            
            let mut encrypted = Vec::new();
            file.read_to_end(&mut encrypted).await
                .map_err(|e| CryptError::Io(format!("Failed to read key: {}", e)))?;
            
            // Decrypt inline (simple XOR for now)
            let mut decrypted = encrypted;
            for (i, byte) in decrypted.iter_mut().enumerate() {
                *byte ^= master_key[i % 32];
            }
            
            Ok(decrypted)
        }
    }
}

impl KeyGeneration for FileKeyStore {
    fn generate(&self, key_id: &dyn KeyId, key_size_bytes: usize) -> impl AsyncGenerateResult {
        let path = self.key_path(key_id);
        let master_key = self.master_key.clone();
        
        async move {
            use rand::RngCore;
            
            // Generate random key material
            let mut key_material = vec![0u8; key_size_bytes];
            rand::thread_rng().fill_bytes(&mut key_material);
            
            // Encrypt and store the key
            // TODO: Implement encryption with master key
            let encrypted = key_material.clone(); // For now, store unencrypted
            
            fs::write(&path, &encrypted).await
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
            let mut entries = fs::read_dir(&base_path).await
                .map_err(|e| CryptError::Io(format!("Failed to read directory: {}", e)))?;
            
            let mut keys = Vec::new();
            while let Some(entry) = entries.next_entry().await
                .map_err(|e| CryptError::Io(format!("Failed to read entry: {}", e)))? {
                
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