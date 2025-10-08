//! Storage Trait Implementations
//!
//! This module provides implementations of storage traits for file-based key storage,
//! including key import, retrieval, generation, and enumeration operations.

use super::core::FileKeyStore;
use super::encryption::{decrypt_key_material, encrypt_key_material};
use crate::api::KeyStore;
use crate::{KeyError, KeyResult};
use tokio::fs;
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

impl KeyStore for FileKeyStore {
    /// Generate a new key
    fn generate_key(&self, size_bits: u32, namespace: &str, version: u32) -> KeyResult {
        let key_size_bytes = (size_bits / 8) as usize;
        let path = self.key_path(namespace, version);
        let master_key = self.master_key.clone();

        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let result = async move {
                // Direct async implementation - RNG and encryption are fast, no blocking needed
                let (key_material, encrypted_data) = {
                    use rand::RngCore;

                    // Generate random key material
                    let mut key_material = Zeroizing::new(vec![0u8; key_size_bytes]);
                    rand::rng().fill_bytes(&mut key_material);

                    // Encrypt the key material
                    let encrypted_data = encrypt_key_material(&key_material, &master_key)?;

                    (key_material.to_vec(), encrypted_data)
                };

                // Ensure directory exists
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).await.map_err(KeyError::Io)?;
                }

                // Write encrypted data to file
                fs::write(&path, &encrypted_data)
                    .await
                    .map_err(KeyError::Io)?;

                Ok(key_material)
            }
            .await;

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
                let mut file = fs::File::open(&path).await.map_err(KeyError::Io)?;

                let mut encrypted_data = Zeroizing::new(Vec::new());
                file.read_to_end(&mut encrypted_data)
                    .await
                    .map_err(KeyError::Io)?;

                // Direct async implementation - decryption is fast, no blocking needed
                decrypt_key_material(&encrypted_data, &master_key)
            }
            .await;

            let _ = tx.send(result);
        });

        KeyResult::new(rx)
    }
}

impl FileKeyStore {
    /// Import a key with the given material
    #[must_use]
    pub fn import_key(&self, key_material: &[u8], namespace: &str, version: u32) -> KeyResult {
        let path = self.key_path(namespace, version);
        let master_key = self.master_key.clone();
        let key_data = key_material.to_vec();

        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let result = async move {
                let key_data_for_encryption = key_data.clone();
                // Direct async implementation - encryption is fast, no blocking needed
                let encrypted_data = encrypt_key_material(&key_data_for_encryption, &master_key)?;

                // Ensure directory exists
                if let Some(parent) = path.parent() {
                    fs::create_dir_all(parent).await.map_err(KeyError::Io)?;
                }

                // Write encrypted data to file
                fs::write(&path, &encrypted_data)
                    .await
                    .map_err(KeyError::Io)?;

                Ok(key_data)
            }
            .await;

            let _ = tx.send(result);
        });

        KeyResult::new(rx)
    }

    /// List all available keys in the store
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The base directory cannot be read (permissions, doesn't exist, etc.)
    /// - File system I/O operations fail during directory traversal
    /// - Key file names cannot be parsed to extract namespace and version
    pub fn list_keys(&self) -> Result<Vec<(String, u32)>, KeyError> {
        use std::fs;

        let mut keys = Vec::new();

        // Read directory entries
        let entries = fs::read_dir(&self.base_path).map_err(KeyError::Io)?;

        for entry in entries {
            let entry = entry.map_err(KeyError::Io)?;

            let path = entry.path();
            if let Some(filename) = path.file_name().and_then(|n| n.to_str())
                && let Some(name_part) = filename.strip_suffix(".key")
            {
                // Remove .key extension
                if let Some(last_underscore) = name_part.rfind('_') {
                    let namespace = name_part[..last_underscore].replace('_', "/");
                    if let Ok(version) = name_part[last_underscore + 1..].parse::<u32>() {
                        keys.push((namespace, version));
                    }
                }
            }
        }

        Ok(keys)
    }
}
