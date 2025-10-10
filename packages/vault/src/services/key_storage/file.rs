//! File-based key storage for PQCrypto keys

use super::KeyStorage;
use crate::error::{VaultError, VaultResult};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct FileStorage {
    base_dir: PathBuf,
}

impl FileStorage {
    pub fn new(base_dir: impl Into<PathBuf>) -> Self {
        Self { base_dir: base_dir.into() }
    }

    fn key_path(&self, namespace: &str, version: u32) -> PathBuf {
        self.base_dir.join(format!("{}_v{}.key", namespace, version))
    }
}

impl KeyStorage for FileStorage {
    async fn store(&self, namespace: &str, version: u32, keypair: &[u8]) -> VaultResult<()> {
        let path = self.key_path(namespace, version);
        
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| VaultError::Provider(format!("Failed to create key dir: {}", e)))?;
        }

        tokio::fs::write(&path, keypair).await
            .map_err(|e| VaultError::Provider(format!("Failed to write key: {}", e)))?;

        log::debug!("Stored key to file: {}", path.display());
        Ok(())
    }

    async fn retrieve(&self, namespace: &str, version: u32) -> VaultResult<Vec<u8>> {
        let path = self.key_path(namespace, version);
        
        tokio::fs::read(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                VaultError::ItemNotFound
            } else {
                VaultError::Provider(format!("Failed to read key: {}", e))
            }
        })
    }

    async fn delete(&self, namespace: &str, version: u32) -> VaultResult<()> {
        let path = self.key_path(namespace, version);
        tokio::fs::remove_file(&path).await
            .map_err(|e| VaultError::Provider(format!("Failed to delete key: {}", e)))
    }

    async fn list_versions(&self, namespace: &str) -> VaultResult<Vec<u32>> {
        let mut versions = Vec::new();
        let mut entries = tokio::fs::read_dir(&self.base_dir).await
            .map_err(|e| VaultError::Provider(format!("Failed to read dir: {}", e)))?;

        let prefix = format!("{}_v", namespace);
        while let Some(entry) = entries.next_entry().await
            .map_err(|e| VaultError::Provider(format!("Failed to read entry: {}", e)))? {
            
            if let Some(name) = entry.file_name().to_str() {
                if name.starts_with(&prefix) && name.ends_with(".key") {
                    if let Some(v) = name.strip_prefix(&prefix)
                        .and_then(|s| s.strip_suffix(".key"))
                        .and_then(|s| s.parse::<u32>().ok()) {
                        versions.push(v);
                    }
                }
            }
        }

        versions.sort_unstable();
        Ok(versions)
    }
}
