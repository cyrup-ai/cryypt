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

    fn key_path(&self, key_id: &str) -> PathBuf {
        // Sanitize key_id for filesystem (replace : with _)
        let safe_name = key_id.replace(':', "_");
        self.base_dir.join(format!("{}.key", safe_name))
    }
}

impl KeyStorage for FileStorage {
    async fn store(&self, key_id: &str, keypair: &[u8]) -> VaultResult<()> {
        let path = self.key_path(key_id);

        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| VaultError::Provider(format!("Failed to create key dir: {}", e)))?;
        }

        tokio::fs::write(&path, keypair).await
            .map_err(|e| VaultError::Provider(format!("Failed to write key: {}", e)))?;

        log::debug!("Stored key to file: {}", path.display());
        Ok(())
    }

    async fn retrieve(&self, key_id: &str) -> VaultResult<Vec<u8>> {
        let path = self.key_path(key_id);

        tokio::fs::read(&path).await.map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                VaultError::ItemNotFound
            } else {
                VaultError::Provider(format!("Failed to read key: {}", e))
            }
        })
    }

    async fn delete(&self, key_id: &str) -> VaultResult<()> {
        let path = self.key_path(key_id);
        tokio::fs::remove_file(&path).await
            .map_err(|e| VaultError::Provider(format!("Failed to delete key: {}", e)))
    }
}
