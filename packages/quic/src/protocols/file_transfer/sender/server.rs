//! Running file transfer server implementation

use super::super::FileTransferProgress;
use super::server_builder::FileTransferServerBuilder;
use crate::error::Result;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use uuid::Uuid;

/// Running file transfer server
pub struct FileTransferServer {
    pub(super) config: FileTransferServerBuilder,
    pub(super) storage_dir: PathBuf,
    pub(super) active_transfers: Arc<RwLock<std::collections::HashMap<Uuid, FileTransferProgress>>>,
    pub(super) semaphore: Arc<Semaphore>,
}

impl FileTransferServer {
    /// Get current transfer statistics
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Failed to acquire read lock on active transfers
    pub async fn get_transfer_stats(&self) -> Result<Vec<FileTransferProgress>> {
        // Use the active transfers to return stats
        let transfers = self.active_transfers.read().await;
        Ok(transfers.values().cloned().collect())
    }

    /// Get storage directory
    #[must_use]
    pub fn storage_dir(&self) -> &Path {
        &self.storage_dir
    }

    /// Get server configuration
    #[must_use]
    pub fn config(&self) -> &FileTransferServerBuilder {
        &self.config
    }

    /// Check if server can accept more transfers
    #[must_use]
    pub fn can_accept_transfer(&self) -> bool {
        self.semaphore.available_permits() > 0
    }
}
