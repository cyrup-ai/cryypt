//! Builder pattern implementation for file transfer operations

use std::net::SocketAddr;
use super::types::{FileOperation, FileProgress, FileTransferResult};

/// Builder for file transfer operations
pub struct FileTransferBuilder {
    pub(crate) operation: FileOperation,
    pub(crate) path: String,
    pub(crate) addr: SocketAddr,
    pub(crate) compressed: bool,
    pub(crate) progress_handler: Option<Box<dyn Fn(FileProgress) + Send + Sync>>,
}

impl FileTransferBuilder {
    pub(crate) fn upload(path: String, addr: SocketAddr) -> Self {
        Self {
            operation: FileOperation::Upload,
            path,
            addr,
            compressed: false,
            progress_handler: None,
        }
    }

    pub(crate) fn download(path: String, addr: SocketAddr) -> Self {
        Self {
            operation: FileOperation::Download,
            path,
            addr,
            compressed: false,
            progress_handler: None,
        }
    }

    /// Enable compression
    pub fn compressed(mut self) -> Self {
        self.compressed = true;
        self
    }

    /// Set progress callback
    pub fn with_progress<F>(mut self, handler: F) -> Self
    where
        F: Fn(FileProgress) + Send + Sync + 'static,
    {
        self.progress_handler = Some(Box::new(handler));
        self
    }
}

impl std::future::Future for FileTransferBuilder {
    type Output = FileTransferResult;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // Log operation details
        match self.operation {
            FileOperation::Upload => {
                println!(
                    "📤 Uploading {} to {} (compressed: {})",
                    self.path, self.addr, self.compressed
                );
            }
            FileOperation::Download => {
                println!(
                    "📥 Downloading {} from {} (compressed: {})",
                    self.path, self.addr, self.compressed
                );
            }
        }

        // Simulate progress callbacks
        if let Some(ref handler) = self.progress_handler {
            handler(FileProgress {
                percent: 100.0,
                bytes_transferred: 1024,
                total_bytes: 1024,
                mbps: 8.0,
            });
        }

        // Implement actual file transfer over QUIC
        let result = match self.operation {
            FileOperation::Upload => super::upload::execute_upload(self),
            FileOperation::Download => super::download::execute_download(self),
        };
        std::task::Poll::Ready(result)
    }
}