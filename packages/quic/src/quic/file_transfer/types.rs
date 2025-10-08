//! Core types and structures for file transfer protocol

use std::net::SocketAddr;
use std::time::Duration;

/// File transfer protocol over QUIC stream
pub struct FileTransferProtocol {
    addr: SocketAddr,
}

impl FileTransferProtocol {
    #[must_use]
    pub(crate) fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    /// Upload a file
    #[must_use]
    pub fn upload(&self, path: impl Into<String>) -> crate::quic::file_transfer::UploadConfig {
        crate::quic::file_transfer::FileTransferConfig::upload(path.into(), self.addr)
    }

    /// Download a file
    #[must_use]
    pub fn download(&self, path: impl Into<String>) -> crate::quic::file_transfer::DownloadConfig {
        crate::quic::file_transfer::FileTransferConfig::download(path.into(), self.addr)
    }
}

#[derive(Debug)]
pub enum FileOperation {
    Upload,
    Download,
}

/// Progress information for file transfers
#[derive(Debug, Clone)]
pub struct FileProgress {
    /// Percentage complete (0.0 to 100.0)
    pub percent: f64,
    /// Number of bytes transferred so far
    pub bytes_transferred: u64,
    /// Total number of bytes to transfer
    pub total_bytes: u64,
    /// Current transfer rate in megabits per second
    pub mbps: f64,
}

/// Result of a file transfer operation
#[derive(Debug)]
pub struct FileTransferResult {
    /// Total number of bytes transferred
    pub bytes_transferred: u64,
    /// Time taken for the transfer
    pub duration: Duration,
    /// Whether the transfer completed successfully
    pub success: bool,
}
