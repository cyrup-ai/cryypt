//! High-level file transfer protocol over QUIC
//!
//! This builder completely abstracts away QUIC complexity and provides a simple,
//! production-ready file transfer API with built-in features like resume,
//! integrity verification, compression, and progress tracking.

use serde::{Deserialize, Serialize};
use std::time::Duration;
use uuid::Uuid;

// Declare submodules
pub mod sender;
pub mod receiver;

/// Progress information for file transfers
#[derive(Debug, Clone)]
pub struct FileTransferProgress {
    pub file_id: Uuid,
    pub filename: String,
    pub bytes_transferred: u64,
    pub total_bytes: u64,
    pub throughput_mbps: f64,
    pub eta_seconds: Option<u64>,
}

/// Result of a completed file transfer
#[derive(Debug)]
pub struct TransferResult {
    pub file_id: Uuid,
    pub filename: String,
    pub bytes_transferred: u64,
    pub duration: Duration,
    pub checksum: String,
    pub success: bool,
}

/// Internal protocol messages (hidden from users)
#[derive(Debug, Serialize, Deserialize)]
enum FileTransferMessage {
    UploadRequest {
        file_id: Uuid,
        filename: String,
        size: u64,
        checksum: String,
        compressed: bool,
        resume_offset: Option<u64>,
    },
    UploadResponse {
        file_id: Uuid,
        accepted: bool,
        resume_offset: u64,
        reason: Option<String>,
    },
    DataChunk {
        file_id: Uuid,
        offset: u64,
        data: Vec<u8>,
        is_final: bool,
    },
    TransferComplete {
        file_id: Uuid,
        checksum: String,
        success: bool,
    },
    ListRequest,
    ListResponse {
        files: Vec<FileMetadata>,
    },
    DownloadRequest {
        filename: String,
        offset: u64,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileMetadata {
    pub filename: String,
    pub size: u64,
    pub checksum: String,
    pub upload_time: String,
    pub compressed: bool,
}

/// High-level file transfer builder - completely hides QUIC complexity
pub struct QuicFileTransfer;

impl QuicFileTransfer {
    /// Start building a file transfer server
    pub fn server() -> sender::FileTransferServerBuilder {
        sender::FileTransferServerBuilder::default()
    }

    /// Start building a file transfer client connection
    pub fn connect(server_addr: &str) -> receiver::FileTransferClientBuilder {
        receiver::FileTransferClientBuilder::new(server_addr.to_string())
    }
}

// Re-export types from submodules for convenience
pub use sender::{FileTransferServerBuilder, FileTransferServer, FileUploadBuilder};
pub use receiver::{FileTransferClientBuilder, FileDownloadBuilder};
