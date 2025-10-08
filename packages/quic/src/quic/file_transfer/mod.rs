//! File transfer protocol over QUIC stream

pub mod builder;
pub mod download;
pub mod types;
pub mod upload;

// Re-export main public types and structs
pub use builder::{DownloadConfig, FileTransferConfig, UploadConfig};
pub use types::{FileProgress, FileTransferProtocol, FileTransferResult};
