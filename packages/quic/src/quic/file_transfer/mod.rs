//! File transfer protocol over QUIC stream

pub mod types;
pub mod builder;
pub mod upload;
pub mod download;

// Re-export main public types and structs
pub use types::{FileTransferProtocol, FileProgress, FileTransferResult};
pub use builder::FileTransferBuilder;