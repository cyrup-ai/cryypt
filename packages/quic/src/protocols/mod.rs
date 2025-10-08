//! High-level protocol builders for QUIC transport
//!
//! These builders provide domain-specific APIs that hide all the low-level QUIC complexity.
//! Instead of managing streams, chunks, and protocol messages manually, users work with
//! intuitive operations like "upload file", "send message", "call method".

pub mod file_transfer;
pub mod messaging;
pub mod rpc;

pub use file_transfer::{FileTransferProgress, QuicFileTransfer, TransferResult};
pub use messaging::{MessageDelivery, QuicMessaging};
