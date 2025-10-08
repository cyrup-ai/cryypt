//! QUIC Chunk Type
//!
//! Chunk type for QUIC operations (connect, send, receive)

use cyrup_sugars::prelude::*;

/// Chunk type for QUIC operations (connect, send, receive)
#[derive(Debug, Clone)]
pub struct QuicChunk {
    pub data: Vec<u8>,
    pub operation: String, // "connect" | "send" | "receive" | "stream"
    pub stream_id: Option<u64>,
    pub connection_info: Option<String>,
    pub metadata: Option<String>,
    error: Option<String>,
}

impl QuicChunk {
    /// Create a new successful QUIC chunk
    #[must_use]
    pub fn new(data: Vec<u8>, operation: String) -> Self {
        QuicChunk {
            data,
            operation,
            stream_id: None,
            connection_info: None,
            metadata: None,
            error: None,
        }
    }

    /// Add stream ID
    #[must_use]
    pub fn with_stream_id(mut self, stream_id: u64) -> Self {
        self.stream_id = Some(stream_id);
        self
    }

    /// Add connection info
    #[must_use]
    pub fn with_connection_info(mut self, info: String) -> Self {
        self.connection_info = Some(info);
        self
    }

    /// Add metadata to the chunk
    #[must_use]
    pub fn with_metadata(mut self, metadata: String) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

impl MessageChunk for QuicChunk {
    fn bad_chunk(error: String) -> Self {
        QuicChunk {
            data: vec![],
            operation: "error".to_string(),
            stream_id: None,
            connection_info: None,
            metadata: Some("error_chunk".to_string()),
            error: Some(error),
        }
    }

    fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}
