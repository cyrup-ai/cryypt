//! Cipher Chunk Type
//!
//! Chunk type for cipher operations (AES, `ChaCha20` encrypt/decrypt)

use cyrup_sugars::prelude::*;

/// Chunk type for cipher operations (AES, `ChaCha20` encrypt/decrypt)
#[derive(Debug, Clone)]
pub struct CipherChunk {
    pub data: Vec<u8>,
    pub operation: String, // "encrypt" | "decrypt"
    pub algorithm: String, // "AES" | "ChaCha20"
    pub metadata: Option<String>,
    error: Option<String>,
}

impl CipherChunk {
    /// Create a new successful cipher chunk
    #[must_use]
    pub fn new(data: Vec<u8>, operation: String, algorithm: String) -> Self {
        CipherChunk {
            data,
            operation,
            algorithm,
            metadata: None,
            error: None,
        }
    }

    /// Add metadata to the chunk
    #[must_use]
    pub fn with_metadata(mut self, metadata: String) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

impl MessageChunk for CipherChunk {
    fn bad_chunk(error: String) -> Self {
        CipherChunk {
            data: vec![],
            operation: "error".to_string(),
            algorithm: "error".to_string(),
            metadata: Some("error_chunk".to_string()),
            error: Some(error),
        }
    }

    fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}
