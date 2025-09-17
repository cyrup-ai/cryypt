//! Hash Chunk Type
//!
//! Chunk type for hash operations (SHA256, SHA3, Blake2b, etc.)

use cyrup_sugars::prelude::*;

/// Chunk type for hash operations (SHA256, SHA3, Blake2b, etc.)
#[derive(Debug, Clone)]
pub struct HashChunk {
    pub hash: Vec<u8>,
    pub algorithm: String,
    pub metadata: Option<String>,
    error: Option<String>,
}

impl HashChunk {
    /// Create a new successful hash chunk
    #[must_use]
    pub fn new(hash: Vec<u8>, algorithm: String) -> Self {
        HashChunk {
            hash,
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

impl MessageChunk for HashChunk {
    fn bad_chunk(error: String) -> Self {
        HashChunk {
            hash: vec![],
            algorithm: "error".to_string(),
            metadata: Some("error_chunk".to_string()),
            error: Some(error),
        }
    }

    fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}
