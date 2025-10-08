//! Vault Chunk Type
//!
//! Chunk type for vault operations (store, retrieve, list, delete)

use cyrup_sugars::prelude::*;

/// Chunk type for vault operations (store, retrieve, list, delete)
#[derive(Debug, Clone)]
pub struct VaultChunk {
    pub data: Vec<u8>,
    pub operation: String, // "store" | "retrieve" | "list" | "delete"
    pub key_id: String,    // The vault key identifier
    pub metadata: Option<String>,
    error: Option<String>,
}

impl VaultChunk {
    /// Create a new successful vault chunk
    #[must_use]
    pub fn new(data: Vec<u8>, operation: String, key_id: String) -> Self {
        VaultChunk {
            data,
            operation,
            key_id,
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

impl MessageChunk for VaultChunk {
    fn bad_chunk(error: String) -> Self {
        VaultChunk {
            data: vec![],
            operation: "error".to_string(),
            key_id: "error".to_string(),
            metadata: Some("error_chunk".to_string()),
            error: Some(error),
        }
    }

    fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}
