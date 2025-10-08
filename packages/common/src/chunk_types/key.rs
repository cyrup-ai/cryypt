//! Key Chunk Type
//!
//! Chunk type for key operations (generate, derive, export)

use cyrup_sugars::prelude::*;

/// Chunk type for key operations (generate, derive, export)
#[derive(Debug, Clone)]
pub struct KeyChunk {
    pub key_data: Vec<u8>, // The key material (may be empty for operations like verify)
    pub operation: String, // "generate" | "derive" | "export" | "import"
    pub key_type: String,  // "AES" | "RSA" | "Ed25519" etc.
    pub metadata: Option<String>,
    error: Option<String>,
}

impl KeyChunk {
    /// Create a new successful key chunk
    #[must_use]
    pub fn new(key_data: Vec<u8>, operation: String, key_type: String) -> Self {
        KeyChunk {
            key_data,
            operation,
            key_type,
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

impl MessageChunk for KeyChunk {
    fn bad_chunk(error: String) -> Self {
        KeyChunk {
            key_data: vec![],
            operation: "error".to_string(),
            key_type: "error".to_string(),
            metadata: Some("error_chunk".to_string()),
            error: Some(error),
        }
    }

    fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}
