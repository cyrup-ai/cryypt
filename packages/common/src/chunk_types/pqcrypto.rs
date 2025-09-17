//! Post-Quantum Cryptography Chunk Type
//!
//! Chunk type for post-quantum cryptography operations (keygen, encap, decap, sign, verify)

use cyrup_sugars::prelude::*;

/// Chunk type for post-quantum cryptography operations (keygen, encap, decap, sign, verify)
#[derive(Debug, Clone)]
pub struct PqCryptoChunk {
    pub data: Vec<u8>,
    pub operation: String, // "keygen" | "encap" | "decap" | "sign" | "verify"
    pub algorithm: String, // "Kyber" | "Dilithium" | "Falcon" | "SPHINCS+"
    pub key_type: Option<String>, // "public" | "private" | "shared_secret"
    pub metadata: Option<String>,
    error: Option<String>,
}

impl PqCryptoChunk {
    /// Create a new successful post-quantum crypto chunk
    #[must_use]
    pub fn new(data: Vec<u8>, operation: String, algorithm: String) -> Self {
        PqCryptoChunk {
            data,
            operation,
            algorithm,
            key_type: None,
            metadata: None,
            error: None,
        }
    }

    /// Add key type
    #[must_use]
    pub fn with_key_type(mut self, key_type: String) -> Self {
        self.key_type = Some(key_type);
        self
    }

    /// Add metadata to the chunk
    #[must_use]
    pub fn with_metadata(mut self, metadata: String) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

impl MessageChunk for PqCryptoChunk {
    fn bad_chunk(error: String) -> Self {
        PqCryptoChunk {
            data: vec![],
            operation: "error".to_string(),
            algorithm: "error".to_string(),
            key_type: None,
            metadata: Some("error_chunk".to_string()),
            error: Some(error),
        }
    }

    fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}
