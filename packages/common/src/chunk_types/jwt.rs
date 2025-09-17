//! JWT Chunk Type
//!
//! Chunk type for JWT operations (sign, verify)

use cyrup_sugars::prelude::*;

/// Chunk type for JWT operations (sign, verify)
#[derive(Debug, Clone)]
pub struct JwtChunk {
    pub token: String,
    pub operation: String,      // "sign" | "verify" | "decode"
    pub algorithm: String,      // "HS256" | "RS256" etc.
    pub claims: Option<String>, // JSON string of claims if available
    pub metadata: Option<String>,
    error: Option<String>,
}

impl JwtChunk {
    /// Create a new successful JWT chunk
    #[must_use]
    pub fn new(token: String, operation: String, algorithm: String) -> Self {
        JwtChunk {
            token,
            operation,
            algorithm,
            claims: None,
            metadata: None,
            error: None,
        }
    }

    /// Add claims data
    #[must_use]
    pub fn with_claims(mut self, claims: String) -> Self {
        self.claims = Some(claims);
        self
    }

    /// Add metadata to the chunk
    #[must_use]
    pub fn with_metadata(mut self, metadata: String) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

impl MessageChunk for JwtChunk {
    fn bad_chunk(error: String) -> Self {
        JwtChunk {
            token: String::new(),
            operation: "error".to_string(),
            algorithm: "error".to_string(),
            claims: None,
            metadata: Some("error_chunk".to_string()),
            error: Some(error),
        }
    }

    fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}
