//! Compression Chunk Type
//!
//! Chunk type for compression operations (Gzip, Bzip2, Zstd, Zip)

use cyrup_sugars::prelude::*;

/// Chunk type for compression operations (Gzip, Bzip2, Zstd, Zip)
#[derive(Debug, Clone)]
pub struct CompressionChunk {
    pub data: Vec<u8>,
    pub operation: String,  // "compress" | "decompress"
    pub algorithm: String,  // "Gzip" | "Bzip2" | "Zstd" | "Zip"
    pub ratio: Option<f64>, // Compression ratio if available
    pub metadata: Option<String>,
    error: Option<String>,
}

impl CompressionChunk {
    /// Create a new successful compression chunk
    #[must_use]
    pub fn new(data: Vec<u8>, operation: String, algorithm: String) -> Self {
        CompressionChunk {
            data,
            operation,
            algorithm,
            ratio: None,
            metadata: None,
            error: None,
        }
    }

    /// Add compression ratio
    #[must_use]
    pub fn with_ratio(mut self, ratio: f64) -> Self {
        self.ratio = Some(ratio);
        self
    }

    /// Add metadata to the chunk
    #[must_use]
    pub fn with_metadata(mut self, metadata: String) -> Self {
        self.metadata = Some(metadata);
        self
    }
}

impl MessageChunk for CompressionChunk {
    fn bad_chunk(error: String) -> Self {
        CompressionChunk {
            data: vec![],
            operation: "error".to_string(),
            algorithm: "error".to_string(),
            ratio: None,
            metadata: Some("error_chunk".to_string()),
            error: Some(error),
        }
    }

    fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }
}
