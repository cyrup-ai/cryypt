//! Compression result type with metadata and encoding support

/// Result of a compression operation with metadata and encoding options
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompressionResult {
    /// Compressed data bytes
    bytes: Vec<u8>,
    /// Original size before compression (if known)
    original_size: Option<usize>,
    /// Compression algorithm used
    algorithm: CompressionAlgorithm,
}

/// Compression algorithm identifier
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    Zstd {
        level: Option<i32>,
    },
    Gzip {
        level: Option<u32>,
    },
    Bzip2 {
        level: Option<u32>,
    },
    Zip {
        level: Option<u32>,
        files_count: usize,
    },
}

impl CompressionResult {
    /// Create a new compression result from raw bytes
    #[must_use]
    pub fn new(bytes: Vec<u8>, algorithm: CompressionAlgorithm) -> Self {
        Self {
            bytes,
            original_size: None,
            algorithm,
        }
    }

    /// Create a new compression result with original size metadata
    #[must_use]
    pub fn with_original_size(
        bytes: Vec<u8>,
        algorithm: CompressionAlgorithm,
        original_size: usize,
    ) -> Self {
        Self {
            bytes,
            original_size: Some(original_size),
            algorithm,
        }
    }

    /// Get the raw bytes of the compressed data
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Convert to a Vec<u8>
    #[must_use]
    pub fn to_vec(self) -> Vec<u8> {
        self.bytes
    }

    /// Get the compressed data as a hexadecimal string
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Get the compressed data as a base64 string
    #[must_use]
    pub fn to_base64(&self) -> String {
        use base64::{Engine as _, engine::general_purpose};
        general_purpose::STANDARD.encode(&self.bytes)
    }

    /// Get the compressed data as a base64url string (URL-safe)
    #[must_use]
    pub fn to_base64url(&self) -> String {
        base64_url::encode(&self.bytes)
    }

    /// Get the length of the compressed data in bytes
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the compressed data is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Get the compression algorithm used
    #[must_use]
    pub fn algorithm(&self) -> &CompressionAlgorithm {
        &self.algorithm
    }

    /// Get the compression ratio (compressed size / original size)
    /// Returns None if original size is unknown
    #[must_use]
    pub fn compression_ratio(&self) -> Option<f64> {
        self.original_size.map(|original| {
            if original == 0 {
                0.0
            } else {
                // Handle potential precision loss explicitly for large values
                let bytes_len = self.bytes.len();

                // For most practical cases, this conversion is safe
                // but we document the potential precision loss for very large values
                #[allow(clippy::cast_precision_loss)]
                let bytes_len_f64 = bytes_len as f64;
                #[allow(clippy::cast_precision_loss)]
                let original_f64 = original as f64;

                bytes_len_f64 / original_f64
            }
        })
    }

    /// Get the space saved as a percentage (1 - `compression_ratio`) * 100
    /// Returns None if original size is unknown
    #[must_use]
    pub fn space_saved_percent(&self) -> Option<f64> {
        self.compression_ratio().map(|ratio| (1.0 - ratio) * 100.0)
    }

    /// Get the original size before compression (if known)
    #[must_use]
    pub fn original_size(&self) -> Option<usize> {
        self.original_size
    }

    /// Get the compressed size
    #[must_use]
    pub fn compressed_size(&self) -> usize {
        self.bytes.len()
    }
}

impl From<Vec<u8>> for CompressionResult {
    fn from(bytes: Vec<u8>) -> Self {
        // Default to Zstd when creating from raw bytes
        Self::new(bytes, CompressionAlgorithm::Zstd { level: None })
    }
}

impl From<CompressionResult> for Vec<u8> {
    fn from(result: CompressionResult) -> Self {
        result.bytes
    }
}

impl AsRef<[u8]> for CompressionResult {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Display for CompressionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl std::fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompressionAlgorithm::Zstd { level } => {
                if let Some(level) = level {
                    write!(f, "Zstd(level={level})")
                } else {
                    write!(f, "Zstd")
                }
            }
            CompressionAlgorithm::Gzip { level } => {
                if let Some(level) = level {
                    write!(f, "Gzip(level={level})")
                } else {
                    write!(f, "Gzip")
                }
            }
            CompressionAlgorithm::Bzip2 { level } => {
                if let Some(level) = level {
                    write!(f, "Bzip2(level={level})")
                } else {
                    write!(f, "Bzip2")
                }
            }
            CompressionAlgorithm::Zip { level, files_count } => {
                if let Some(level) = level {
                    write!(f, "ZIP(level={level}, files={files_count})")
                } else {
                    write!(f, "ZIP(files={files_count})")
                }
            }
        }
    }
}
