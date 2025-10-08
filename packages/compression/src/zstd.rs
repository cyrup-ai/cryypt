//! Zstd compression implementation

use crate::{CompressionError, Result};

/// Compress data using zstd algorithm
///
/// # Arguments
/// * `data` - The data to compress
/// * `level` - Compression level (1-22, higher is more compression)
///
/// # Errors
/// Returns `CompressionError` if Zstd compression fails
pub fn compress(data: &[u8], level: i32) -> Result<Vec<u8>> {
    zstd::encode_all(data, level)
        .map_err(|e| CompressionError::compression_failed(format!("Zstd compression failed: {e}")))
}

/// Decompress zstd compressed data
///
/// # Arguments
/// * `data` - The compressed data to decompress
///
/// # Errors
/// Returns `CompressionError` if Zstd decompression fails
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    zstd::decode_all(data).map_err(|e| {
        CompressionError::decompression_failed(format!("Zstd decompression failed: {e}"))
    })
}

/// Compress data using zstd with specified compression level
///
/// # Arguments
/// * `data` - The data to compress
/// * `level` - Compression level (1-22, higher is more compression)
///
/// # Errors
/// Returns `CompressionError` if Zstd compression fails
pub fn compress_with_level(data: &[u8], level: i32) -> Result<Vec<u8>> {
    compress(data, level)
}
