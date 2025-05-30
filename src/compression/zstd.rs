//! Zstd compression implementation

use crate::{CryptError, Result};

/// Compress data using zstd algorithm
/// 
/// # Arguments
/// * `data` - The data to compress
/// * `level` - Compression level (1-22, higher is more compression)
pub fn compress(data: &[u8], level: i32) -> Result<Vec<u8>> {
    zstd::encode_all(data, level)
        .map_err(|e| CryptError::compression(format!("Zstd compression failed: {}", e)))
}

/// Decompress zstd compressed data
/// 
/// # Arguments
/// * `data` - The compressed data to decompress
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    zstd::decode_all(data)
        .map_err(|e| CryptError::decompression(format!("Zstd decompression failed: {}", e)))
}

/// Compress data using zstd with specified compression level
/// 
/// # Arguments
/// * `data` - The data to compress
/// * `level` - Compression level (1-22, higher is more compression)
pub fn compress_with_level(data: &[u8], level: i32) -> Result<Vec<u8>> {
    compress(data, level)
}
