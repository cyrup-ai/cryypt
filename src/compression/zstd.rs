//! Zstd compression implementation

use crate::{CryptError, Result};

pub fn compress(data: &[u8], level: i32) -> Result<Vec<u8>> {
    zstd::encode_all(data, level)
        .map_err(|e| CryptError::compression(format!("Zstd compression failed: {}", e)))
}

pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    zstd::decode_all(data)
        .map_err(|e| CryptError::decompression(format!("Zstd decompression failed: {}", e)))
}

pub fn compress_with_level(data: &[u8], level: i32) -> Result<Vec<u8>> {
    compress(data, level)
}
