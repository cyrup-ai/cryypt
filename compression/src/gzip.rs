//! Gzip compression implementation

use crate::{CompressionError, Result};
use flate2::read::{GzDecoder, GzEncoder};
use flate2::Compression;
use std::io::Read;

/// Compress data using gzip algorithm
///
/// # Arguments
/// * `data` - The data to compress
/// * `level` - Compression level (0-9, higher is more compression)
pub fn compress(data: &[u8], level: u32) -> Result<Vec<u8>> {
    let compression = match level {
        0..=3 => Compression::fast(),
        4..=6 => Compression::default(),
        7..=9 => Compression::best(),
        _ => Compression::best(),
    };

    let mut encoder = GzEncoder::new(data, compression);
    let mut compressed = Vec::new();
    encoder.read_to_end(&mut compressed).map_err(|e| {
        CompressionError::compression_failed(format!("Gzip compression failed: {}", e))
    })?;

    Ok(compressed)
}

/// Decompress gzip compressed data
///
/// # Arguments
/// * `data` - The compressed data to decompress
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).map_err(|e| {
        CompressionError::decompression_failed(format!("Gzip decompression failed: {}", e))
    })?;

    Ok(decompressed)
}

/// Compress data using gzip with specified compression level
///
/// # Arguments
/// * `data` - The data to compress
/// * `level` - Compression level (-1 to 9, -1 is default, higher is more compression)
pub fn compress_with_level(data: &[u8], level: i32) -> Result<Vec<u8>> {
    compress(data, level as u32)
}
