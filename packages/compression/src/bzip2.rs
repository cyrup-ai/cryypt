//! Bzip2 compression implementation

use crate::{CompressionError, Result};
use bzip2::Compression;
use bzip2::read::{BzDecoder, BzEncoder};
use std::io::Read;

/// Compress data using bzip2 algorithm
///
/// # Arguments
/// * `data` - The data to compress
/// * `level` - Compression level (1-9, higher is more compression)
///
/// # Errors
/// Returns `CompressionError::CompressionFailed` if the bzip2 compression operation fails
pub fn compress(data: &[u8], level: u32) -> Result<Vec<u8>> {
    let compression = Compression::new(level);

    let mut encoder = BzEncoder::new(data, compression);
    let mut compressed = Vec::new();
    encoder.read_to_end(&mut compressed).map_err(|e| {
        CompressionError::compression_failed(format!("Bzip2 compression failed: {e}"))
    })?;

    Ok(compressed)
}

/// Decompress bzip2 compressed data
///
/// # Arguments
/// * `data` - The compressed data to decompress
///
/// # Errors
/// Returns `CompressionError::DecompressionFailed` if the bzip2 decompression operation fails
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = BzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).map_err(|e| {
        CompressionError::decompression_failed(format!("Bzip2 decompression failed: {e}"))
    })?;

    Ok(decompressed)
}
