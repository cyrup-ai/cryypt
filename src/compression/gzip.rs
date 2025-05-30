//! Gzip compression implementation

use crate::{CryptError, Result};
use flate2::Compression;
use flate2::read::{GzDecoder, GzEncoder};
use std::io::Read;

pub fn compress(data: &[u8], level: u32) -> Result<Vec<u8>> {
    let compression = match level {
        0..=3 => Compression::fast(),
        4..=6 => Compression::default(),
        7..=9 => Compression::best(),
        _ => Compression::best(),
    };

    let mut encoder = GzEncoder::new(data, compression);
    let mut compressed = Vec::new();
    encoder
        .read_to_end(&mut compressed)
        .map_err(|e| CryptError::compression(format!("Gzip compression failed: {}", e)))?;

    Ok(compressed)
}

pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| CryptError::decompression(format!("Gzip decompression failed: {}", e)))?;

    Ok(decompressed)
}

pub fn compress_with_level(data: &[u8], level: i32) -> Result<Vec<u8>> {
    compress(data, level as u32)
}
