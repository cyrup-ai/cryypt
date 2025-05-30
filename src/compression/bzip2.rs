//! Bzip2 compression implementation

use crate::{CryptError, Result};
use bzip2::Compression;
use bzip2::read::{BzDecoder, BzEncoder};
use std::io::Read;

pub fn compress(data: &[u8], level: u32) -> Result<Vec<u8>> {
    let compression = Compression::new(level);

    let mut encoder = BzEncoder::new(data, compression);
    let mut compressed = Vec::new();
    encoder
        .read_to_end(&mut compressed)
        .map_err(|e| CryptError::compression(format!("Bzip2 compression failed: {}", e)))?;

    Ok(compressed)
}

pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = BzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .map_err(|e| CryptError::decompression(format!("Bzip2 decompression failed: {}", e)))?;

    Ok(decompressed)
}
