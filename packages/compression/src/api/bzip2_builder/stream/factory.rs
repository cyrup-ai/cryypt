//! Factory functions for creating Bzip2 compressor and decompressor

use super::compressor::Bzip2Compressor;
use super::decompressor::Bzip2Decompressor;
use crate::CompressionAlgorithm;

#[inline]
#[must_use]
pub fn create_bzip2_compressor(algorithm: &CompressionAlgorithm) -> Bzip2Compressor {
    match algorithm {
        CompressionAlgorithm::Bzip2 { level } => Bzip2Compressor::new(level.unwrap_or(6)),
        _ => Bzip2Compressor::new(6),
    }
}

#[inline]
#[must_use]
pub fn create_bzip2_decompressor() -> Bzip2Decompressor {
    Bzip2Decompressor::new()
}
