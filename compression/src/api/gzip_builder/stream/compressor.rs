//! Gzip compression and decompression implementations

use crate::{CompressionAlgorithm, CompressionError, Result};

// Real streaming compression implementation
pub struct GzipCompressor {
    encoder: flate2::write::GzEncoder<Vec<u8>>,
}

impl GzipCompressor {
    pub fn new(level: u32) -> Self {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        Self {
            encoder: GzEncoder::new(Vec::new(), Compression::new(level)),
        }
    }

    pub fn compress_chunk(&mut self, chunk: Vec<u8>) -> Result<Vec<u8>> {
        use std::io::Write;

        self.encoder
            .write_all(&chunk)
            .map_err(|e| CompressionError::internal(e.to_string()))?;

        // For streaming, we need to flush to get partial output
        self.encoder
            .flush()
            .map_err(|e| CompressionError::internal(e.to_string()))?;

        // Get any available compressed data
        let inner = self.encoder.get_mut();
        let compressed = inner.clone();
        inner.clear();

        Ok(compressed)
    }

    pub fn finish(self) -> Result<Vec<u8>> {
        self.encoder
            .finish()
            .map_err(|e| CompressionError::internal(e.to_string()))
    }
}

pub struct GzipDecompressor {
    decoder: flate2::read::GzDecoder<std::io::Cursor<Vec<u8>>>,
    buffer: Vec<u8>,
}

impl Default for GzipDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl GzipDecompressor {
    pub fn new() -> Self {
        use flate2::read::GzDecoder;
        use std::io::Cursor;

        Self {
            decoder: GzDecoder::new(Cursor::new(Vec::new())),
            buffer: Vec::new(),
        }
    }

    pub fn decompress_chunk(&mut self, chunk: Vec<u8>) -> Result<Vec<u8>> {
        use std::io::Read;

        // Append new data to our buffer
        self.buffer.extend_from_slice(&chunk);

        // Update the decoder with new data
        self.decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(self.buffer.clone()));
        let mut output = Vec::new();

        match self.decoder.read_to_end(&mut output) {
            Ok(_) => Ok(output),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Need more data, return empty for now
                Ok(Vec::new())
            }
            Err(e) => Err(CompressionError::internal(e.to_string())),
        }
    }

    pub fn finish(self) -> Result<Vec<u8>> {
        use std::io::Read;

        let mut decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(self.buffer));
        let mut output = Vec::new();

        decoder
            .read_to_end(&mut output)
            .map_err(|e| CompressionError::internal(e.to_string()))?;

        Ok(output)
    }
}

pub fn create_gzip_compressor(algorithm: &CompressionAlgorithm) -> GzipCompressor {
    match algorithm {
        CompressionAlgorithm::Gzip { level } => GzipCompressor::new(level.unwrap_or(6)),
        _ => GzipCompressor::new(6),
    }
}

pub fn create_gzip_decompressor() -> GzipDecompressor {
    GzipDecompressor::new()
}
