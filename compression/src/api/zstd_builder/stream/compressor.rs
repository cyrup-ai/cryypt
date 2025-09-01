//! Zstd compression and decompression implementations

use crate::{CompressionAlgorithm, CompressionError, Result};

// Real streaming compression implementation
pub struct ZstdCompressor {
    encoder: zstd::stream::Encoder<'static, Vec<u8>>,
}

impl ZstdCompressor {
    pub fn new(level: i32) -> Result<Self> {
        let encoder = zstd::stream::Encoder::new(Vec::new(), level)
            .map_err(|e| CompressionError::internal(format!("Failed to create zstd encoder: {}", e)))?;
        Ok(Self { encoder })
    }

    pub fn compress_chunk(&mut self, chunk: Vec<u8>) -> Result<Vec<u8>> {
        use std::io::Write;

        self.encoder
            .write_all(&chunk)
            .map_err(|e| CompressionError::internal(e.to_string()))?;

        // Flush to get partial output
        self.encoder
            .flush()
            .map_err(|e| CompressionError::internal(e.to_string()))?;

        // Get compressed data using zero-copy buffer swap
        let inner = self.encoder.get_mut();
        let compressed = std::mem::take(inner);

        Ok(compressed)
    }

    pub fn finish(self) -> Result<Vec<u8>> {
        self.encoder
            .finish()
            .map_err(|e| CompressionError::internal(e.to_string()))
    }
}

pub struct ZstdDecompressor {
    input_buffer: Vec<u8>,
}

impl ZstdDecompressor {
    pub fn new() -> Result<Self> {
        Ok(Self {
            input_buffer: Vec::new(),
        })
    }
}



impl ZstdDecompressor {
    pub fn decompress_chunk(&mut self, chunk: Vec<u8>) -> Result<Vec<u8>> {
        use std::io::{Cursor, Read};

        // Append new data to input buffer
        self.input_buffer.extend_from_slice(&chunk);

        // Try to decompress with current accumulated data
        // Create decoder with current input buffer without cloning by using a temporary cursor
        let cursor = Cursor::new(&self.input_buffer);
        let mut temp_decoder = zstd::stream::Decoder::new(cursor)
            .map_err(|e| CompressionError::internal(e.to_string()))?;

        let mut output = Vec::new();
        match temp_decoder.read_to_end(&mut output) {
            Ok(_) => {
                // Successfully decompressed - clear input buffer as frame is complete
                self.input_buffer.clear();
                Ok(output)
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Need more data - keep input buffer for next chunk
                Ok(Vec::new())
            }
            Err(e) => Err(CompressionError::internal(e.to_string())),
        }
    }

    pub fn finish(self) -> Result<Vec<u8>> {
        use std::io::{Cursor, Read};

        let mut decoder = zstd::stream::Decoder::new(Cursor::new(self.input_buffer))
            .map_err(|e| CompressionError::internal(e.to_string()))?;

        let mut output = Vec::new();
        decoder
            .read_to_end(&mut output)
            .map_err(|e| CompressionError::internal(e.to_string()))?;

        Ok(output)
    }
}

pub fn create_compressor(algorithm: &CompressionAlgorithm) -> Result<ZstdCompressor> {
    match algorithm {
        CompressionAlgorithm::Zstd { level } => ZstdCompressor::new(level.unwrap_or(3)),
        other => Err(CompressionError::internal(format!(
            "ZstdCompressor cannot handle algorithm: {}. Only Zstd algorithm is supported by this compressor.",
            other
        ))),
    }
}

pub fn create_decompressor() -> Result<ZstdDecompressor> {
    ZstdDecompressor::new()
}
