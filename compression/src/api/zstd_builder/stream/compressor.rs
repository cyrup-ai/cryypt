//! Zstd compression and decompression implementations

use crate::{CompressionAlgorithm, CompressionError, Result};

// Real streaming compression implementation
pub struct ZstdCompressor {
    encoder: zstd::stream::Encoder<'static, Vec<u8>>,
}

impl ZstdCompressor {
    pub fn new(level: i32) -> Self {
        let encoder = zstd::stream::Encoder::new(Vec::new(), level)
            .unwrap_or_else(|e| panic!("Failed to create zstd encoder: {}", e));
        Self { encoder }
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

        // Get compressed data
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

pub struct ZstdDecompressor {
    decoder: zstd::stream::Decoder<
        'static,
        std::io::BufReader<std::io::BufReader<std::io::Cursor<Vec<u8>>>>,
    >,
    buffer: Vec<u8>,
}

impl ZstdDecompressor {
    pub fn new() -> Self {
        use std::io::Cursor;

        let decoder = zstd::stream::Decoder::new(std::io::BufReader::new(Cursor::new(Vec::new())))
            .unwrap_or_else(|e| panic!("Failed to create zstd decoder: {}", e));

        Self {
            decoder,
            buffer: Vec::new(),
        }
    }
}

impl Default for ZstdDecompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl ZstdDecompressor {
    pub fn decompress_chunk(&mut self, chunk: Vec<u8>) -> Result<Vec<u8>> {
        use std::io::{Cursor, Read};

        // Append new data to buffer
        self.buffer.extend_from_slice(&chunk);

        // Update decoder with all buffered data
        self.decoder =
            zstd::stream::Decoder::new(std::io::BufReader::new(Cursor::new(self.buffer.clone())))
                .map_err(|e| CompressionError::internal(e.to_string()))?;

        let mut output = Vec::new();
        match self.decoder.read_to_end(&mut output) {
            Ok(_) => Ok(output),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Need more data
                Ok(Vec::new())
            }
            Err(e) => Err(CompressionError::internal(e.to_string())),
        }
    }

    pub fn finish(self) -> Result<Vec<u8>> {
        use std::io::{Cursor, Read};

        let mut decoder =
            zstd::stream::Decoder::new(std::io::BufReader::new(Cursor::new(self.buffer)))
                .map_err(|e| CompressionError::internal(e.to_string()))?;

        let mut output = Vec::new();
        decoder
            .read_to_end(&mut output)
            .map_err(|e| CompressionError::internal(e.to_string()))?;

        Ok(output)
    }
}

pub fn create_compressor(algorithm: &CompressionAlgorithm) -> ZstdCompressor {
    match algorithm {
        CompressionAlgorithm::Zstd { level } => ZstdCompressor::new(level.unwrap_or(3)),
        _ => ZstdCompressor::new(3),
    }
}

pub fn create_decompressor() -> ZstdDecompressor {
    ZstdDecompressor::new()
}
