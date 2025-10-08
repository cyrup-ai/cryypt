//! Gzip compression and decompression implementations

use crate::{CompressionAlgorithm, CompressionError, Result};

// Real streaming compression implementation
pub struct GzipCompressor {
    encoder: flate2::write::GzEncoder<Vec<u8>>,
}

impl GzipCompressor {
    #[must_use]
    pub fn new(level: u32) -> Self {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        Self {
            encoder: GzEncoder::new(Vec::new(), Compression::new(level)),
        }
    }

    /// Compress a single chunk of data using gzip compression
    ///
    /// # Errors
    ///
    /// Returns `CompressionError::Internal` if:
    /// - The underlying gzip encoder fails to write the input data
    /// - The encoder fails to flush and produce compressed output
    /// - I/O operations on the internal buffer fail
    pub fn compress_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        use std::io::Write;

        self.encoder
            .write_all(chunk)
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

    /// Finalize gzip compression and return remaining compressed data
    ///
    /// # Errors
    ///
    /// Returns `CompressionError::Internal` if the encoder fails to finalize
    /// and produce the final compressed output.
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
    #[must_use]
    pub fn new() -> Self {
        use flate2::read::GzDecoder;
        use std::io::Cursor;

        Self {
            decoder: GzDecoder::new(Cursor::new(Vec::new())),
            buffer: Vec::new(),
        }
    }

    /// Decompress a chunk of data
    ///
    /// # Errors
    /// Returns an error if decompression fails or if invalid gzip data is provided
    pub fn decompress_chunk(&mut self, chunk: &[u8]) -> Result<Vec<u8>> {
        use std::io::Read;

        // Append new data to our buffer
        self.buffer.extend_from_slice(chunk);

        // Update the decoder with new data
        self.decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(self.buffer.clone()));
        let mut output = Vec::new();

        match self.decoder.read_to_end(&mut output) {
            Ok(_) => Ok(output),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Need more data - implement proper buffering for partial decompression
                if !self.buffer.is_empty() && self.buffer.len() >= 10 {
                    // Minimum gzip header size
                    // Try partial decompression with current buffer
                    let mut partial_output = vec![0u8; 4096]; // 4KB buffer for partial read
                    let mut temp_decoder =
                        flate2::read::GzDecoder::new(std::io::Cursor::new(&self.buffer));

                    match temp_decoder.read(&mut partial_output) {
                        Ok(bytes_read) if bytes_read > 0 => {
                            partial_output.truncate(bytes_read);
                            Ok(partial_output)
                        }
                        Ok(_) | Err(_) => Ok(Vec::new()), // No data available yet or partial read failed, need more data
                    }
                } else {
                    Ok(Vec::new()) // Not enough data for gzip header
                }
            }
            Err(e) => Err(CompressionError::internal(e.to_string())),
        }
    }

    /// Complete decompression and return final data
    ///
    /// # Errors
    /// Returns an error if final decompression fails or if the gzip stream is incomplete
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

#[must_use]
pub fn create_gzip_compressor(algorithm: &CompressionAlgorithm) -> GzipCompressor {
    match algorithm {
        CompressionAlgorithm::Gzip { level } => GzipCompressor::new(level.unwrap_or(6)),
        _ => GzipCompressor::new(6),
    }
}

#[must_use]
pub fn create_gzip_decompressor() -> GzipDecompressor {
    GzipDecompressor::new()
}
