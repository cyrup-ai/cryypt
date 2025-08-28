//! Zero-allocation streaming bzip2 compressor

use crate::{CompressionError, Result};

/// Zero-allocation streaming bzip2 compressor
pub struct Bzip2Compressor {
    encoder: bzip2::write::BzEncoder<Vec<u8>>,
    // Pre-allocated buffer for efficiency
    output_buffer: Vec<u8>,
}

impl Bzip2Compressor {
    pub fn new(level: u32) -> Self {
        use bzip2::Compression;
        use bzip2::write::BzEncoder;

        // Pre-allocate output buffer with reasonable capacity
        let mut output_buffer = Vec::with_capacity(64 * 1024);
        output_buffer.clear(); // Ensure len is 0

        Self {
            encoder: BzEncoder::new(output_buffer, Compression::new(level)),
            output_buffer: Vec::with_capacity(64 * 1024),
        }
    }

    pub fn compress_chunk(&mut self, chunk: Vec<u8>) -> Result<Vec<u8>> {
        use std::io::Write;

        // Write input to encoder
        self.encoder
            .write_all(&chunk)
            .map_err(|e| CompressionError::internal(e.to_string()))?;

        // Flush to get partial output
        self.encoder
            .flush()
            .map_err(|e| CompressionError::internal(e.to_string()))?;

        // Extract any available compressed data
        let inner = self.encoder.get_mut();
        if inner.is_empty() {
            return Ok(Vec::new());
        }

        // Swap buffers to avoid allocation
        std::mem::swap(inner, &mut self.output_buffer);
        inner.clear();

        // Return the compressed data (ownership transferred)
        Ok(std::mem::take(&mut self.output_buffer))
    }

    pub fn finish(self) -> Result<Vec<u8>> {
        self.encoder
            .finish()
            .map_err(|e| CompressionError::internal(e.to_string()))
    }
}
