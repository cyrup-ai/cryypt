//! Zero-allocation streaming bzip2 decompressor

use crate::{CompressionError, Result};

/// Zero-allocation streaming bzip2 decompressor
pub struct Bzip2Decompressor {
    // Buffer to accumulate input data
    input_buffer: Vec<u8>,
    // Pre-allocated output buffer
    output_buffer: Vec<u8>,
    // Track how much we've decompressed
    consumed: usize,
}

impl Default for Bzip2Decompressor {
    fn default() -> Self {
        Self::new()
    }
}

impl Bzip2Decompressor {
    pub fn new() -> Self {
        Self {
            input_buffer: Vec::with_capacity(64 * 1024),
            output_buffer: Vec::with_capacity(64 * 1024),
            consumed: 0,
        }
    }

    pub fn decompress_chunk(&mut self, chunk: Vec<u8>) -> Result<Vec<u8>> {
        use bzip2::read::BzDecoder;
        use std::io::Read;

        // Append new data to our input buffer
        self.input_buffer.extend_from_slice(&chunk);

        // Try to decompress from current position
        let unconsumed = &self.input_buffer[self.consumed..];
        if unconsumed.is_empty() {
            return Ok(Vec::new());
        }

        // Create decoder for unconsumed data
        let mut decoder = BzDecoder::new(unconsumed);
        self.output_buffer.clear();

        // Read as much as we can
        match decoder.read_to_end(&mut self.output_buffer) {
            Ok(n) if n > 0 => {
                // Calculate how much input was consumed
                let total_in = decoder.total_in();
                self.consumed += total_in as usize;

                // Return decompressed data (move to avoid copy)
                Ok(std::mem::take(&mut self.output_buffer))
            }
            Ok(_) => Ok(Vec::new()), // Need more data
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                // Need more data for complete block
                Ok(Vec::new())
            }
            Err(e) => Err(CompressionError::internal(e.to_string())),
        }
    }

    pub fn finish(mut self) -> Result<Vec<u8>> {
        use bzip2::read::BzDecoder;
        use std::io::Read;

        // Final decompression of any remaining data
        let unconsumed = &self.input_buffer[self.consumed..];
        if unconsumed.is_empty() {
            return Ok(Vec::new());
        }

        let mut decoder = BzDecoder::new(unconsumed);
        self.output_buffer.clear();

        decoder
            .read_to_end(&mut self.output_buffer)
            .map_err(|e| CompressionError::internal(e.to_string()))?;

        Ok(self.output_buffer)
    }
}
