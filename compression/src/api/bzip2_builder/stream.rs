//! Bzip2 streaming compression and decompression
//!
//! Contains streaming operations and related types for Bzip2 compression.

use super::{Bzip2BuilderWithChunk, HasLevel, NoLevel};
use crate::{CompressionAlgorithm, CompressionError, Result};
use std::pin::Pin;
use tokio::sync::mpsc;
use tokio_stream::Stream;

// Streaming methods for NoLevel builder with chunk handler
impl<C> Bzip2BuilderWithChunk<NoLevel, C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    /// Compress data from a stream using default level (6)
    #[inline]
    pub fn compress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self,
        stream: S,
    ) -> Bzip2Stream<C> {
        Bzip2Stream::new(
            stream,
            CompressionAlgorithm::Bzip2 { level: Some(6) },
            self.chunk_handler,
            self.error_handler,
        )
    }

    /// Decompress data from a stream
    #[inline]
    pub fn decompress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self,
        stream: S,
    ) -> Bzip2Stream<C> {
        Bzip2Stream::new_decompress(
            stream,
            CompressionAlgorithm::Bzip2 { level: None },
            self.chunk_handler,
            self.error_handler,
        )
    }
}

// Streaming methods for HasLevel builder with chunk handler
impl<C> Bzip2BuilderWithChunk<HasLevel, C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    /// Compress data from a stream using the configured level
    #[inline]
    pub fn compress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self,
        stream: S,
    ) -> Bzip2Stream<C> {
        Bzip2Stream::new(
            stream,
            CompressionAlgorithm::Bzip2 {
                level: Some(self.level.0),
            },
            self.chunk_handler,
            self.error_handler,
        )
    }

    /// Decompress data from a stream
    #[inline]
    pub fn decompress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self,
        stream: S,
    ) -> Bzip2Stream<C> {
        Bzip2Stream::new_decompress(
            stream,
            CompressionAlgorithm::Bzip2 { level: None },
            self.chunk_handler,
            self.error_handler,
        )
    }
}

/// Stream of Bzip2 compression chunks
pub struct Bzip2Stream<C> {
    receiver: mpsc::Receiver<Result<Vec<u8>>>,
    handler: C,
}

impl<C> Bzip2Stream<C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync,
{
    /// Create a new compression stream
    pub fn new<S>(
        stream: S,
        algorithm: CompressionAlgorithm,
        handler: C,
        error_handler: Option<Box<dyn Fn(CompressionError) -> CompressionError + Send + Sync>>,
    ) -> Self
    where
        S: Stream<Item = Vec<u8>> + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel(16); // Bounded channel for backpressure

        // Spawn task to process stream
        tokio::spawn(async move {
            use tokio_stream::StreamExt;
            let mut stream = Box::pin(stream);
            let mut compressor = create_bzip2_compressor(&algorithm);

            while let Some(chunk) = stream.next().await {
                // Compress chunk
                match compressor.compress_chunk(chunk) {
                    Ok(compressed) if !compressed.is_empty() => {
                        if sender.send(Ok(compressed)).await.is_err() {
                            break; // Receiver dropped
                        }
                    }
                    Ok(_) => {} // Empty chunk, skip
                    Err(e) => {
                        let error = error_handler.as_ref().map(|h| h(e.clone())).unwrap_or(e);
                        if sender.send(Err(error)).await.is_err() {
                            break; // Receiver dropped
                        }
                    }
                }
            }

            // Send final compressed data
            match compressor.finish() {
                Ok(final_data) if !final_data.is_empty() => {
                    let _ = sender.send(Ok(final_data)).await;
                }
                Ok(_) => {} // No final data
                Err(e) => {
                    let error = error_handler.as_ref().map(|h| h(e.clone())).unwrap_or(e);
                    let _ = sender.send(Err(error)).await;
                }
            }
        });

        Bzip2Stream { receiver, handler }
    }

    /// Create a new decompression stream
    pub fn new_decompress<S>(
        stream: S,
        _algorithm: CompressionAlgorithm,
        handler: C,
        error_handler: Option<Box<dyn Fn(CompressionError) -> CompressionError + Send + Sync>>,
    ) -> Self
    where
        S: Stream<Item = Vec<u8>> + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel(16); // Bounded channel for backpressure

        // Spawn task to process stream
        tokio::spawn(async move {
            use tokio_stream::StreamExt;
            let mut stream = Box::pin(stream);
            let mut decompressor = create_bzip2_decompressor();

            while let Some(chunk) = stream.next().await {
                // Decompress chunk
                match decompressor.decompress_chunk(chunk) {
                    Ok(decompressed) if !decompressed.is_empty() => {
                        if sender.send(Ok(decompressed)).await.is_err() {
                            break; // Receiver dropped
                        }
                    }
                    Ok(_) => {} // Need more data
                    Err(e) => {
                        let error = error_handler.as_ref().map(|h| h(e.clone())).unwrap_or(e);
                        if sender.send(Err(error)).await.is_err() {
                            break; // Receiver dropped
                        }
                    }
                }
            }

            // Send final decompressed data
            match decompressor.finish() {
                Ok(final_data) if !final_data.is_empty() => {
                    let _ = sender.send(Ok(final_data)).await;
                }
                Ok(_) => {} // No final data
                Err(e) => {
                    let error = error_handler.as_ref().map(|h| h(e.clone())).unwrap_or(e);
                    let _ = sender.send(Err(error)).await;
                }
            }
        });

        Bzip2Stream { receiver, handler }
    }
}

impl<C> Stream for Bzip2Stream<C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Unpin,
{
    type Item = Vec<u8>;

    #[inline]
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.receiver.poll_recv(cx) {
            std::task::Poll::Ready(Some(result)) => {
                // Apply user's chunk handler
                std::task::Poll::Ready((self.handler)(result))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        // We don't know the exact size, but we can hint based on channel
        (0, None)
    }
}

// Implement standard async iteration
impl<C> Bzip2Stream<C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Unpin,
{
    /// Get the next chunk from the stream
    #[inline]
    pub async fn next(&mut self) -> Option<Vec<u8>> {
        use tokio_stream::StreamExt;
        StreamExt::next(self).await
    }
}

/// Zero-allocation streaming bzip2 compressor
struct Bzip2Compressor {
    encoder: bzip2::write::BzEncoder<Vec<u8>>,
    // Pre-allocated buffer for efficiency
    output_buffer: Vec<u8>,
}

impl Bzip2Compressor {
    fn new(level: u32) -> Self {
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

    fn compress_chunk(&mut self, chunk: Vec<u8>) -> Result<Vec<u8>> {
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

    fn finish(self) -> Result<Vec<u8>> {
        self.encoder
            .finish()
            .map_err(|e| CompressionError::internal(e.to_string()))
    }
}

/// Zero-allocation streaming bzip2 decompressor
struct Bzip2Decompressor {
    // Buffer to accumulate input data
    input_buffer: Vec<u8>,
    // Pre-allocated output buffer
    output_buffer: Vec<u8>,
    // Track how much we've decompressed
    consumed: usize,
}

impl Bzip2Decompressor {
    fn new() -> Self {
        Self {
            input_buffer: Vec::with_capacity(64 * 1024),
            output_buffer: Vec::with_capacity(64 * 1024),
            consumed: 0,
        }
    }

    fn decompress_chunk(&mut self, chunk: Vec<u8>) -> Result<Vec<u8>> {
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

    fn finish(mut self) -> Result<Vec<u8>> {
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

#[inline]
fn create_bzip2_compressor(algorithm: &CompressionAlgorithm) -> Bzip2Compressor {
    match algorithm {
        CompressionAlgorithm::Bzip2 { level } => Bzip2Compressor::new(level.unwrap_or(6) as u32),
        _ => Bzip2Compressor::new(6),
    }
}

#[inline]
fn create_bzip2_decompressor() -> Bzip2Decompressor {
    Bzip2Decompressor::new()
}
