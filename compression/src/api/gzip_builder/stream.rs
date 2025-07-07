//! Gzip streaming compression and decompression
//!
//! Contains streaming operations and related types for Gzip compression.

use super::{GzipBuilderWithChunk, NoLevel, HasLevel};
use crate::{CompressionAlgorithm, CompressionError, Result};
use std::pin::Pin;
use tokio::sync::mpsc;
use tokio_stream::Stream;

// Streaming methods for NoLevel builder with chunk handler
impl<C> GzipBuilderWithChunk<NoLevel, C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    /// Compress data from a stream using default level (6)
    pub fn compress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self, 
        stream: S
    ) -> GzipStream<C> {
        GzipStream::new(stream, CompressionAlgorithm::Gzip { level: Some(6) }, self.chunk_handler, self.error_handler)
    }
    
    /// Decompress data from a stream
    pub fn decompress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self, 
        stream: S
    ) -> GzipStream<C> {
        GzipStream::new_decompress(stream, CompressionAlgorithm::Gzip { level: None }, self.chunk_handler, self.error_handler)
    }
}

// Streaming methods for HasLevel builder with chunk handler
impl<C> GzipBuilderWithChunk<HasLevel, C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    /// Compress data from a stream using the configured level
    pub fn compress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self, 
        stream: S
    ) -> GzipStream<C> {
        GzipStream::new(stream, CompressionAlgorithm::Gzip { level: Some(self.level.0) }, self.chunk_handler, self.error_handler)
    }
    
    /// Decompress data from a stream
    pub fn decompress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self, 
        stream: S
    ) -> GzipStream<C> {
        GzipStream::new_decompress(stream, CompressionAlgorithm::Gzip { level: None }, self.chunk_handler, self.error_handler)
    }
}

/// Stream of Gzip compression chunks
pub struct GzipStream<C> {
    receiver: mpsc::Receiver<Result<Vec<u8>>>,
    handler: C,
}

impl<C> GzipStream<C>
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
        let (sender, receiver) = mpsc::channel(100);
        
        // Spawn task to process stream
        tokio::spawn(async move {
            use tokio_stream::StreamExt;
            let mut stream = Box::pin(stream);
            let mut compressor = create_gzip_compressor(&algorithm);
            
            while let Some(chunk) = stream.next().await {
                // Compress chunk
                match compressor.compress_chunk(chunk) {
                    Ok(compressed) => {
                        let _ = sender.send(Ok(compressed)).await;
                    }
                    Err(e) => {
                        let error = match &error_handler {
                            Some(handler) => handler(e),
                            None => e,
                        };
                        let _ = sender.send(Err(error)).await;
                    }
                }
            }
            
            // Send final compressed data
            match compressor.finish() {
                Ok(final_data) => {
                    let _ = sender.send(Ok(final_data)).await;
                }
                Err(e) => {
                    let error = match &error_handler {
                        Some(handler) => handler(e),
                        None => e,
                    };
                    let _ = sender.send(Err(error)).await;
                }
            }
        });
        
        GzipStream {
            receiver,
            handler,
        }
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
        let (sender, receiver) = mpsc::channel(100);
        
        // Spawn task to process stream
        tokio::spawn(async move {
            use tokio_stream::StreamExt;
            let mut stream = Box::pin(stream);
            let mut decompressor = create_gzip_decompressor();
            
            while let Some(chunk) = stream.next().await {
                // Decompress chunk
                match decompressor.decompress_chunk(chunk) {
                    Ok(decompressed) => {
                        let _ = sender.send(Ok(decompressed)).await;
                    }
                    Err(e) => {
                        let error = match &error_handler {
                            Some(handler) => handler(e),
                            None => e,
                        };
                        let _ = sender.send(Err(error)).await;
                    }
                }
            }
            
            // Send final decompressed data
            match decompressor.finish() {
                Ok(final_data) => {
                    let _ = sender.send(Ok(final_data)).await;
                }
                Err(e) => {
                    let error = match &error_handler {
                        Some(handler) => handler(e),
                        None => e,
                    };
                    let _ = sender.send(Err(error)).await;
                }
            }
        });
        
        GzipStream {
            receiver,
            handler,
        }
    }
}

impl<C> Stream for GzipStream<C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Unpin,
{
    type Item = Vec<u8>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
        match self.receiver.poll_recv(cx) {
            std::task::Poll::Ready(Some(result)) => {
                // Apply user's chunk handler
                std::task::Poll::Ready((self.handler)(result))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

// Implement standard async iteration
impl<C> GzipStream<C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Unpin,
{
    /// Get the next chunk from the stream
    pub async fn next(&mut self) -> Option<Vec<u8>> {
        use tokio_stream::StreamExt;
        StreamExt::next(self).await
    }
}

// Real streaming compression implementation
struct GzipCompressor {
    encoder: flate2::write::GzEncoder<Vec<u8>>,
}

impl GzipCompressor {
    fn new(level: u32) -> Self {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        
        Self {
            encoder: GzEncoder::new(Vec::new(), Compression::new(level)),
        }
    }
    
    fn compress_chunk(&mut self, chunk: Vec<u8>) -> Result<Vec<u8>> {
        use std::io::Write;
        
        self.encoder.write_all(&chunk)
            .map_err(|e| CompressionError::internal(e.to_string()))?;
        
        // For streaming, we need to flush to get partial output
        self.encoder.flush()
            .map_err(|e| CompressionError::internal(e.to_string()))?;
        
        // Get any available compressed data
        let inner = self.encoder.get_mut();
        let compressed = inner.clone();
        inner.clear();
        
        Ok(compressed)
    }
    
    fn finish(self) -> Result<Vec<u8>> {
        self.encoder.finish()
            .map_err(|e| CompressionError::internal(e.to_string()))
    }
}

struct GzipDecompressor {
    decoder: flate2::read::GzDecoder<std::io::Cursor<Vec<u8>>>,
    buffer: Vec<u8>,
}

impl GzipDecompressor {
    fn new() -> Self {
        use flate2::read::GzDecoder;
        use std::io::Cursor;
        
        Self {
            decoder: GzDecoder::new(Cursor::new(Vec::new())),
            buffer: Vec::new(),
        }
    }
    
    fn decompress_chunk(&mut self, chunk: Vec<u8>) -> Result<Vec<u8>> {
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
    
    fn finish(self) -> Result<Vec<u8>> {
        use std::io::Read;
        
        let mut decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(self.buffer));
        let mut output = Vec::new();
        
        decoder.read_to_end(&mut output)
            .map_err(|e| CompressionError::internal(e.to_string()))?;
        
        Ok(output)
    }
}

fn create_gzip_compressor(algorithm: &CompressionAlgorithm) -> GzipCompressor {
    match algorithm {
        CompressionAlgorithm::Gzip { level } => GzipCompressor::new(level.unwrap_or(6) as u32),
        _ => GzipCompressor::new(6),
    }
}

fn create_gzip_decompressor() -> GzipDecompressor {
    GzipDecompressor::new()
}