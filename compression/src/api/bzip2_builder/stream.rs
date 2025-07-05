//! Bzip2 streaming compression and decompression
//!
//! Contains streaming operations and related types for Bzip2 compression.

use super::{Bzip2Builder, NoLevel, HasLevel};
use crate::{CompressionAlgorithm, Result};
use std::pin::Pin;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use crate::compression_on_chunk_impl;

/// Apply chunk handler using compression_on_chunk_impl macro
#[allow(dead_code)]
pub(crate) fn apply_compression_chunk_handler() -> impl Fn(Result<Vec<u8>>) -> Option<Vec<u8>> {
    compression_on_chunk_impl!(|chunk| { Ok => chunk, Err(e) => return })
}

// Streaming methods for NoLevel builder
impl Bzip2Builder<NoLevel> {
    /// Compress data from a stream using default level (9)
    pub fn compress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self, 
        stream: S
    ) -> Bzip2Stream {
        Bzip2Stream::new(stream, CompressionAlgorithm::Bzip2 { level: Some(9) }, self.chunk_handler)
    }
    
    /// Decompress data from a stream
    pub fn decompress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self, 
        stream: S
    ) -> Bzip2Stream {
        Bzip2Stream::new_decompress(stream, CompressionAlgorithm::Bzip2 { level: None }, self.chunk_handler)
    }
}

// Streaming methods for HasLevel builder
impl Bzip2Builder<HasLevel> {
    /// Compress data from a stream using the configured level
    pub fn compress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self, 
        stream: S
    ) -> Bzip2Stream {
        Bzip2Stream::new(stream, CompressionAlgorithm::Bzip2 { level: Some(self.level.0) }, self.chunk_handler)
    }
    
    /// Decompress data from a stream
    pub fn decompress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self, 
        stream: S
    ) -> Bzip2Stream {
        Bzip2Stream::new_decompress(stream, CompressionAlgorithm::Bzip2 { level: None }, self.chunk_handler)
    }
}

/// Stream of Bzip2 compression chunks
pub struct Bzip2Stream {
    receiver: mpsc::Receiver<Result<Vec<u8>>>,
    handler: Option<Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send>>,
}

impl Bzip2Stream {
    /// Create a new compression stream
    pub fn new<S>(
        stream: S,
        algorithm: CompressionAlgorithm,
        handler: Option<Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync>>,
    ) -> Self
    where
        S: Stream<Item = Vec<u8>> + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel(100);
        
        // Spawn task to process stream
        tokio::spawn(async move {
            use tokio_stream::StreamExt;
            let mut stream = Box::pin(stream);
            let mut compressor = create_bzip2_compressor(&algorithm);
            
            while let Some(chunk) = stream.next().await {
                // Compress chunk
                let compressed = compressor.compress_chunk(chunk);
                let _ = sender.send(Ok(compressed)).await;
            }
            
            // Send final compressed data
            let final_data = compressor.finish();
            let _ = sender.send(Ok(final_data)).await;
        });
        
        Bzip2Stream {
            receiver,
            handler: handler.map(|h| Box::new(h) as Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send>),
        }
    }
    
    /// Create a new decompression stream
    pub fn new_decompress<S>(
        stream: S,
        _algorithm: CompressionAlgorithm,
        handler: Option<Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync>>,
    ) -> Self
    where
        S: Stream<Item = Vec<u8>> + Send + 'static,
    {
        let (sender, receiver) = mpsc::channel(100);
        
        // Spawn task to process stream
        tokio::spawn(async move {
            use tokio_stream::StreamExt;
            let mut stream = Box::pin(stream);
            let mut decompressor = create_bzip2_decompressor();
            
            while let Some(chunk) = stream.next().await {
                // Decompress chunk
                let decompressed = decompressor.decompress_chunk(chunk);
                let _ = sender.send(Ok(decompressed)).await;
            }
            
            // Send final decompressed data
            let final_data = decompressor.finish();
            let _ = sender.send(Ok(final_data)).await;
        });
        
        Bzip2Stream {
            receiver,
            handler: handler.map(|h| Box::new(h) as Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send>),
        }
    }
}

impl Stream for Bzip2Stream {
    type Item = Vec<u8>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
        match self.receiver.poll_recv(cx) {
            std::task::Poll::Ready(Some(result)) => {
                if let Some(handler) = &self.handler {
                    std::task::Poll::Ready(handler(result))
                } else {
                    match result {
                        Ok(chunk) => std::task::Poll::Ready(Some(chunk)),
                        Err(_) => std::task::Poll::Ready(None),
                    }
                }
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

// Implement standard async iteration
impl Bzip2Stream {
    /// Get the next chunk from the stream
    pub async fn next(&mut self) -> Option<Vec<u8>> {
        use tokio_stream::StreamExt;
        StreamExt::next(self).await
    }
}

// Placeholder for streaming compression - simplified for now
struct Bzip2Compressor {
    level: u32,
    buffer: Vec<u8>,
}

impl Bzip2Compressor {
    fn new(level: u32) -> Self {
        Self {
            level,
            buffer: Vec::new(),
        }
    }
    
    fn compress_chunk(&mut self, mut chunk: Vec<u8>) -> Vec<u8> {
        self.buffer.append(&mut chunk);
        Vec::new() // Return empty for now - real implementation would compress incrementally
    }
    
    fn finish(self) -> Vec<u8> {
        // Final compression of all buffered data
        crate::bzip2::compress(&self.buffer, self.level).unwrap_or_default()
    }
}

struct Bzip2Decompressor {
    buffer: Vec<u8>,
}

impl Bzip2Decompressor {
    fn new() -> Self {
        Self {
            buffer: Vec::new(),
        }
    }
    
    fn decompress_chunk(&mut self, mut chunk: Vec<u8>) -> Vec<u8> {
        self.buffer.append(&mut chunk);
        Vec::new() // Return empty for now - real implementation would decompress incrementally
    }
    
    fn finish(self) -> Vec<u8> {
        // Final decompression of all buffered data
        crate::bzip2::decompress(&self.buffer).unwrap_or_default()
    }
}

fn create_bzip2_compressor(algorithm: &CompressionAlgorithm) -> Bzip2Compressor {
    match algorithm {
        CompressionAlgorithm::Bzip2 { level } => Bzip2Compressor::new(level.unwrap_or(9)),
        _ => Bzip2Compressor::new(9),
    }
}

fn create_bzip2_decompressor() -> Bzip2Decompressor {
    Bzip2Decompressor::new()
}