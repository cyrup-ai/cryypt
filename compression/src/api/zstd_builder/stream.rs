//! Zstd streaming compression and decompression
//!
//! Contains streaming operations and related types for Zstd compression.

use super::{HasLevel, NoLevel, ZstdBuilderWithChunk};
use crate::{CompressionAlgorithm, CompressionError, Result};
use std::pin::Pin;
use tokio::sync::mpsc;
use tokio_stream::Stream;

// Streaming methods for NoLevel builder with chunk handler
impl<C> ZstdBuilderWithChunk<NoLevel, C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    /// Compress data from a stream using default level (3)
    pub fn compress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self,
        stream: S,
    ) -> ZstdStream<C> {
        ZstdStream::new(
            stream,
            CompressionAlgorithm::Zstd { level: Some(3) },
            self.chunk_handler,
            self.error_handler,
        )
    }

    /// Decompress data from a stream
    pub fn decompress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self,
        stream: S,
    ) -> ZstdStream<C> {
        ZstdStream::new_decompress(
            stream,
            CompressionAlgorithm::Zstd { level: None },
            self.chunk_handler,
            self.error_handler,
        )
    }
}

// Streaming methods for HasLevel builder with chunk handler
impl<C> ZstdBuilderWithChunk<HasLevel, C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    /// Compress data from a stream using the configured level
    pub fn compress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self,
        stream: S,
    ) -> ZstdStream<C> {
        ZstdStream::new(
            stream,
            CompressionAlgorithm::Zstd {
                level: Some(self.level.0),
            },
            self.chunk_handler,
            self.error_handler,
        )
    }

    /// Decompress data from a stream
    pub fn decompress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self,
        stream: S,
    ) -> ZstdStream<C> {
        ZstdStream::new_decompress(
            stream,
            CompressionAlgorithm::Zstd { level: None },
            self.chunk_handler,
            self.error_handler,
        )
    }
}

/// Stream of Zstd compression chunks
pub struct ZstdStream<C> {
    receiver: mpsc::Receiver<Result<Vec<u8>>>,
    handler: C,
}

impl<C> ZstdStream<C>
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
            let mut compressor = create_compressor(&algorithm);

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

        ZstdStream { receiver, handler }
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
            let mut decompressor = create_decompressor();

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

        ZstdStream { receiver, handler }
    }
}

impl<C> Stream for ZstdStream<C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Unpin,
{
    type Item = Vec<u8>;

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
}

// Implement standard async iteration
impl<C> ZstdStream<C>
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
struct ZstdCompressor {
    encoder: zstd::stream::Encoder<'static, Vec<u8>>,
}

impl ZstdCompressor {
    fn new(level: i32) -> Self {
        let encoder =
            zstd::stream::Encoder::new(Vec::new(), level).expect("Failed to create zstd encoder");
        Self { encoder }
    }

    fn compress_chunk(&mut self, chunk: Vec<u8>) -> Result<Vec<u8>> {
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

    fn finish(self) -> Result<Vec<u8>> {
        self.encoder
            .finish()
            .map_err(|e| CompressionError::internal(e.to_string()))
    }
}

struct ZstdDecompressor {
    decoder: zstd::stream::Decoder<
        'static,
        std::io::BufReader<std::io::BufReader<std::io::Cursor<Vec<u8>>>>,
    >,
    buffer: Vec<u8>,
}

impl ZstdDecompressor {
    fn new() -> Self {
        use std::io::Cursor;

        let decoder = zstd::stream::Decoder::new(std::io::BufReader::new(Cursor::new(Vec::new())))
            .expect("Failed to create zstd decoder");

        Self {
            decoder,
            buffer: Vec::new(),
        }
    }

    fn decompress_chunk(&mut self, chunk: Vec<u8>) -> Result<Vec<u8>> {
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

    fn finish(self) -> Result<Vec<u8>> {
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

fn create_compressor(algorithm: &CompressionAlgorithm) -> ZstdCompressor {
    match algorithm {
        CompressionAlgorithm::Zstd { level } => ZstdCompressor::new(level.unwrap_or(3)),
        _ => ZstdCompressor::new(3),
    }
}

fn create_decompressor() -> ZstdDecompressor {
    ZstdDecompressor::new()
}
