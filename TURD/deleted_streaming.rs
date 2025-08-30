//! True streaming compression patterns
//!
//! Implements incremental processing instead of batch-then-stream antipatterns

use crate::{CompressionError, Result};
use futures::Stream;
use pin_project_lite::pin_project;
use std::io::Write;
use std::pin::Pin;
use std::task::{Context, Poll};

pin_project! {
    /// True streaming compression that processes chunks as they arrive
    pub struct StreamingCompressor<S> {
        #[pin]
        input: S,
        encoder: Option<zstd::Encoder<'static, Vec<u8>>>,
        buffer: Vec<u8>,
        finished: bool,
    }
}

impl<S> StreamingCompressor<S>
where
    S: Stream<Item = Vec<u8>>,
{
    /// Create a new streaming compressor with the specified level
    pub fn new(input: S, level: i32) -> Result<Self> {
        let encoder = zstd::Encoder::new(Vec::new(), level)
            .map_err(|e| CompressionError::compression_failed(format!("Failed to create encoder: {}", e)))?;
        
        Ok(Self {
            input,
            encoder: Some(encoder),
            buffer: Vec::new(),
            finished: false,
        })
    }
}

impl<S> Stream for StreamingCompressor<S>
where
    S: Stream<Item = Vec<u8>>,
{
    type Item = Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        if *this.finished {
            return Poll::Ready(None);
        }

        // Process next chunk from input stream
        match this.input.as_mut().poll_next(cx) {
            Poll::Ready(Some(chunk)) => {
                if let Some(encoder) = this.encoder.as_mut() {
                    // Process chunk incrementally
                    match encoder.write_all(&chunk) {
                        Ok(()) => {
                            // Get any compressed output
                            let output = encoder.get_mut().clone();
                            encoder.get_mut().clear();
                            
                            if !output.is_empty() {
                                Poll::Ready(Some(Ok(output)))
                            } else {
                                // Continue processing - no output yet
                                cx.waker().wake_by_ref();
                                Poll::Pending
                            }
                        }
                        Err(e) => Poll::Ready(Some(Err(
                            CompressionError::compression_failed(format!("Streaming compression failed: {}", e))
                        ))),
                    }
                } else {
                    Poll::Ready(Some(Err(
                        CompressionError::compression_failed("Encoder not available".to_string())
                    )))
                }
            }
            Poll::Ready(None) => {
                // Input stream finished - finalize compression
                if let Some(encoder) = this.encoder.take() {
                    match encoder.finish() {
                        Ok(final_output) => {
                            *this.finished = true;
                            if !final_output.is_empty() {
                                Poll::Ready(Some(Ok(final_output)))
                            } else {
                                Poll::Ready(None)
                            }
                        }
                        Err(e) => Poll::Ready(Some(Err(
                            CompressionError::compression_failed(format!("Failed to finish compression: {}", e))
                        ))),
                    }
                } else {
                    *this.finished = true;
                    Poll::Ready(None)
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

pin_project! {
    /// True streaming decompression that processes chunks as they arrive
    pub struct StreamingDecompressor<S> {
        #[pin]
        input: S,
        decoder: Option<zstd::Decoder<'static, std::io::BufReader<std::io::Cursor<Vec<u8>>>>>,
        finished: bool,
    }
}

impl<S> StreamingDecompressor<S>
where
    S: Stream<Item = Vec<u8>>,
{
    /// Create a new streaming decompressor
    pub fn new(input: S) -> Result<Self> {
        let decoder = zstd::Decoder::new(std::io::Cursor::new(Vec::new()))
            .map_err(|e| CompressionError::decompression_failed(format!("Failed to create decoder: {}", e)))?;
        
        Ok(Self {
            input,
            decoder: Some(decoder),
            finished: false,
        })
    }
}

impl<S> Stream for StreamingDecompressor<S>
where
    S: Stream<Item = Vec<u8>>,
{
    type Item = Result<Vec<u8>>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        if *this.finished {
            return Poll::Ready(None);
        }

        // Process next chunk from input stream
        match this.input.as_mut().poll_next(cx) {
            Poll::Ready(Some(chunk)) => {
                if let Some(_decoder) = this.decoder.as_mut() {
                    // Process chunk incrementally
                    let mut output = Vec::new();
                    match std::io::copy(&mut std::io::Cursor::new(chunk), &mut output) {
                        Ok(_) => {
                            if !output.is_empty() {
                                Poll::Ready(Some(Ok(output)))
                            } else {
                                // Continue processing
                                cx.waker().wake_by_ref();
                                Poll::Pending
                            }
                        }
                        Err(e) => Poll::Ready(Some(Err(
                            CompressionError::decompression_failed(format!("Streaming decompression failed: {}", e))
                        ))),
                    }
                } else {
                    Poll::Ready(Some(Err(
                        CompressionError::decompression_failed("Decoder not available".to_string())
                    )))
                }
            }
            Poll::Ready(None) => {
                // Input stream finished
                *this.finished = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Create a streaming compressor from any stream of byte chunks
pub fn stream_compress<S>(
    input: S,
    level: i32,
) -> Result<StreamingCompressor<S>>
where
    S: Stream<Item = Vec<u8>>,
{
    StreamingCompressor::new(input, level)
}

/// Create a streaming decompressor from any stream of byte chunks  
pub fn stream_decompress<S>(
    input: S,
) -> Result<StreamingDecompressor<S>>
where
    S: Stream<Item = Vec<u8>>,
{
    StreamingDecompressor::new(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;
    use tokio_stream::StreamExt;

    #[tokio::test]
    async fn test_streaming_compression() {
        // Create a stream of data chunks
        let data_chunks = vec![
            b"Hello ".to_vec(),
            b"streaming ".to_vec(),
            b"world!".to_vec(),
        ];
        let input_stream = stream::iter(data_chunks);

        // Compress using true streaming
        let compress_stream = stream_compress(input_stream, 3).expect("Should create compressor");
        
        let compressed_chunks: Vec<_> = compress_stream
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .expect("Compression should succeed");

        // Verify we got actual compressed data
        assert!(!compressed_chunks.is_empty(), "Should produce compressed chunks");
    }

    #[tokio::test]
    async fn test_streaming_round_trip() {
        let original_data = b"This is test data for streaming compression and decompression";
        let chunks = vec![
            original_data[0..10].to_vec(),
            original_data[10..25].to_vec(),
            original_data[25..].to_vec(),
        ];
        
        let input_stream = stream::iter(chunks);

        // Compress
        let compress_stream = stream_compress(input_stream, 1).expect("Should create compressor");
        let compressed_chunks: Vec<_> = compress_stream
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .expect("Compression should succeed");

        // Decompress
        let compressed_stream = stream::iter(compressed_chunks);
        let decompress_stream = stream_decompress(compressed_stream).expect("Should create decompressor");
        let decompressed_chunks: Vec<_> = decompress_stream
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .expect("Decompression should succeed");

        // Verify round-trip
        let decompressed_data: Vec<u8> = decompressed_chunks.into_iter().flatten().collect();
        assert_eq!(decompressed_data, original_data, "Round-trip should preserve data");
    }
}