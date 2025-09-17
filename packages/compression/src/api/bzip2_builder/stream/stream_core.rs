//! Core `Bzip2Stream` struct and creation methods

use super::factory::{create_bzip2_compressor, create_bzip2_decompressor};
use crate::{CompressionAlgorithm, CompressionError, Result};
use tokio::sync::mpsc;
use tokio_stream::Stream;

/// Stream of Bzip2 compression chunks
pub struct Bzip2Stream<C> {
    pub(super) receiver: mpsc::Receiver<Result<Vec<u8>>>,
    pub(super) handler: C,
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
                match compressor.compress_chunk(&chunk) {
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
                match decompressor.decompress_chunk(&chunk) {
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
