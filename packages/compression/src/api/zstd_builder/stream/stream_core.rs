//! Core `ZstdStream` struct and compression methods

use super::compressor::create_compressor;
use crate::{CompressionAlgorithm, CompressionError, Result};
use tokio::sync::mpsc;
use tokio_stream::Stream;

/// Stream of Zstd compression chunks
pub struct ZstdStream<C> {
    pub(super) receiver: mpsc::Receiver<Result<Vec<u8>>>,
    pub(super) handler: C,
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
            let mut compressor = match create_compressor(&algorithm) {
                Ok(c) => c,
                Err(e) => {
                    let _ = sender.send(Err(e)).await;
                    return;
                }
            };

            while let Some(chunk) = stream.next().await {
                // Compress chunk
                match compressor.compress_chunk(&chunk) {
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
}
