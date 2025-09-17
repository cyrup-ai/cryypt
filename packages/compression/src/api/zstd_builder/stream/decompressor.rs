//! Zstd decompression stream methods

use super::compressor::create_decompressor;
use super::stream_core::ZstdStream;
use crate::{CompressionAlgorithm, CompressionError, Result};
use tokio::sync::mpsc;
use tokio_stream::Stream;

impl<C> ZstdStream<C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync,
{
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
            let mut decompressor = match create_decompressor() {
                Ok(d) => d,
                Err(e) => {
                    let _ = sender.send(Err(e)).await;
                    return;
                }
            };

            while let Some(chunk) = stream.next().await {
                // Decompress chunk
                match decompressor.decompress_chunk(&chunk) {
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
