//! Streaming compression operations for `ZstdBuilderWithChunk`

use super::compress::zstd_compress;
use super::{HasLevel, NoLevel, ZstdBuilderWithChunk};
use crate::Result;
use futures::Stream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

// Chunk handler implementations for streaming
impl<F> ZstdBuilderWithChunk<HasLevel, F>
where
    F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Compress data with streaming chunks
    pub fn compress<D: Into<Vec<u8>>>(self, data: D) -> impl Stream<Item = Vec<u8>> {
        let (tx, rx) = mpsc::channel(32);
        let data = data.into();
        let level = self.level.0;
        let handler = self.chunk_handler;

        tokio::spawn(async move {
            let chunk_size = 64 * 1024; // 64KB chunks
            let total_chunks = data.len().div_ceil(chunk_size);

            for i in 0..total_chunks {
                // Yield control to allow other tasks to run
                tokio::task::yield_now().await;

                let start = i * chunk_size;
                let end = std::cmp::min(start + chunk_size, data.len());
                let chunk = &data[start..end];

                // Compress individual chunk
                let result = zstd_compress(chunk.to_vec(), level).await;

                // Apply handler and send result
                let processed_chunk = handler(result);

                if tx.send(processed_chunk).await.is_err() {
                    break; // Receiver dropped
                }
            }
        });

        ReceiverStream::new(rx)
    }
}

impl<F> ZstdBuilderWithChunk<NoLevel, F>
where
    F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Compress data with streaming chunks using default level
    pub fn compress<D: Into<Vec<u8>>>(self, data: D) -> impl Stream<Item = Vec<u8>> {
        let (tx, rx) = mpsc::channel(32);
        let data = data.into();
        let level = 3; // Default level
        let handler = self.chunk_handler;

        tokio::spawn(async move {
            let chunk_size = 64 * 1024; // 64KB chunks
            let total_chunks = data.len().div_ceil(chunk_size);

            for i in 0..total_chunks {
                // Yield control to allow other tasks to run
                tokio::task::yield_now().await;

                let start = i * chunk_size;
                let end = std::cmp::min(start + chunk_size, data.len());
                let chunk = &data[start..end];

                // Compress individual chunk
                let result = zstd_compress(chunk.to_vec(), level).await;

                // Apply handler and send result
                let processed_chunk = handler(result);

                if tx.send(processed_chunk).await.is_err() {
                    break; // Receiver dropped
                }
            }
        });

        ReceiverStream::new(rx)
    }
}
