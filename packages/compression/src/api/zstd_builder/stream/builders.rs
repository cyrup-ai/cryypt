//! Zstd builder implementations for streaming operations

use super::stream_core::ZstdStream;
use super::{HasLevel, NoLevel, ZstdBuilderWithChunk};
use crate::{CompressionAlgorithm, ZstdBuilder};
use tokio_stream::Stream;

// Streaming methods for NoLevel builder with chunk handler
impl<C> ZstdBuilderWithChunk<NoLevel, C>
where
    C: Fn(crate::Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
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

    /// Decompress data using streaming chunk handler - follows cipher pattern
    pub async fn decompress<T: Into<Vec<u8>>>(self, data: T) -> Vec<u8> {
        let data = data.into();
        let handler = self.chunk_handler;

        // Use public ZstdBuilder API - create builder and decompress
        let builder = ZstdBuilder::new();
        let result = builder.decompress(data).await;

        // Apply chunk handler to raw Vec<u8> result
        handler(result.map(crate::compression_result::CompressionResult::to_vec))
            .unwrap_or_default()
    }
}

// Streaming methods for HasLevel builder with chunk handler
impl<C> ZstdBuilderWithChunk<HasLevel, C>
where
    C: Fn(crate::Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
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

    /// Decompress data using streaming chunk handler - follows cipher pattern
    pub async fn decompress<T: Into<Vec<u8>>>(self, data: T) -> Vec<u8> {
        let data = data.into();
        let handler = self.chunk_handler;

        // Use public ZstdBuilder API - create builder and decompress
        let builder = ZstdBuilder::new();
        let result = builder.decompress(data).await;

        // Apply chunk handler to raw Vec<u8> result
        handler(result.map(crate::compression_result::CompressionResult::to_vec))
            .unwrap_or_default()
    }
}
