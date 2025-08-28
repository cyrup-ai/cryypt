//! Gzip builder implementations for streaming operations

use super::stream_core::GzipStream;
use super::{GzipBuilderWithChunk, HasLevel, NoLevel};
use crate::CompressionAlgorithm;
use tokio_stream::Stream;

// Streaming methods for NoLevel builder with chunk handler
impl<C> GzipBuilderWithChunk<NoLevel, C>
where
    C: Fn(crate::Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    /// Compress data from a stream using default level (6)
    pub fn compress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self,
        stream: S,
    ) -> GzipStream<C> {
        GzipStream::new(
            stream,
            CompressionAlgorithm::Gzip { level: Some(6) },
            self.chunk_handler,
            self.error_handler,
        )
    }

    /// Decompress data from a stream
    pub fn decompress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self,
        stream: S,
    ) -> GzipStream<C> {
        GzipStream::new_decompress(
            stream,
            CompressionAlgorithm::Gzip { level: None },
            self.chunk_handler,
            self.error_handler,
        )
    }
}

// Streaming methods for HasLevel builder with chunk handler
impl<C> GzipBuilderWithChunk<HasLevel, C>
where
    C: Fn(crate::Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    /// Compress data from a stream using the configured level
    pub fn compress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self,
        stream: S,
    ) -> GzipStream<C> {
        GzipStream::new(
            stream,
            CompressionAlgorithm::Gzip {
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
    ) -> GzipStream<C> {
        GzipStream::new_decompress(
            stream,
            CompressionAlgorithm::Gzip { level: None },
            self.chunk_handler,
            self.error_handler,
        )
    }
}
