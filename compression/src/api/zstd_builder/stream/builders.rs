//! Zstd builder implementations for streaming operations

use super::stream_core::ZstdStream;
use super::{HasLevel, NoLevel, ZstdBuilderWithChunk};
use crate::CompressionAlgorithm;
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
