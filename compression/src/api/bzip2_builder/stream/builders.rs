//! Stream builder implementations for Bzip2 compression

use super::super::{Bzip2BuilderWithChunk, HasLevel, NoLevel};
use super::stream_core::Bzip2Stream;
use crate::CompressionAlgorithm;
use tokio_stream::Stream;

// Streaming methods for NoLevel builder with chunk handler
impl<C> Bzip2BuilderWithChunk<NoLevel, C>
where
    C: Fn(crate::Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    /// Compress data from a stream using default level (6)
    #[inline]
    pub fn compress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self,
        stream: S,
    ) -> Bzip2Stream<C> {
        Bzip2Stream::new(
            stream,
            CompressionAlgorithm::Bzip2 { level: Some(6) },
            self.chunk_handler,
            self.error_handler,
        )
    }

    /// Decompress data from a stream
    #[inline]
    pub fn decompress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self,
        stream: S,
    ) -> Bzip2Stream<C> {
        Bzip2Stream::new_decompress(
            stream,
            CompressionAlgorithm::Bzip2 { level: None },
            self.chunk_handler,
            self.error_handler,
        )
    }
}

// Streaming methods for HasLevel builder with chunk handler
impl<C> Bzip2BuilderWithChunk<HasLevel, C>
where
    C: Fn(crate::Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    /// Compress data from a stream using the configured level
    #[inline]
    pub fn compress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self,
        stream: S,
    ) -> Bzip2Stream<C> {
        Bzip2Stream::new(
            stream,
            CompressionAlgorithm::Bzip2 {
                level: Some(self.level.0),
            },
            self.chunk_handler,
            self.error_handler,
        )
    }

    /// Decompress data from a stream
    #[inline]
    pub fn decompress_stream<S: Stream<Item = Vec<u8>> + Send + 'static>(
        self,
        stream: S,
    ) -> Bzip2Stream<C> {
        Bzip2Stream::new_decompress(
            stream,
            CompressionAlgorithm::Bzip2 { level: None },
            self.chunk_handler,
            self.error_handler,
        )
    }
}
