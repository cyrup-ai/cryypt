//! True streaming hash computation patterns
//!
//! Implements incremental hashing instead of batch processing

use crate::{HashError, Result};
use futures::Stream;
use pin_project_lite::pin_project;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Streaming hash algorithms
#[derive(Debug, Clone)]
pub enum HashAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

pin_project! {
    /// True streaming hasher that processes chunks incrementally
    pub struct StreamingHasher<S> {
        #[pin]
        input: S,
        algorithm: HashAlgorithm,
        hasher_state: HasherState,
        finished: bool,
        total_bytes: u64,
    }
}

/// Internal hasher state for different algorithms
enum HasherState {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl<S> StreamingHasher<S>
where
    S: Stream<Item = Vec<u8>>,
{
    /// Create a new streaming hasher for the specified algorithm
    pub fn new(input: S, algorithm: HashAlgorithm) -> Self {
        let hasher_state = match algorithm {
            HashAlgorithm::Sha256 => HasherState::Sha256(Sha256::new()),
            HashAlgorithm::Sha384 => HasherState::Sha384(Sha384::new()),
            HashAlgorithm::Sha512 => HasherState::Sha512(Sha512::new()),
        };

        Self {
            input,
            algorithm,
            hasher_state,
            finished: false,
            total_bytes: 0,
        }
    }

    /// Get the total number of bytes processed so far
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }
}

/// Result of streaming hash computation
#[derive(Debug, Clone)]
pub struct StreamHashResult {
    /// The final hash value
    pub hash: Vec<u8>,
    /// Total bytes processed
    pub total_bytes: u64,
    /// Algorithm used
    pub algorithm: HashAlgorithm,
}

impl<S> Stream for StreamingHasher<S>
where
    S: Stream<Item = Vec<u8>>,
{
    type Item = Result<StreamHashChunk>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut this = self.project();

        if *this.finished {
            return Poll::Ready(None);
        }

        // Process next chunk from input stream
        match this.input.as_mut().poll_next(cx) {
            Poll::Ready(Some(chunk)) => {
                let chunk_size = chunk.len() as u64;
                *this.total_bytes += chunk_size;

                // Update hasher with chunk - incremental processing
                match this.hasher_state {
                    HasherState::Sha256(hasher) => {
                        hasher.update(&chunk);
                    }
                    HasherState::Sha384(hasher) => {
                        hasher.update(&chunk);
                    }
                    HasherState::Sha512(hasher) => {
                        hasher.update(&chunk);
                    }
                }

                // Return chunk processed notification
                Poll::Ready(Some(Ok(StreamHashChunk {
                    bytes_processed: chunk_size,
                    total_bytes: *this.total_bytes,
                    is_final: false,
                    partial_hash: None,
                })))
            }
            Poll::Ready(None) => {
                // Input stream finished - finalize hash
                let final_hash = match this.hasher_state {
                    HasherState::Sha256(hasher) => {
                        let mut h = Sha256::new();
                        std::mem::swap(hasher, &mut h);
                        h.finalize().to_vec()
                    }
                    HasherState::Sha384(hasher) => {
                        let mut h = Sha384::new();
                        std::mem::swap(hasher, &mut h);
                        h.finalize().to_vec()
                    }
                    HasherState::Sha512(hasher) => {
                        let mut h = Sha512::new();
                        std::mem::swap(hasher, &mut h);
                        h.finalize().to_vec()
                    }
                };

                *this.finished = true;

                Poll::Ready(Some(Ok(StreamHashChunk {
                    bytes_processed: 0,
                    total_bytes: *this.total_bytes,
                    is_final: true,
                    partial_hash: Some(final_hash),
                })))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Chunk result from streaming hash computation
#[derive(Debug, Clone)]
pub struct StreamHashChunk {
    /// Bytes processed in this chunk
    pub bytes_processed: u64,
    /// Total bytes processed so far
    pub total_bytes: u64,
    /// Whether this is the final chunk with hash result
    pub is_final: bool,
    /// Final hash (only present if `is_final` = true)
    pub partial_hash: Option<Vec<u8>>,
}

/// Create a streaming SHA-256 hasher from any stream of byte chunks
pub fn stream_sha256<S>(input: S) -> StreamingHasher<S>
where
    S: Stream<Item = Vec<u8>>,
{
    StreamingHasher::new(input, HashAlgorithm::Sha256)
}

/// Create a streaming SHA-384 hasher from any stream of byte chunks
pub fn stream_sha384<S>(input: S) -> StreamingHasher<S>
where
    S: Stream<Item = Vec<u8>>,
{
    StreamingHasher::new(input, HashAlgorithm::Sha384)
}

/// Create a streaming SHA-512 hasher from any stream of byte chunks
pub fn stream_sha512<S>(input: S) -> StreamingHasher<S>
where
    S: Stream<Item = Vec<u8>>,
{
    StreamingHasher::new(input, HashAlgorithm::Sha512)
}

/// Collect the final hash result from a streaming hasher
///
/// # Errors
///
/// Returns `HashError` if the stream processing or final hash computation fails.
pub async fn collect_hash<S>(mut hasher: StreamingHasher<S>) -> Result<StreamHashResult>
where
    S: Stream<Item = Vec<u8>> + Unpin,
{
    use futures::StreamExt;

    let algorithm = hasher.algorithm.clone();
    let mut total_bytes = 0;
    let mut final_hash = None;

    while let Some(chunk_result) = hasher.next().await {
        let chunk = chunk_result?;
        total_bytes = chunk.total_bytes;

        if chunk.is_final {
            final_hash = chunk.partial_hash;
            break;
        }
    }

    let hash = final_hash.ok_or_else(|| {
        HashError::HashComputation("Stream ended without producing final hash".to_string())
    })?;

    Ok(StreamHashResult {
        hash,
        total_bytes,
        algorithm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::stream;
    use sha2::Digest;
    use tokio_stream::StreamExt;

    #[tokio::test]
    async fn test_streaming_sha256() -> Result<()> {
        // Test data in chunks
        let data_chunks = vec![
            b"Hello ".to_vec(),
            b"streaming ".to_vec(),
            b"world!".to_vec(),
        ];
        let input_stream = stream::iter(data_chunks.clone());

        // Hash using streaming approach
        let stream_hasher = stream_sha256(input_stream);
        let stream_result = collect_hash(stream_hasher).await?;

        // Compare with batch approach
        let combined_data: Vec<u8> = data_chunks.into_iter().flatten().collect();
        let mut batch_hasher = Sha256::new();
        batch_hasher.update(&combined_data);
        let batch_hash = batch_hasher.finalize().to_vec();

        assert_eq!(
            stream_result.hash, batch_hash,
            "Streaming and batch results should match"
        );
        assert_eq!(stream_result.total_bytes, combined_data.len() as u64);
        Ok(())
    }

    #[tokio::test]
    async fn test_streaming_chunk_processing() -> Result<()> {
        let data_chunks = vec![b"chunk1".to_vec(), b"chunk2".to_vec(), b"chunk3".to_vec()];
        let input_stream = stream::iter(data_chunks);

        let mut stream_hasher = stream_sha256(input_stream);
        let mut chunk_count = 0;
        let mut bytes_seen = 0;

        while let Some(chunk_result) = stream_hasher.next().await {
            let chunk = chunk_result?;

            if chunk.is_final {
                assert!(chunk.partial_hash.is_some(), "Final chunk should have hash");
                break;
            }
            chunk_count += 1;
            bytes_seen += chunk.bytes_processed;
            assert!(
                chunk.partial_hash.is_none(),
                "Non-final chunks should not have hash"
            );
        }

        assert_eq!(chunk_count, 3, "Should process 3 data chunks");
        assert_eq!(bytes_seen, 18, "Should process 18 bytes total"); // 6 + 6 + 6
        Ok(())
    }

    #[tokio::test]
    async fn test_different_algorithms() -> Result<()> {
        let data = b"test data for different algorithms";
        let chunks = vec![data[0..10].to_vec(), data[10..].to_vec()];

        // Test SHA-256
        let sha256_stream = stream::iter(chunks.clone());
        let sha256_hasher = stream_sha256(sha256_stream);
        let sha256_result = collect_hash(sha256_hasher).await?;

        // Test SHA-384
        let sha384_stream = stream::iter(chunks.clone());
        let sha384_hasher = stream_sha384(sha384_stream);
        let sha384_result = collect_hash(sha384_hasher).await?;

        // Test SHA-512
        let sha512_stream = stream::iter(chunks);
        let sha512_hasher = stream_sha512(sha512_stream);
        let sha512_result = collect_hash(sha512_hasher).await?;

        // Verify different hash lengths
        assert_eq!(
            sha256_result.hash.len(),
            32,
            "SHA-256 should produce 32-byte hash"
        );
        assert_eq!(
            sha384_result.hash.len(),
            48,
            "SHA-384 should produce 48-byte hash"
        );
        assert_eq!(
            sha512_result.hash.len(),
            64,
            "SHA-512 should produce 64-byte hash"
        );

        // Verify all processed same amount of data
        let expected_bytes = data.len() as u64;
        assert_eq!(sha256_result.total_bytes, expected_bytes);
        assert_eq!(sha384_result.total_bytes, expected_bytes);
        assert_eq!(sha512_result.total_bytes, expected_bytes);
        Ok(())
    }
}
