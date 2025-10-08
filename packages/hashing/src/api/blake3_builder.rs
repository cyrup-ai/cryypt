//! Blake3 Hash Builder - Polymorphic pattern for Blake3 hashing operations
//!
//! Provides polymorphic builder pattern for Blake3 hashing with both single-result
//! and streaming chunk operations.

use futures::Stream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Blake3 hash builder - initial state
#[derive(Debug, Clone, Copy)]
pub struct Blake3Builder;

/// Blake3 builder with result handler
#[derive(Debug)]
pub struct Blake3WithHandler<F> {
    handler: F,
}

/// Blake3 builder with chunk handler for streaming
#[derive(Debug)]
pub struct Blake3WithChunkHandler<F> {
    handler: F,
}

impl Default for Blake3Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake3Builder {
    /// Create new Blake3 builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Set result handler for single hash computation
    #[must_use]
    pub fn on_result<F, T>(self, handler: F) -> Blake3WithHandler<F>
    where
        F: FnOnce(crate::Result<Vec<u8>>) -> T,
        T: cryypt_common::NotResult,
    {
        Blake3WithHandler { handler }
    }

    /// Set chunk handler for streaming hash computation
    #[must_use]
    pub fn on_chunk<F>(self, handler: F) -> Blake3WithChunkHandler<F>
    where
        F: Fn(crate::Result<Vec<u8>>) -> Vec<u8>,
    {
        Blake3WithChunkHandler { handler }
    }
}

impl<F, T> Blake3WithHandler<F>
where
    F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Compute Blake3 hash of data
    #[must_use]
    pub async fn compute(self, data: &[u8]) -> T {
        let result = async {
            // Yield control to allow other tasks to run
            tokio::task::yield_now().await;

            // Compute Blake3 hash using production Blake3 cryptography
            let hash = blake3_hash(data);
            Ok(hash)
        }
        .await;

        // Apply result handler
        (self.handler)(result)
    }
}

impl<F> Blake3WithChunkHandler<F>
where
    F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Compute Blake3 hash with streaming progress updates
    pub fn compute_stream(self, data: &[u8]) -> impl Stream<Item = Vec<u8>> {
        let (tx, rx) = mpsc::channel(32);
        let data = data.to_vec();
        let handler = self.handler;

        tokio::spawn(async move {
            let chunk_size = 64 * 1024; // 64KB chunks
            let total_chunks = data.len().div_ceil(chunk_size);

            for i in 0..total_chunks {
                // Yield control to allow other tasks to run
                tokio::task::yield_now().await;

                let start = i * chunk_size;
                let end = std::cmp::min(start + chunk_size, data.len());
                let chunk = &data[start..end];

                // Compute incremental hash state
                let result = async {
                    let progress_hash = blake3_incremental_hash(chunk, i, total_chunks);
                    Ok(progress_hash)
                }
                .await;

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

/// Production Blake3 hash computation using real Blake3 cryptography
fn blake3_hash(data: &[u8]) -> Vec<u8> {
    blake3::hash(data).as_bytes().to_vec()
}

/// Production Blake3 incremental hash computation with progress metadata
fn blake3_incremental_hash(chunk: &[u8], chunk_index: usize, total_chunks: usize) -> Vec<u8> {
    // Use Blake3 hasher for incremental computation with progress metadata
    let mut hasher = blake3::Hasher::new();

    // Include progress metadata in hash computation
    hasher.update(&u32::try_from(chunk_index).unwrap_or(u32::MAX).to_le_bytes());
    hasher.update(
        &u32::try_from(total_chunks)
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    hasher.update(&u32::try_from(chunk.len()).unwrap_or(u32::MAX).to_le_bytes());
    hasher.update(chunk);

    hasher.finalize().as_bytes().to_vec()
}
