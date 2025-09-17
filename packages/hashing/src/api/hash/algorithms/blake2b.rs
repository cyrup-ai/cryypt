//! Blake2b hash algorithm implementation
//!
//! Provides Blake2b builders with zero-allocation patterns and optional keying.

use crate::AsyncHashResult;
use tokio::sync::oneshot;

/// Blake2b hash builder - README.md pattern
#[derive(Clone)]
pub struct Blake2bBuilder;

/// Blake2b hash builder with result handler
pub struct Blake2bBuilderWithHandler<F, T> {
    #[allow(dead_code)] // Used by handler pattern
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

/// Blake2b hash builder with error handler
pub struct Blake2bBuilderWithError<E> {
    #[allow(dead_code)] // Used by handler pattern
    error_handler: E,
}

/// Blake2b hash builder with chunk handler
pub struct Blake2bBuilderWithChunk<C> {
    #[allow(dead_code)] // Used by handler pattern
    chunk_handler: C,
}

/// Blake2b hash builder with key
pub struct Blake2bBuilderWithKey {
    key: Vec<u8>,
}
impl Default for Blake2bBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl Blake2bBuilder {
    /// Create new Blake2b builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Add Blake2b key
    #[must_use]
    pub fn with_key<K: Into<Vec<u8>>>(self, key: K) -> Blake2bBuilderWithKey {
        Blake2bBuilderWithKey { key: key.into() }
    }

    /// Compute Blake2b hash
    #[must_use]
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResult {
        let data = data.into();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = blake2b_hash(data, None, 64)
                .await
                .map(std::convert::Into::into);
            let _ = tx.send(result);
        });

        AsyncHashResult::new(rx)
    }
}

impl Blake2bBuilderWithKey {
    /// Compute keyed Blake2b hash
    #[must_use]
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResult {
        let data = data.into();
        let key = self.key;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = blake2b_hash(data, Some(key), 64)
                .await
                .map(std::convert::Into::into);
            let _ = tx.send(result);
        });

        AsyncHashResult::new(rx)
    }
}

/// Blake2b hash function implementation
async fn blake2b_hash(
    data: Vec<u8>,
    key: Option<Vec<u8>>,
    output_size: u8,
) -> crate::Result<Vec<u8>> {
    use blake2::digest::{Digest, KeyInit, Mac};
    use blake2::{Blake2b512, Blake2bMac512};

    const CHUNK_SIZE: usize = 8192;

    if let Some(key) = key {
        // Use Blake2b as MAC with chunked processing
        let mut mac = <Blake2bMac512 as KeyInit>::new_from_slice(&key)
            .map_err(|e| crate::HashError::internal(format!("Blake2b key error: {e}")))?;

        // Process data in 8KB chunks with yield points
        for chunk in data.chunks(CHUNK_SIZE) {
            mac.update(chunk);
            tokio::task::yield_now().await;
        }

        let result = mac.finalize().into_bytes().to_vec();
        // Truncate to requested size
        Ok(result[..output_size.min(64) as usize].to_vec())
    } else {
        // Use Blake2b as hash with chunked processing
        let mut hasher = Blake2b512::default();

        // Process data in 8KB chunks with yield points
        for chunk in data.chunks(CHUNK_SIZE) {
            hasher.update(chunk);
            tokio::task::yield_now().await;
        }

        let result = hasher.finalize().to_vec();
        // Truncate to requested size
        Ok(result[..output_size.min(64) as usize].to_vec())
    }
}
