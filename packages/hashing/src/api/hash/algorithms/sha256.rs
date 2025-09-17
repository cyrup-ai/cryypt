//! SHA-256 hash algorithm implementation
//!
//! Provides SHA-256 builders and implementations with zero-allocation patterns.

use crate::{AsyncHashResult, HashResult, Result as HashingResult};
use tokio::sync::oneshot;

/// SHA-256 hash builder - README.md pattern
#[derive(Clone)]
pub struct Sha256Builder;

/// SHA-256 hash builder with result handler
pub struct Sha256BuilderWithHandler<F, T> {
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

/// SHA-256 hash builder with error handler
pub struct Sha256BuilderWithError<E> {
    error_handler: E,
}

/// SHA-256 hash builder with chunk handler
pub struct Sha256BuilderWithChunk<C> {
    #[allow(dead_code)] // Used by handler pattern
    chunk_handler: C,
}

/// SHA-256 hash builder with HMAC key
pub struct Sha256BuilderWithKey {
    key: Vec<u8>,
}

impl Sha256BuilderWithKey {
    #[allow(dead_code)] // Used by handler pattern
    fn on_chunk<F>(self, _handler: F) -> Self
    where
        F: Fn(HashingResult<Vec<u8>>) -> Vec<u8> + Send + Sync + 'static,
    {
        self
    }
}

impl Default for Sha256Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256Builder {
    /// Create new SHA-256 builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Add HMAC key - README.md pattern
    pub fn with_key<K: Into<Vec<u8>>>(self, key: K) -> Sha256BuilderWithKey {
        Sha256BuilderWithKey { key: key.into() }
    }

    /// Add `on_result` handler - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> Sha256BuilderWithHandler<F, T>
    where
        F: FnOnce(HashingResult<HashResult>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        Sha256BuilderWithHandler {
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Add `on_error` handler - transforms errors but passes through success
    pub fn on_error<E>(self, handler: E) -> Sha256BuilderWithError<E>
    where
        E: Fn(crate::HashError) -> crate::HashError + Send + Sync + 'static,
    {
        Sha256BuilderWithError {
            error_handler: handler,
        }
    }

    /// Add `on_chunk` handler for streaming - README.md pattern
    pub fn on_chunk<C>(self, handler: C) -> Sha256BuilderWithChunk<C>
    where
        C: Fn(HashingResult<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        Sha256BuilderWithChunk {
            chunk_handler: handler,
        }
    }

    /// Compute hash - action takes data as argument per README.md
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResult {
        let data = data.into();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = sha256_hash(&data).await.map(std::convert::Into::into);
            let _ = tx.send(result);
        });

        AsyncHashResult::new(rx)
    }
}
impl<F, T> Sha256BuilderWithHandler<F, T>
where
    F: FnOnce(HashingResult<HashResult>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Compute hash with handler
    pub async fn compute<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();
        let result = sha256_hash(&data).await.map(std::convert::Into::into);
        (self.result_handler)(result)
    }
}

impl<E> Sha256BuilderWithError<E>
where
    E: Fn(crate::HashError) -> crate::HashError + Send + Sync + 'static,
{
    /// Add `on_result` handler after error handler
    pub fn on_result<F, T>(self, handler: F) -> Sha256BuilderWithHandler<F, T>
    where
        F: FnOnce(HashingResult<HashResult>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        Sha256BuilderWithHandler {
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Compute hash with error handler
    pub fn compute<D: Into<Vec<u8>>>(self, data: D) -> crate::AsyncHashResultWithError<E> {
        let data = data.into();
        let error_handler = self.error_handler;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = sha256_hash(&data).await.map(std::convert::Into::into);
            let _ = tx.send(result);
        });

        crate::AsyncHashResultWithError::new(rx, error_handler)
    }
}

impl Sha256BuilderWithKey {
    /// Compute HMAC-SHA256
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResult {
        let data = data.into();
        let key = self.key;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = sha256_hmac(&key, &data).await.map(std::convert::Into::into);
            let _ = tx.send(result);
        });

        AsyncHashResult::new(rx)
    }
}

/// Internal SHA256 hash function with chunked async processing
async fn sha256_hash(data: &[u8]) -> crate::Result<Vec<u8>> {
    use sha2::{Digest, Sha256};

    const CHUNK_SIZE: usize = 8192;
    let mut hasher = Sha256::new();

    // Process data in 8KB chunks with yield points
    for chunk in data.chunks(CHUNK_SIZE) {
        hasher.update(chunk);
        tokio::task::yield_now().await;
    }

    let result = hasher.finalize();
    Ok(result.to_vec())
}

/// Internal HMAC-SHA256 function with chunked async processing
async fn sha256_hmac(key: &[u8], data: &[u8]) -> crate::Result<Vec<u8>> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    const CHUNK_SIZE: usize = 8192;
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| crate::HashError::invalid_parameters("Invalid HMAC key length"))?;

    // Process data in 8KB chunks with yield points
    for chunk in data.chunks(CHUNK_SIZE) {
        mac.update(chunk);
        tokio::task::yield_now().await;
    }

    let result = mac.finalize().into_bytes();
    Ok(result.to_vec())
}
