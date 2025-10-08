//! SHA-3 family hash algorithms implementation
//!
//! Provides SHA3-256, SHA3-384, and SHA3-512 builders with zero-allocation patterns.

use crate::AsyncHashResult;
use tokio::sync::oneshot;

/// SHA3-256 hash builder - README.md pattern
#[derive(Clone)]
pub struct Sha3_256Builder;

/// SHA3-256 hash builder with result handler
pub struct Sha3_256BuilderWithHandler<F, T> {
    #[allow(dead_code)] // Used by handler pattern
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

/// SHA3-256 hash builder with error handler
pub struct Sha3_256BuilderWithError<E> {
    #[allow(dead_code)] // Used by handler pattern
    error_handler: E,
}

/// SHA3-256 hash builder with chunk handler
pub struct Sha3_256BuilderWithChunk<C> {
    #[allow(dead_code)] // Used by handler pattern
    chunk_handler: C,
}

/// SHA3-384 hash builder - README.md pattern
#[derive(Clone)]
pub struct Sha3_384Builder;

/// SHA3-512 hash builder - README.md pattern
#[derive(Clone)]
pub struct Sha3_512Builder;
impl Default for Sha3_256Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_256Builder {
    /// Create new SHA3-256 builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Compute SHA3-256 hash
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResult {
        let data = data.into();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = sha3_256_hash(&data).await.map(std::convert::Into::into);
            let _ = tx.send(result);
        });

        AsyncHashResult::new(rx)
    }
}

impl Default for Sha3_384Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_384Builder {
    /// Create new SHA3-384 builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Compute SHA3-384 hash
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResult {
        let data = data.into();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = sha3_384_hash(&data).await.map(std::convert::Into::into);
            let _ = tx.send(result);
        });

        AsyncHashResult::new(rx)
    }
}

impl Default for Sha3_512Builder {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha3_512Builder {
    /// Create new SHA3-512 builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Compute SHA3-512 hash
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResult {
        let data = data.into();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = sha3_512_hash(&data).await.map(std::convert::Into::into);
            let _ = tx.send(result);
        });

        AsyncHashResult::new(rx)
    }
}

/// Internal SHA3-256 hash function with chunked async processing
async fn sha3_256_hash(data: &[u8]) -> crate::Result<Vec<u8>> {
    use sha3::{Digest, Sha3_256};

    const CHUNK_SIZE: usize = 8192;
    let mut hasher = Sha3_256::new();

    // Process data in 8KB chunks with yield points
    for chunk in data.chunks(CHUNK_SIZE) {
        hasher.update(chunk);
        tokio::task::yield_now().await;
    }

    let result = hasher.finalize();
    Ok(result.to_vec())
}

/// Internal SHA3-384 hash function with chunked async processing
async fn sha3_384_hash(data: &[u8]) -> crate::Result<Vec<u8>> {
    use sha3::{Digest, Sha3_384};

    const CHUNK_SIZE: usize = 8192;
    let mut hasher = Sha3_384::new();

    // Process data in 8KB chunks with yield points
    for chunk in data.chunks(CHUNK_SIZE) {
        hasher.update(chunk);
        tokio::task::yield_now().await;
    }

    let result = hasher.finalize();
    Ok(result.to_vec())
}

/// Internal SHA3-512 hash function with chunked async processing
async fn sha3_512_hash(data: &[u8]) -> crate::Result<Vec<u8>> {
    use sha3::{Digest, Sha3_512};

    const CHUNK_SIZE: usize = 8192;
    let mut hasher = Sha3_512::new();

    // Process data in 8KB chunks with yield points
    for chunk in data.chunks(CHUNK_SIZE) {
        hasher.update(chunk);
        tokio::task::yield_now().await;
    }

    let result = hasher.finalize();
    Ok(result.to_vec())
}
