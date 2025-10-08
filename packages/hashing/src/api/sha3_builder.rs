//! SHA3 hash builders following README.md patterns

use crate::{AsyncHashResult, AsyncHashResultWithError, HashResult, Result};
use tokio::sync::oneshot;

/// SHA3-256 hash builder following README.md patterns
pub struct Sha3_256Builder;

/// SHA3-256 hash builder with result handler
pub struct Sha3_256BuilderWithHandler<F, T> {
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

/// SHA3-256 hash builder with error handler
pub struct Sha3_256BuilderWithError<E> {
    error_handler: E,
}

/// SHA3-256 hash builder with chunk handler
pub struct Sha3_256BuilderWithChunk<C> {
    chunk_handler: C,
}

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

    /// Add `on_result` handler - README.md pattern
    #[must_use]
    pub fn on_result<F, T>(self, handler: F) -> Sha3_256BuilderWithHandler<F, T>
    where
        F: FnOnce(Result<HashResult>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        Sha3_256BuilderWithHandler {
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Add `on_error` handler - transforms errors but passes through success
    #[must_use]
    pub fn on_error<E>(self, handler: E) -> Sha3_256BuilderWithError<E>
    where
        E: Fn(crate::HashError) -> crate::HashError + Send + Sync + 'static,
    {
        Sha3_256BuilderWithError {
            error_handler: handler,
        }
    }

    /// Add `on_chunk` handler for streaming - README.md pattern
    #[must_use]
    pub fn on_chunk<C>(self, handler: C) -> Sha3_256BuilderWithChunk<C>
    where
        C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        Sha3_256BuilderWithChunk {
            chunk_handler: handler,
        }
    }

    /// Compute hash - action takes data as argument per README.md
    #[must_use]
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResult {
        let data = data.into();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = super::hash_functions::sha3_256_hash(&data).await;
            let _ = tx.send(result);
        });

        AsyncHashResult::new(rx)
    }
}

impl<F, T> Sha3_256BuilderWithHandler<F, T>
where
    F: FnOnce(Result<HashResult>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Compute hash - action takes data as argument per README.md
    pub async fn compute<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();
        let handler = self.result_handler;

        // Perform SHA3-256 hashing
        let result = super::hash_functions::sha3_256_hash(&data).await;

        // Apply result handler
        handler(result)
    }
}

impl<E> Sha3_256BuilderWithError<E>
where
    E: Fn(crate::HashError) -> crate::HashError + Send + Sync + 'static,
{
    /// Add `on_result` handler after error handler
    #[must_use]
    pub fn on_result<F, T>(self, handler: F) -> Sha3_256BuilderWithHandler<F, T>
    where
        F: FnOnce(Result<HashResult>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        Sha3_256BuilderWithHandler {
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Compute hash with error handler - returns `AsyncHashResultWithError`
    #[must_use]
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResultWithError<E> {
        let data = data.into();
        let error_handler = self.error_handler;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = super::hash_functions::sha3_256_hash(&data).await;
            let _ = tx.send(result);
        });

        AsyncHashResultWithError::new(rx, error_handler)
    }
}

impl<C> Sha3_256BuilderWithChunk<C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    /// Compute hash from stream - returns final hash when stream completes
    pub async fn compute_stream<S>(self, stream: S) -> Vec<u8>
    where
        S: tokio_stream::Stream<Item = Vec<u8>> + Send + 'static,
    {
        use sha3::{Digest, Sha3_256};
        use tokio_stream::StreamExt;

        let chunk_handler = self.chunk_handler;
        let mut hasher = Sha3_256::new();
        let mut stream = Box::pin(stream);

        // Process each chunk through the handler and update the hasher
        while let Some(chunk) = stream.next().await {
            // Apply chunk handler to the chunk
            let processed = (chunk_handler)(Ok(chunk));

            // If handler returns Some(data), continue processing
            if let Some(data) = processed {
                hasher.update(&data);
            } else {
                // Handler returned None, stop processing
                break;
            }
        }

        // Return final hash
        hasher.finalize().to_vec()
    }
}

/// SHA3-384 hash builder following README.md patterns
pub struct Sha3_384Builder;

/// SHA3-384 hash builder with result handler
pub struct Sha3_384BuilderWithHandler<F, T> {
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
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

    /// Add `on_result` handler - README.md pattern
    #[must_use]
    pub fn on_result<F, T>(self, handler: F) -> Sha3_384BuilderWithHandler<F, T>
    where
        F: FnOnce(Result<HashResult>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        Sha3_384BuilderWithHandler {
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Compute hash - action takes data as argument per README.md
    #[must_use]
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResult {
        let data = data.into();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = super::hash_functions::sha3_384_hash(&data).await;
            let _ = tx.send(result);
        });

        AsyncHashResult::new(rx)
    }
}

impl<F, T> Sha3_384BuilderWithHandler<F, T>
where
    F: FnOnce(Result<HashResult>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Compute hash - action takes data as argument per README.md
    pub async fn compute<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();
        let handler = self.result_handler;

        // Perform SHA3-384 hashing
        let result = super::hash_functions::sha3_384_hash(&data).await;

        // Apply result handler
        handler(result)
    }
}

/// SHA3-512 hash builder following README.md patterns
pub struct Sha3_512Builder;

/// SHA3-512 hash builder with result handler
pub struct Sha3_512BuilderWithHandler<F, T> {
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
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

    /// Add `on_result` handler - README.md pattern
    #[must_use]
    pub fn on_result<F, T>(self, handler: F) -> Sha3_512BuilderWithHandler<F, T>
    where
        F: FnOnce(Result<HashResult>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        Sha3_512BuilderWithHandler {
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Compute hash - action takes data as argument per README.md
    #[must_use]
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResult {
        let data = data.into();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = super::hash_functions::sha3_512_hash(&data).await;
            let _ = tx.send(result);
        });

        AsyncHashResult::new(rx)
    }
}

impl<F, T> Sha3_512BuilderWithHandler<F, T>
where
    F: FnOnce(Result<HashResult>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Compute hash - action takes data as argument per README.md
    pub async fn compute<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();
        let handler = self.result_handler;

        // Perform SHA3-512 hashing
        let result = super::hash_functions::sha3_512_hash(&data).await;

        // Apply result handler
        handler(result)
    }
}
