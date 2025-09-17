//! Blake2b hash builder following README.md patterns

use crate::{AsyncHashResult, AsyncHashResultWithError, HashResult, Result};
use tokio::sync::oneshot;

/// Blake2b hash builder following README.md patterns
pub struct Blake2bBuilder;

/// Blake2b hash builder with result handler
pub struct Blake2bBuilderWithHandler<F, T> {
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

/// Blake2b hash builder with error handler
pub struct Blake2bBuilderWithError<E> {
    error_handler: E,
}

/// Blake2b hash builder with chunk handler
pub struct Blake2bBuilderWithChunk<C> {
    chunk_handler: C,
}

/// Blake2b hash builder with custom output size
pub struct Blake2bBuilderWithSize {
    output_size: usize,
}

/// Blake2b hash builder with custom size and result handler
pub struct Blake2bBuilderWithSizeAndHandler<F, T> {
    output_size: usize,
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
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

    /// Set output size for Blake2b - README.md pattern
    #[must_use]
    pub fn with_output_size(self, size: usize) -> Blake2bBuilderWithSize {
        Blake2bBuilderWithSize {
            output_size: size.min(64),
        }
    }

    /// Add `on_result` handler - README.md pattern
    #[must_use]
    pub fn on_result<F, T>(self, handler: F) -> Blake2bBuilderWithHandler<F, T>
    where
        F: FnOnce(Result<HashResult>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        Blake2bBuilderWithHandler {
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Add `on_error` handler - transforms errors but passes through success
    #[must_use]
    pub fn on_error<E>(self, handler: E) -> Blake2bBuilderWithError<E>
    where
        E: Fn(crate::HashError) -> crate::HashError + Send + Sync + 'static,
    {
        Blake2bBuilderWithError {
            error_handler: handler,
        }
    }

    /// Add `on_chunk` handler for streaming - README.md pattern
    #[must_use]
    pub fn on_chunk<C>(self, handler: C) -> Blake2bBuilderWithChunk<C>
    where
        C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        Blake2bBuilderWithChunk {
            chunk_handler: handler,
        }
    }

    /// Compute hash - action takes data as argument per README.md
    #[must_use]
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResult {
        let data = data.into();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = super::hash_functions::blake2b_hash(&data).await;
            let _ = tx.send(result);
        });

        AsyncHashResult::new(rx)
    }
}

impl<F, T> Blake2bBuilderWithHandler<F, T>
where
    F: FnOnce(Result<HashResult>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Compute hash - action takes data as argument per README.md
    pub async fn compute<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();
        let handler = self.result_handler;

        // Perform Blake2b hashing
        let result = super::hash_functions::blake2b_hash(&data).await;

        // Apply result handler
        handler(result)
    }
}

impl<E> Blake2bBuilderWithError<E>
where
    E: Fn(crate::HashError) -> crate::HashError + Send + Sync + 'static,
{
    /// Add `on_result` handler after error handler
    #[must_use]
    pub fn on_result<F, T>(self, handler: F) -> Blake2bBuilderWithHandler<F, T>
    where
        F: FnOnce(Result<HashResult>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        Blake2bBuilderWithHandler {
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
            let result = super::hash_functions::blake2b_hash(&data).await;
            let _ = tx.send(result);
        });

        AsyncHashResultWithError::new(rx, error_handler)
    }
}

impl<C> Blake2bBuilderWithChunk<C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    /// Compute hash from stream - returns final hash when stream completes
    pub async fn compute_stream<S>(self, stream: S) -> Vec<u8>
    where
        S: tokio_stream::Stream<Item = Vec<u8>> + Send + 'static,
    {
        use blake2::{Blake2b512, Digest};
        use tokio_stream::StreamExt;

        let chunk_handler = self.chunk_handler;
        let mut hasher = Blake2b512::new();
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

impl Blake2bBuilderWithSize {
    /// Add `on_result` handler - README.md pattern for Blake2b with custom size
    #[must_use]
    pub fn on_result<F, T>(self, handler: F) -> Blake2bBuilderWithSizeAndHandler<F, T>
    where
        F: FnOnce(Result<HashResult>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        Blake2bBuilderWithSizeAndHandler {
            output_size: self.output_size,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Compute Blake2b hash with custom size - action takes data as argument per README.md
    #[must_use]
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResult {
        let data = data.into();
        let output_size = self.output_size;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = super::hash_functions::blake2b_hash_with_size(&data, output_size).await;
            let _ = tx.send(result);
        });

        AsyncHashResult::new(rx)
    }
}

impl<F, T> Blake2bBuilderWithSizeAndHandler<F, T>
where
    F: FnOnce(Result<HashResult>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Compute Blake2b hash with custom size - action takes data as argument per README.md
    pub async fn compute<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();
        let output_size = self.output_size;
        let handler = self.result_handler;

        // Perform Blake2b hashing with custom size
        let result = super::hash_functions::blake2b_hash_with_size(&data, output_size).await;

        // Apply result handler
        handler(result)
    }
}
