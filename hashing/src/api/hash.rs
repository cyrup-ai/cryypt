//! Entry point for the fluent hashing API following README.md patterns exactly

use crate::{AsyncHashResult, AsyncHashResultWithError, HashResult, Result};
use tokio::sync::oneshot;

/// Entry point for hash operations - README.md pattern
pub struct Hash;

impl Hash {
    /// Use SHA-256 - README.md pattern
    pub fn sha256() -> crate::api::sha256_builder::Sha256Builder {
        crate::api::sha256_builder::Sha256Builder::new()
    }

    /// Use SHA3-256 - README.md pattern  
    pub fn sha3_256() -> Sha3_256Builder {
        Sha3_256Builder::new()
    }

    /// Use SHA3-384 - README.md pattern
    pub fn sha3_384() -> Sha3_384Builder {
        Sha3_384Builder::new()
    }

    /// Use SHA3-512 - README.md pattern  
    pub fn sha3_512() -> Sha3_512Builder {
        Sha3_512Builder::new()
    }

    /// Use Blake2b - README.md pattern
    pub fn blake2b() -> Blake2bBuilder {
        Blake2bBuilder::new()
    }
}

/// SHA-256 hash builder following README.md patterns
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
    chunk_handler: C,
}

/// SHA-256 hash builder with HMAC key
pub struct Sha256BuilderWithKey {
    key: Vec<u8>,
}

impl Sha256Builder {
    /// Create new SHA-256 builder
    pub fn new() -> Self {
        Self
    }

    /// Add HMAC key - README.md pattern
    pub fn with_key<K: Into<Vec<u8>>>(self, key: K) -> Sha256BuilderWithKey {
        Sha256BuilderWithKey { key: key.into() }
    }

    /// Add on_result handler - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> Sha256BuilderWithHandler<F, T>
    where
        F: FnOnce(Result<HashResult>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        Sha256BuilderWithHandler {
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Add on_error handler - transforms errors but passes through success
    pub fn on_error<E>(self, handler: E) -> Sha256BuilderWithError<E>
    where
        E: Fn(crate::HashError) -> crate::HashError + Send + Sync + 'static,
    {
        Sha256BuilderWithError {
            error_handler: handler,
        }
    }

    /// Add on_chunk handler for streaming - README.md pattern
    pub fn on_chunk<C>(self, handler: C) -> Sha256BuilderWithChunk<C>
    where
        C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
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
            let result = sha256_hash(&data).await;
            let _ = tx.send(result);
        });

        AsyncHashResult::new(rx)
    }
}

impl<F, T> Sha256BuilderWithHandler<F, T>
where
    F: FnOnce(Result<HashResult>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Compute hash - action takes data as argument per README.md
    pub async fn compute<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();
        let handler = self.result_handler;

        // Perform SHA-256 hashing
        let result = sha256_hash(&data).await;

        // Apply result handler
        handler(result)
    }
}

impl<E> Sha256BuilderWithError<E>
where
    E: Fn(crate::HashError) -> crate::HashError + Send + Sync + 'static,
{
    /// Add on_result handler after error handler
    pub fn on_result<F, T>(self, handler: F) -> Sha256BuilderWithHandler<F, T>
    where
        F: FnOnce(Result<HashResult>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        Sha256BuilderWithHandler {
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Compute hash with error handler - returns AsyncHashResultWithError
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResultWithError<E> {
        let data = data.into();
        let error_handler = self.error_handler;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = sha256_hash(&data).await;
            let _ = tx.send(result);
        });

        AsyncHashResultWithError::new(rx, error_handler)
    }
}

impl<C> Sha256BuilderWithChunk<C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
{
    /// Compute hash from stream - returns final hash when stream completes
    pub async fn compute_stream<S>(self, stream: S) -> Vec<u8>
    where
        S: tokio_stream::Stream<Item = Vec<u8>> + Send + 'static,
    {
        use sha2::{Digest, Sha256};
        use tokio_stream::StreamExt;

        let chunk_handler = self.chunk_handler;
        let mut hasher = Sha256::new();
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

impl Sha256BuilderWithKey {
    /// Add on_result handler - README.md pattern for HMAC
    pub fn on_result<F, T>(self, handler: F) -> Sha256BuilderWithKeyAndHandler<F, T>
    where
        F: FnOnce(Result<HashResult>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        Sha256BuilderWithKeyAndHandler {
            key: self.key,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Compute HMAC - action takes data as argument per README.md
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResult {
        let data = data.into();
        let key = self.key;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = sha256_hmac(&data, &key).await;
            let _ = tx.send(result);
        });

        AsyncHashResult::new(rx)
    }
}

/// SHA-256 hash builder with HMAC key and result handler
pub struct Sha256BuilderWithKeyAndHandler<F, T> {
    key: Vec<u8>,
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

impl<F, T> Sha256BuilderWithKeyAndHandler<F, T>
where
    F: FnOnce(Result<HashResult>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Compute HMAC - action takes data as argument per README.md
    pub async fn compute<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();
        let key = self.key;
        let handler = self.result_handler;

        // Perform HMAC-SHA256
        let result = sha256_hmac(&data, &key).await;

        // Apply result handler
        handler(result)
    }
}

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

impl Sha3_256Builder {
    /// Create new SHA3-256 builder
    pub fn new() -> Self {
        Self
    }

    /// Add on_result handler - README.md pattern
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

    /// Add on_error handler - transforms errors but passes through success
    pub fn on_error<E>(self, handler: E) -> Sha3_256BuilderWithError<E>
    where
        E: Fn(crate::HashError) -> crate::HashError + Send + Sync + 'static,
    {
        Sha3_256BuilderWithError {
            error_handler: handler,
        }
    }

    /// Add on_chunk handler for streaming - README.md pattern
    pub fn on_chunk<C>(self, handler: C) -> Sha3_256BuilderWithChunk<C>
    where
        C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        Sha3_256BuilderWithChunk {
            chunk_handler: handler,
        }
    }

    /// Compute hash - action takes data as argument per README.md
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResult {
        let data = data.into();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = sha3_256_hash(&data).await;
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
        let result = sha3_256_hash(&data).await;

        // Apply result handler
        handler(result)
    }
}

impl<E> Sha3_256BuilderWithError<E>
where
    E: Fn(crate::HashError) -> crate::HashError + Send + Sync + 'static,
{
    /// Add on_result handler after error handler
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

    /// Compute hash with error handler - returns AsyncHashResultWithError
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResultWithError<E> {
        let data = data.into();
        let error_handler = self.error_handler;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = sha3_256_hash(&data).await;
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

impl Sha3_384Builder {
    /// Create new SHA3-384 builder
    pub fn new() -> Self {
        Self
    }

    /// Add on_result handler - README.md pattern
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
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResult {
        let data = data.into();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = sha3_384_hash(&data).await;
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
        let result = sha3_384_hash(&data).await;

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

impl Sha3_512Builder {
    /// Create new SHA3-512 builder
    pub fn new() -> Self {
        Self
    }

    /// Add on_result handler - README.md pattern
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
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResult {
        let data = data.into();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = sha3_512_hash(&data).await;
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
        let result = sha3_512_hash(&data).await;

        // Apply result handler
        handler(result)
    }
}

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

impl Blake2bBuilder {
    /// Create new Blake2b builder
    pub fn new() -> Self {
        Self
    }

    /// Set output size for Blake2b - README.md pattern
    pub fn with_output_size(self, size: usize) -> Blake2bBuilderWithSize {
        Blake2bBuilderWithSize {
            output_size: size.min(64),
        }
    }

    /// Add on_result handler - README.md pattern
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

    /// Add on_error handler - transforms errors but passes through success
    pub fn on_error<E>(self, handler: E) -> Blake2bBuilderWithError<E>
    where
        E: Fn(crate::HashError) -> crate::HashError + Send + Sync + 'static,
    {
        Blake2bBuilderWithError {
            error_handler: handler,
        }
    }

    /// Add on_chunk handler for streaming - README.md pattern
    pub fn on_chunk<C>(self, handler: C) -> Blake2bBuilderWithChunk<C>
    where
        C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        Blake2bBuilderWithChunk {
            chunk_handler: handler,
        }
    }

    /// Compute hash - action takes data as argument per README.md
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResult {
        let data = data.into();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = blake2b_hash(&data).await;
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
        let result = blake2b_hash(&data).await;

        // Apply result handler
        handler(result)
    }
}

impl<E> Blake2bBuilderWithError<E>
where
    E: Fn(crate::HashError) -> crate::HashError + Send + Sync + 'static,
{
    /// Add on_result handler after error handler
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

    /// Compute hash with error handler - returns AsyncHashResultWithError
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResultWithError<E> {
        let data = data.into();
        let error_handler = self.error_handler;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = blake2b_hash(&data).await;
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
    /// Add on_result handler - README.md pattern for Blake2b with custom size
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
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> AsyncHashResult {
        let data = data.into();
        let output_size = self.output_size;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = blake2b_hash_with_size(&data, output_size).await;
            let _ = tx.send(result);
        });

        AsyncHashResult::new(rx)
    }
}

/// Blake2b hash builder with custom size and result handler
pub struct Blake2bBuilderWithSizeAndHandler<F, T> {
    output_size: usize,
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
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
        let result = blake2b_hash_with_size(&data, output_size).await;

        // Apply result handler
        handler(result)
    }
}

// Internal hash functions using true async with channels - NO spawn_blocking!
async fn sha256_hash(data: &[u8]) -> Result<HashResult> {
    let (tx, rx) = oneshot::channel();
    let data = data.to_vec();

    std::thread::spawn(move || {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let result = hasher.finalize();

        let _ = tx.send(Ok(HashResult::new(result.to_vec())));
    });

    rx.await
        .map_err(|_| crate::HashError::internal("Hashing task failed"))?
}

async fn sha3_256_hash(data: &[u8]) -> Result<HashResult> {
    let (tx, rx) = oneshot::channel();
    let data = data.to_vec();

    std::thread::spawn(move || {
        use sha3::{Digest, Sha3_256};

        let mut hasher = Sha3_256::new();
        hasher.update(&data);
        let result = hasher.finalize();

        let _ = tx.send(Ok(HashResult::new(result.to_vec())));
    });

    rx.await
        .map_err(|_| crate::HashError::internal("Hashing task failed"))?
}

async fn blake2b_hash(data: &[u8]) -> Result<HashResult> {
    let (tx, rx) = oneshot::channel();
    let data = data.to_vec();

    std::thread::spawn(move || {
        use blake2::{Blake2b512, Digest};

        let mut hasher = Blake2b512::new();
        hasher.update(&data);
        let result = hasher.finalize();

        let _ = tx.send(Ok(HashResult::new(result.to_vec())));
    });

    rx.await
        .map_err(|_| crate::HashError::internal("Hashing task failed"))?
}

async fn sha256_hmac(data: &[u8], key: &[u8]) -> Result<HashResult> {
    let (tx, rx) = oneshot::channel();
    let data = data.to_vec();
    let key = key.to_vec();

    std::thread::spawn(move || {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mac = HmacSha256::new_from_slice(&key)
            .map_err(|e| crate::HashError::internal(format!("HMAC key error: {}", e)));

        match mac {
            Ok(mut mac) => {
                mac.update(&data);
                let result = mac.finalize().into_bytes();
                let _ = tx.send(Ok(HashResult::new(result.to_vec())));
            }
            Err(e) => {
                let _ = tx.send(Err(e));
            }
        }
    });

    rx.await
        .map_err(|_| crate::HashError::internal("HMAC task failed"))?
}

async fn sha3_384_hash(data: &[u8]) -> Result<HashResult> {
    let (tx, rx) = oneshot::channel();
    let data = data.to_vec();

    std::thread::spawn(move || {
        use sha3::{Digest, Sha3_384};

        let mut hasher = Sha3_384::new();
        hasher.update(&data);
        let result = hasher.finalize();

        let _ = tx.send(Ok(HashResult::new(result.to_vec())));
    });

    rx.await
        .map_err(|_| crate::HashError::internal("Hashing task failed"))?
}

async fn sha3_512_hash(data: &[u8]) -> Result<HashResult> {
    let (tx, rx) = oneshot::channel();
    let data = data.to_vec();

    std::thread::spawn(move || {
        use sha3::{Digest, Sha3_512};

        let mut hasher = Sha3_512::new();
        hasher.update(&data);
        let result = hasher.finalize();

        let _ = tx.send(Ok(HashResult::new(result.to_vec())));
    });

    rx.await
        .map_err(|_| crate::HashError::internal("Hashing task failed"))?
}

async fn blake2b_hash_with_size(data: &[u8], output_size: usize) -> Result<HashResult> {
    let (tx, rx) = oneshot::channel();
    let data = data.to_vec();

    std::thread::spawn(move || {
        use blake2::{Blake2b512, Digest};

        let mut hasher = Blake2b512::new();
        hasher.update(&data);
        let result = hasher.finalize();

        // Truncate to requested size
        let truncated = result[..output_size.min(64)].to_vec();
        let _ = tx.send(Ok(HashResult::new(truncated)));
    });

    rx.await
        .map_err(|_| crate::HashError::internal("Hashing task failed"))?
}
