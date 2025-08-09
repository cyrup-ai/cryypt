//! SHA-256 hash builders following README.md patterns exactly

use crate::{HashError, Result};
use tokio::sync::oneshot;

// Declare submodules
pub mod compute;
pub mod stream;

/// Initial SHA256 builder - entry point
pub struct Sha256Builder;

/// SHA256 builder with result handler
pub struct Sha256WithHandler<F, T> {
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

/// SHA256 builder with key (for HMAC)
pub struct Sha256WithKey {
    key: Vec<u8>,
}

/// SHA256 builder with key and result handler
pub struct Sha256WithKeyAndHandler<F, T> {
    key: Vec<u8>,
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

/// SHA256 builder with result handler for universal macro support
pub struct Sha256BuilderWithResultHandler<F> {
    result_handler: F,
}

/// SHA256 builder with chunk handler for universal macro support
pub struct Sha256BuilderWithChunkHandler<F> {
    chunk_handler: F,
}

impl Sha256Builder {
    /// Create new SHA256 builder
    pub fn new() -> Self {
        Self
    }

    /// Internal implementation for on_result - called by macro
    fn on_result_impl<F>(self, handler: F) -> Sha256BuilderWithResultHandler<F>
    where
        F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        Sha256BuilderWithResultHandler {
            result_handler: handler,
        }
    }

    /// Internal implementation for on_chunk - called by macro
    fn on_chunk_impl<F>(self, handler: F) -> Sha256BuilderWithChunkHandler<F>
    where
        F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        Sha256BuilderWithChunkHandler {
            chunk_handler: handler,
        }
    }

    /// Add on_result handler - transforms pattern matching internally
    pub fn on_result<F>(self, handler: F) -> Sha256BuilderWithResultHandler<F>
    where
        F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        Sha256BuilderWithResultHandler {
            result_handler: handler,
        }
    }

    /// Add on_chunk handler - transforms pattern matching internally
    pub fn on_chunk<F>(self, handler: F) -> Sha256BuilderWithChunkHandler<F>
    where
        F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        Sha256BuilderWithChunkHandler {
            chunk_handler: handler,
        }
    }

    /// Add on_result handler - README.md pattern (legacy)
    pub fn on_result_legacy<F, T>(self, handler: F) -> Sha256WithHandler<F, T>
    where
        F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        Sha256WithHandler {
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Add key for HMAC operations
    pub fn with_key<T: Into<Vec<u8>>>(self, key: T) -> Sha256WithKey {
        Sha256WithKey::new(key.into())
    }

    /// Compute hash without handler - returns Result
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> Sha256Result {
        let data = data.into();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = sha256_hash(&data).await;
            let _ = tx.send(result);
        });

        Sha256Result::new(rx)
    }
}

impl Sha256WithKey {
    /// Create SHA256 builder with key
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    /// Add on_result handler - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> Sha256WithKeyAndHandler<F, T>
    where
        F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        Sha256WithKeyAndHandler {
            key: self.key,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Compute HMAC without handler - returns Result
    pub fn compute<T: Into<Vec<u8>>>(self, data: T) -> Sha256Result {
        let data = data.into();
        let key = self.key;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = sha256_hmac(&key, &data).await;
            let _ = tx.send(result);
        });

        Sha256Result::new(rx)
    }
}

impl<F, T> Sha256WithHandler<F, T>
where
    F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
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

impl<F, T> Sha256WithKeyAndHandler<F, T>
where
    F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Compute HMAC - action takes data as argument per README.md
    pub async fn compute<D: Into<Vec<u8>>>(self, data: D) -> T {
        let data = data.into();
        let key = self.key;
        let handler = self.result_handler;

        // Perform SHA-256 HMAC
        let result = sha256_hmac(&key, &data).await;

        // Apply result handler
        handler(result)
    }
}

impl<F> Sha256BuilderWithResultHandler<F>
where
    F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Compute hash with result handler - returns Vec<u8>
    pub async fn compute<D: Into<Vec<u8>>>(self, data: D) -> Vec<u8> {
        let data = data.into();
        let handler = self.result_handler;

        // Perform SHA-256 hashing
        let result = sha256_hash(&data).await;

        // Apply result handler
        handler(result)
    }
}

impl<F> Sha256BuilderWithChunkHandler<F>
where
    F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Compute hash as stream - returns async iterator of chunks
    pub fn compute_stream<D: Into<Vec<u8>>>(
        self,
        data: D,
    ) -> impl futures::Stream<Item = Vec<u8>> + Send {
        let data = data.into();
        let handler = self.chunk_handler;

        futures::stream::unfold((data, handler, false), 
            move |(data, handler, done)| async move {
                if done {
                    return None;
                }

                // Compute the hash
                let result = sha256_hash(&data).await;
                let processed_chunk = handler(result);

                Some((processed_chunk, (data, handler, true)))
            })
    }
}

/// Result type for SHA256 operations
pub struct Sha256Result {
    receiver: oneshot::Receiver<Result<Vec<u8>>>,
}

impl Sha256Result {
    pub(crate) fn new(receiver: oneshot::Receiver<Result<Vec<u8>>>) -> Self {
        Self { receiver }
    }
}

impl std::future::Future for Sha256Result {
    type Output = Result<Vec<u8>>;

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        use std::pin::Pin;
        match Pin::new(&mut self.receiver).poll(cx) {
            std::task::Poll::Ready(Ok(result)) => std::task::Poll::Ready(result),
            std::task::Poll::Ready(Err(_)) => {
                std::task::Poll::Ready(Err(HashError::internal("Channel closed".to_string())))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

// Internal hashing function using true async
async fn sha256_hash(data: &[u8]) -> Result<Vec<u8>> {
    let data = data.to_vec();

    tokio::task::spawn_blocking(move || {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&data);
        let result = hasher.finalize();

        Ok(result.to_vec())
    })
    .await
    .map_err(|e| HashError::internal(e.to_string()))?
}

// Internal HMAC function using true async
async fn sha256_hmac(key: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    let key = key.to_vec();
    let data = data.to_vec();

    tokio::task::spawn_blocking(move || {
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        type HmacSha256 = Hmac<Sha256>;

        let mut mac = HmacSha256::new_from_slice(&key)
            .map_err(|e| HashError::internal(format!("HMAC key error: {}", e)))?;
        mac.update(&data);

        Ok(mac.finalize().into_bytes().to_vec())
    })
    .await
    .map_err(|e| HashError::internal(e.to_string()))?
}
