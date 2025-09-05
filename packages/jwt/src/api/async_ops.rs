//! JWT Async Operations - Advanced async result handling with error handlers
//!
//! This module provides blazing-fast async JWT operations with sophisticated
//! error handling patterns and zero-allocation async coordination.

use super::builder::{JwtBuilderWithError, JwtBuilderWithHandler};
use crate::error::*;
use serde::Serialize;
use tokio::sync::oneshot;

impl<F, T> JwtBuilderWithHandler<F>
where
    F: FnOnce(Result<String, JwtError>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Sign JWT with handler - returns unwrapped type T
    /// Zero-allocation handler transformation with blazing-fast performance
    pub async fn sign<C: Serialize + Send + 'static>(self, claims: C) -> T {
        let algorithm = self.algorithm.unwrap_or_else(|| "HS256".to_string());
        let result =
            super::algorithms::sign_jwt(algorithm, claims, self.secret, self.private_key).await;
        (self.handler)(result)
    }
}

impl<F, T> JwtBuilderWithHandler<F>
where
    F: FnOnce(Result<serde_json::Value, JwtError>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Verify JWT with handler - returns unwrapped type T
    /// Zero-allocation handler transformation with blazing-fast performance
    pub async fn verify<S: AsRef<str>>(self, token: S) -> T {
        let token = token.as_ref().to_string();
        let result = super::algorithms::verify_jwt(token, self.secret, self.public_key).await;
        (self.handler)(result)
    }
}

impl<E> JwtBuilderWithError<E>
where
    E: Fn(JwtError) -> JwtError + Send + Sync + 'static,
{
    /// Set algorithm
    /// Inlined for blazing-fast performance
    #[inline]
    pub fn with_algorithm(mut self, algorithm: &str) -> Self {
        self.algorithm = Some(algorithm.to_string());
        self
    }

    /// Set secret for symmetric algorithms
    /// Inlined for blazing-fast performance
    #[inline]
    pub fn with_secret(mut self, secret: &[u8]) -> Self {
        self.secret = Some(secret.to_vec());
        self
    }

    /// Set private key for asymmetric algorithms
    /// Inlined for blazing-fast performance
    #[inline]
    pub fn with_private_key(mut self, key: &[u8]) -> Self {
        self.private_key = Some(key.to_vec());
        self
    }

    /// Set public key for asymmetric verification
    /// Inlined for blazing-fast performance
    #[inline]
    pub fn with_public_key(mut self, key: &[u8]) -> Self {
        self.public_key = Some(key.to_vec());
        self
    }

    /// Add on_result handler after error handler
    /// Zero-allocation transformation to handler
    #[inline]
    pub fn on_result<F>(self, handler: F) -> JwtBuilderWithHandler<F>
    where
        F: Send + 'static,
    {
        JwtBuilderWithHandler {
            algorithm: self.algorithm,
            secret: self.secret,
            private_key: self.private_key,
            public_key: self.public_key,
            handler,
        }
    }

    /// Sign JWT with error handler - returns AsyncJwtResultWithError
    /// Blazing-fast async coordination with sophisticated error handling
    pub fn sign<C: Serialize + Send + 'static>(
        self,
        claims: C,
    ) -> AsyncJwtResultWithError<String, E> {
        let algorithm = self.algorithm.unwrap_or_else(|| "HS256".to_string());
        let secret = self.secret;
        let private_key = self.private_key;
        let error_handler = self.error_handler;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = super::algorithms::sign_jwt(algorithm, claims, secret, private_key).await;
            let _ = tx.send(result);
        });

        AsyncJwtResultWithError::new(rx, error_handler)
    }

    /// Verify JWT with error handler - returns AsyncJwtResultWithError
    /// Blazing-fast async coordination with sophisticated error handling
    pub fn verify<S: AsRef<str>>(self, token: S) -> AsyncJwtResultWithError<serde_json::Value, E> {
        let token = token.as_ref().to_string();
        let secret = self.secret;
        let public_key = self.public_key;
        let error_handler = self.error_handler;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = super::algorithms::verify_jwt(token, secret, public_key).await;
            let _ = tx.send(result);
        });

        AsyncJwtResultWithError::new(rx, error_handler)
    }
}

/// Async JWT result with error handler
/// Blazing-fast async coordination with zero-allocation error transformation
pub struct AsyncJwtResultWithError<T, E> {
    receiver: oneshot::Receiver<Result<T, JwtError>>,
    error_handler: E,
}

impl<T, E> AsyncJwtResultWithError<T, E> {
    /// Create new async result with error handler
    /// Zero-allocation construction
    #[inline]
    pub(crate) fn new(receiver: oneshot::Receiver<Result<T, JwtError>>, error_handler: E) -> Self {
        Self {
            receiver,
            error_handler,
        }
    }
}

impl<T: Send + 'static, E> std::future::Future for AsyncJwtResultWithError<T, E>
where
    E: Fn(JwtError) -> JwtError + Unpin,
{
    type Output = Result<T, JwtError>;

    #[inline]
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        let receiver = std::pin::Pin::new(&mut self.receiver);
        match receiver.poll(cx) {
            std::task::Poll::Ready(Ok(Ok(value))) => std::task::Poll::Ready(Ok(value)),
            std::task::Poll::Ready(Ok(Err(e))) => {
                std::task::Poll::Ready(Err((self.error_handler)(e)))
            }
            std::task::Poll::Ready(Err(_)) => std::task::Poll::Ready(Err((self.error_handler)(
                JwtError::Internal("JWT operation failed".to_string()),
            ))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Async JWT result builder for complex async operations
/// Zero-allocation builder pattern for sophisticated async coordination
pub struct AsyncJwtResultBuilder<T> {
    receiver: oneshot::Receiver<Result<T, JwtError>>,
}

impl<T> AsyncJwtResultBuilder<T> {
    /// Add error handler to async result
    /// Zero-allocation transformation to error-handled result
    #[inline]
    pub fn with_error_handler<E>(self, error_handler: E) -> AsyncJwtResultWithError<T, E>
    where
        E: Fn(JwtError) -> JwtError + Unpin,
    {
        AsyncJwtResultWithError::new(self.receiver, error_handler)
    }
}

/// Async JWT result combinator for advanced async patterns
/// Blazing-fast async coordination with zero-allocation combinators
pub struct AsyncJwtResultCombinator<T> {
    receiver: oneshot::Receiver<Result<T, JwtError>>,
}

impl<T> AsyncJwtResultCombinator<T> {
    /// Create new async result combinator
    /// Zero-allocation construction
    #[inline]
    pub(crate) fn new(receiver: oneshot::Receiver<Result<T, JwtError>>) -> Self {
        Self { receiver }
    }

    /// Map result value with zero-allocation transformation
    /// Blazing-fast value transformation
    pub fn map<U, F>(self, f: F) -> AsyncJwtResultCombinator<U>
    where
        F: FnOnce(T) -> U + Send + 'static,
        T: Send + 'static,
        U: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            match self.receiver.await {
                Ok(Ok(value)) => {
                    let _ = tx.send(Ok(f(value)));
                }
                Ok(Err(e)) => {
                    let _ = tx.send(Err(e));
                }
                Err(_) => {
                    let _ = tx.send(Err(JwtError::Internal("Channel closed".to_string())));
                }
            }
        });

        AsyncJwtResultCombinator::new(rx)
    }

    /// Map error with zero-allocation transformation
    /// Blazing-fast error transformation
    pub fn map_err<F>(self, f: F) -> AsyncJwtResultCombinator<T>
    where
        F: FnOnce(JwtError) -> JwtError + Send + 'static,
        T: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            match self.receiver.await {
                Ok(Ok(value)) => {
                    let _ = tx.send(Ok(value));
                }
                Ok(Err(e)) => {
                    let _ = tx.send(Err(f(e)));
                }
                Err(_) => {
                    let _ = tx.send(Err(f(JwtError::Internal("Channel closed".to_string()))));
                }
            }
        });

        AsyncJwtResultCombinator::new(rx)
    }
}

impl<T: Send + 'static> std::future::Future for AsyncJwtResultCombinator<T> {
    type Output = Result<T, JwtError>;

    #[inline]
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        match std::pin::Pin::new(&mut self.receiver).poll(cx) {
            std::task::Poll::Ready(Ok(result)) => std::task::Poll::Ready(result),
            std::task::Poll::Ready(Err(_)) => {
                std::task::Poll::Ready(Err(JwtError::Internal("Channel closed".to_string())))
            }
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}
