//! JWT builder types and implementations
//!
//! Contains all builder structs and their implementations following README.md patterns.

use super::validation::AsyncJwtResultWithError;
use crate::api::algorithms::{sign_jwt, verify_jwt};
use crate::error::JwtError;
use serde::Serialize;
use tokio::sync::oneshot;

/// Master builder for JWT operations - README.md pattern
pub struct JwtMasterBuilder;

impl JwtMasterBuilder {
    /// Create new JWT builder - unified entry point
    #[must_use]
    pub fn builder() -> JwtBuilder {
        JwtBuilder::new()
    }

    /// Set algorithm - README.md pattern following EXACT pattern from master builders
    #[inline]
    #[must_use]
    pub fn with_algorithm(self, algorithm: &str) -> JwtBuilder {
        JwtBuilder::new().with_algorithm(algorithm)
    }

    /// Set secret for symmetric algorithms - README.md pattern
    #[inline]
    #[must_use]
    pub fn with_secret(self, secret: &[u8]) -> JwtBuilder {
        JwtBuilder::new().with_secret(secret)
    }
}

/// Direct builder entry point - equivalent to `Cryypt::jwt()`
pub struct Jwt;

impl Jwt {
    /// Create new JWT builder - unified entry point
    #[must_use]
    pub fn builder() -> JwtBuilder {
        JwtBuilder::new()
    }
}

/// Unified JWT builder - follows README.md pattern
pub struct JwtBuilder {
    pub(crate) algorithm: Option<String>,
    pub(crate) secret: Option<Vec<u8>>,
    pub(crate) private_key: Option<Vec<u8>>,
    pub(crate) public_key: Option<Vec<u8>>,
}

/// JWT builder with handler - polymorphic based on usage
pub struct JwtBuilderWithHandler<F> {
    algorithm: Option<String>,
    secret: Option<Vec<u8>>,
    private_key: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    handler: F,
}

/// JWT builder with error handler
pub struct JwtBuilderWithError<E> {
    algorithm: Option<String>,
    secret: Option<Vec<u8>>,
    private_key: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    error_handler: E,
}

/// JWT builder with result handler for Vec<u8> operations
pub struct JwtBuilderWithResultHandler<F> {
    pub(crate) algorithm: Option<String>,
    pub(crate) secret: Option<Vec<u8>>,
    pub(crate) private_key: Option<Vec<u8>>,
    pub(crate) public_key: Option<Vec<u8>>,
    pub(crate) result_handler: F,
}

/// JWT builder with chunk handler for streaming operations
pub struct JwtBuilderWithChunkHandler<F> {
    pub(crate) algorithm: Option<String>,
    pub(crate) secret: Option<Vec<u8>>,
    pub(crate) private_key: Option<Vec<u8>>,
    pub(crate) public_key: Option<Vec<u8>>,
    pub(crate) chunk_handler: F,
}

impl Default for JwtBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl JwtBuilder {
    /// Create new JWT builder
    #[must_use]
    pub fn new() -> Self {
        Self {
            algorithm: None,
            secret: None,
            private_key: None,
            public_key: None,
        }
    }

    /// Get the algorithm (default to HS256 if not set)
    #[must_use]
    pub fn get_algorithm(&self) -> String {
        self.algorithm
            .clone()
            .unwrap_or_else(|| "HS256".to_string())
    }

    /// Set algorithm - README.md pattern
    #[inline]
    #[must_use]
    pub fn with_algorithm(mut self, algorithm: &str) -> Self {
        self.algorithm = Some(algorithm.to_string());
        self
    }

    /// Set secret for symmetric algorithms - README.md pattern
    #[inline]
    #[must_use]
    pub fn with_secret(mut self, secret: &[u8]) -> Self {
        self.secret = Some(secret.to_vec());
        self
    }

    /// Set private key for asymmetric algorithms - README.md pattern
    #[inline]
    #[must_use]
    pub fn with_private_key(mut self, key: &[u8]) -> Self {
        self.private_key = Some(key.to_vec());
        self
    }

    /// Set public key for asymmetric verification - README.md pattern
    #[inline]
    #[must_use]
    pub fn with_public_key(mut self, key: &[u8]) -> Self {
        self.public_key = Some(key.to_vec());
        self
    }

    /// Add `on_result` handler - polymorphic based on subsequent method call (legacy)
    pub fn on_result_legacy<F>(self, handler: F) -> JwtBuilderWithHandler<F>
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
}

// ChunkHandler implementation moved to api/builder.rs to avoid duplicates

impl<F, T> JwtBuilderWithHandler<F>
where
    F: FnOnce(Result<String, JwtError>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Sign JWT with handler - returns unwrapped type T
    pub async fn sign<C: Serialize + Send + 'static>(self, claims: C) -> T {
        let algorithm = self.algorithm.unwrap_or_else(|| "HS256".to_string());
        let result = sign_jwt(algorithm, claims, self.secret, self.private_key).await;
        (self.handler)(result)
    }
}

impl<F, T> JwtBuilderWithHandler<F>
where
    F: FnOnce(Result<serde_json::Value, JwtError>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Verify JWT with handler - returns unwrapped type T
    pub async fn verify<S: AsRef<str>>(self, token: S) -> T {
        let token = token.as_ref().to_string();
        let result = verify_jwt(token, self.secret, self.public_key).await;
        (self.handler)(result)
    }
}

impl<E> JwtBuilderWithError<E>
where
    E: Fn(JwtError) -> JwtError + Send + Sync + 'static,
{
    /// Set algorithm
    #[inline]
    #[must_use]
    pub fn with_algorithm(mut self, algorithm: &str) -> Self {
        self.algorithm = Some(algorithm.to_string());
        self
    }

    /// Set secret for symmetric algorithms
    #[inline]
    #[must_use]
    pub fn with_secret(mut self, secret: &[u8]) -> Self {
        self.secret = Some(secret.to_vec());
        self
    }

    /// Set private key for asymmetric algorithms
    #[inline]
    #[must_use]
    pub fn with_private_key(mut self, key: &[u8]) -> Self {
        self.private_key = Some(key.to_vec());
        self
    }

    /// Set public key for asymmetric verification
    #[inline]
    #[must_use]
    pub fn with_public_key(mut self, key: &[u8]) -> Self {
        self.public_key = Some(key.to_vec());
        self
    }

    /// Add `on_result` handler after error handler
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

    /// Sign JWT with error handler - returns `AsyncJwtResult`
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
            let result = sign_jwt(algorithm, claims, secret, private_key).await;
            let _ = tx.send(result);
        });

        AsyncJwtResultWithError::new(rx, error_handler)
    }

    /// Verify JWT with error handler - returns `AsyncJwtResult`
    pub fn verify<S: AsRef<str>>(self, token: S) -> AsyncJwtResultWithError<serde_json::Value, E> {
        let token = token.as_ref().to_string();
        let secret = self.secret;
        let public_key = self.public_key;
        let error_handler = self.error_handler;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = verify_jwt(token, secret, public_key).await;
            let _ = tx.send(result);
        });

        AsyncJwtResultWithError::new(rx, error_handler)
    }
}
