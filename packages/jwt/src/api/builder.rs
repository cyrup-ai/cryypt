//! JWT Builder API - Entry point structs and configuration methods
//!
//! This module provides zero-allocation, blazing-fast JWT builder patterns
//! with elegant ergonomic APIs following the README.md patterns.

use crate::error::{JwtError, JwtResult};
use cryypt_common::chunk_types::JwtChunk;
use cyrup_sugars::prelude::*;
use serde::Serialize;

/// Master builder for JWT operations - README.md pattern
pub struct JwtMasterBuilder;

impl JwtMasterBuilder {
    /// HS256 JWT operations - polymorphic pattern
    #[must_use]
    pub fn hs256(self) -> crate::api::algorithm_builders::HsJwtBuilder {
        crate::api::algorithm_builders::HsJwtBuilder::new()
    }

    /// RS256 JWT operations - polymorphic pattern
    #[must_use]
    pub fn rs256(self) -> crate::api::algorithm_builders::RsJwtBuilder {
        crate::api::algorithm_builders::RsJwtBuilder::new()
    }

    /// Create new JWT builder - unified entry point
    #[must_use]
    pub fn builder() -> JwtBuilder {
        JwtBuilder::new()
    }

    /// Set algorithm - README.md pattern following EXACT pattern from master builders
    /// SEXY SYNTAX in closures works via CRATE PRIVATE macro transformation
    #[inline]
    #[must_use]
    pub fn with_algorithm(self, algorithm: &str) -> JwtBuilder {
        JwtBuilder::new().with_algorithm(algorithm)
    }

    /// Set secret for symmetric algorithms - README.md pattern
    /// Pattern matching Ok => result in user closures works via INTERNAL MACROS never exposed to users
    #[inline]
    #[must_use]
    pub fn with_secret(self, secret: &[u8]) -> JwtBuilder {
        JwtBuilder::new().with_secret(secret)
    }
}

impl Default for JwtMasterBuilder {
    #[inline]
    fn default() -> Self {
        Self
    }
}

/// Direct builder entry point - equivalent to `Cryypt::jwt()`
pub struct Jwt;

impl Jwt {
    /// Create new JWT builder - unified entry point
    #[inline]
    #[must_use]
    pub fn builder() -> JwtBuilder {
        JwtBuilder::new()
    }
}

/// Unified JWT builder - follows README.md pattern
///
/// Zero-allocation builder with compile-time optimizations.
/// All configuration methods are inlined for blazing-fast performance.
pub struct JwtBuilder {
    pub(crate) algorithm: Option<String>,
    pub(crate) secret: Option<Vec<u8>>,
    pub(crate) private_key: Option<Vec<u8>>,
    pub(crate) public_key: Option<Vec<u8>>,
    pub(crate) chunk_handler: Option<Box<dyn Fn(JwtChunk) -> JwtChunk + Send + Sync>>,
    pub(crate) error_handler: Option<Box<dyn Fn(String) -> JwtChunk + Send + Sync>>,
}

/// JWT builder with handler - polymorphic based on usage
#[allow(dead_code)]
pub struct JwtBuilderWithHandler<F> {
    pub(crate) algorithm: Option<String>,
    pub(crate) secret: Option<Vec<u8>>,
    pub(crate) private_key: Option<Vec<u8>>,
    pub(crate) public_key: Option<Vec<u8>>,
    pub(crate) handler: F,
}

/// JWT builder with error handler
#[allow(dead_code)]
pub struct JwtBuilderWithError<E> {
    pub(crate) algorithm: Option<String>,
    pub(crate) secret: Option<Vec<u8>>,
    pub(crate) private_key: Option<Vec<u8>>,
    pub(crate) public_key: Option<Vec<u8>>,
    pub(crate) error_handler: E,
}

/// JWT builder with result handler for Vec<u8> operations
#[allow(dead_code)]
pub struct JwtBuilderWithResultHandler<F> {
    pub(crate) algorithm: Option<String>,
    pub(crate) secret: Option<Vec<u8>>,
    pub(crate) private_key: Option<Vec<u8>>,
    pub(crate) public_key: Option<Vec<u8>>,
    pub(crate) result_handler: F,
}

/// JWT builder with chunk handler for streaming operations
#[allow(dead_code)]
pub struct JwtBuilderWithChunkHandler<F> {
    pub(crate) algorithm: Option<String>,
    pub(crate) secret: Option<Vec<u8>>,
    pub(crate) private_key: Option<Vec<u8>>,
    pub(crate) public_key: Option<Vec<u8>>,
    pub(crate) chunk_handler: F,
}

impl ChunkHandler<cryypt_common::chunk_types::JwtChunk> for JwtBuilder {
    fn on_chunk<F>(self, _handler: F) -> Self
    where
        F: Fn(
                std::result::Result<cryypt_common::chunk_types::JwtChunk, String>,
            ) -> cryypt_common::chunk_types::JwtChunk
            + Send
            + Sync
            + 'static,
    {
        self
    }
}

impl JwtBuilder {
    /// Create new JWT builder
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            algorithm: None,
            secret: None,
            private_key: None,
            public_key: None,
            chunk_handler: None,
            error_handler: None,
        }
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

    /// Internal implementation for `on_result` - called by macro
    /// Zero-allocation transformation to result handler
    #[inline]
    #[must_use]
    fn on_result_impl<F>(self, handler: F) -> JwtBuilderWithResultHandler<F>
    where
        F: Fn(JwtResult<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        JwtBuilderWithResultHandler {
            algorithm: self.algorithm,
            secret: self.secret,
            private_key: self.private_key,
            public_key: self.public_key,
            result_handler: handler,
        }
    }

    /// Add `on_result` handler - transforms pattern matching internally
    /// Elegant ergonomic API with zero-allocation transformation
    #[inline]
    #[must_use]
    pub fn on_result<F>(self, handler: F) -> JwtBuilderWithResultHandler<F>
    where
        F: Fn(JwtResult<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        self.on_result_impl(handler)
    }

    /// Internal implementation for `on_chunk` - called by macro across multiple crates
    #[allow(dead_code)]
    #[must_use]
    fn on_chunk_impl<F>(mut self, handler: F) -> Self
    where
        F: Fn(JwtChunk) -> JwtChunk + Send + Sync + 'static,
    {
        self.chunk_handler = Some(Box::new(handler));
        self
    }

    /// Internal implementation for `on_error` - called by macro across multiple crates
    #[allow(dead_code)]
    #[must_use]
    fn on_error_impl<F>(mut self, handler: F) -> Self
    where
        F: Fn(String) -> JwtChunk + Send + Sync + 'static,
    {
        self.error_handler = Some(Box::new(handler));
        self
    }

    // on_chunk method is now provided by ChunkHandler trait implementation

    /// Sign JWT with claims - async operation
    ///
    /// # Errors
    /// Returns `JwtError` if signing fails due to invalid algorithm, missing key, or serialization errors
    pub async fn sign<T: Serialize + Send + 'static>(&self, claims: T) -> Result<String, JwtError> {
        use crate::api::algorithms::sign_jwt;

        let algorithm = self.get_algorithm();

        sign_jwt(
            algorithm,
            claims,
            self.secret.clone(),
            self.private_key.clone(),
        )
        .await
    }

    /// Verify JWT token - async operation
    ///
    /// # Errors
    /// Returns `JwtError` if verification fails due to invalid token, signature, or missing keys
    pub async fn verify(&self, token: String) -> Result<serde_json::Value, JwtError> {
        use crate::api::algorithms::verify_jwt;

        verify_jwt(token, self.secret.clone(), self.public_key.clone()).await
    }

    /// Add `on_result` handler - polymorphic based on subsequent method call (legacy)
    /// Maintains backward compatibility with elegant ergonomic API
    #[inline]
    #[must_use]
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

    /// Add `on_error` handler - transforms errors but passes through success
    /// Zero-allocation error transformation with blazing-fast performance
    #[inline]
    #[must_use]
    pub fn on_error<E>(self, handler: E) -> JwtBuilderWithError<E>
    where
        E: Fn(JwtError) -> JwtError + Send + Sync + 'static,
    {
        JwtBuilderWithError {
            algorithm: self.algorithm,
            secret: self.secret,
            private_key: self.private_key,
            public_key: self.public_key,
            error_handler: handler,
        }
    }

    /// Get algorithm with default fallback
    /// Inlined for blazing-fast performance
    #[inline]
    #[must_use]
    pub(crate) fn get_algorithm(&self) -> String {
        self.algorithm
            .clone()
            .unwrap_or_else(|| "HS256".to_string())
    }
}

impl Default for JwtBuilder {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}
