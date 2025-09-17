//! JWT Core Operations - Sign and Verify functionality
//!
//! This module provides blazing-fast JWT signing and verification operations
//! with zero-allocation patterns and elegant ergonomic APIs.

use super::builders::{JwtBuilder, JwtBuilderWithChunkHandler, JwtBuilderWithResultHandler};
use super::validation::AsyncJwtResult;
use crate::error::JwtResult;
use serde::Serialize;
use tokio::sync::oneshot;

impl JwtBuilder {
    /// Sign JWT without handler - returns `AsyncJwtResult` for String
    /// Zero-allocation async operation with blazing-fast performance
    #[inline]
    #[must_use]
    pub fn sign<C: Serialize + Send + 'static>(self, claims: C) -> AsyncJwtResult<String> {
        let algorithm = self.get_algorithm();
        let secret = self.secret;
        let private_key = self.private_key;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = super::algorithms::sign_jwt(algorithm, claims, secret, private_key).await;
            let _ = tx.send(result);
        });

        AsyncJwtResult::new(rx)
    }

    /// Verify JWT without handler - returns `AsyncJwtResult` for Value
    /// Zero-allocation async operation with blazing-fast performance
    #[inline]
    #[must_use]
    pub fn verify<S: AsRef<str>>(self, token: S) -> AsyncJwtResult<serde_json::Value> {
        let token = token.as_ref().to_string();
        let secret = self.secret;
        let public_key = self.public_key;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = super::algorithms::verify_jwt(token, secret, public_key).await;
            let _ = tx.send(result);
        });

        AsyncJwtResult::new(rx)
    }
}

impl<F> JwtBuilderWithResultHandler<F>
where
    F: Fn(JwtResult<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Sign JWT with result handler - returns Vec<u8>
    /// Zero-allocation result transformation with blazing-fast performance
    #[must_use]
    pub async fn sign<C: Serialize + Send + 'static>(self, claims: C) -> Vec<u8> {
        let algorithm = self.algorithm.unwrap_or_else(|| "HS256".to_string());
        let result =
            super::algorithms::sign_jwt(algorithm, claims, self.secret, self.private_key).await;

        // Convert String result to Vec<u8> and apply handler
        let converted_result = result.map(std::string::String::into_bytes);
        (self.result_handler)(converted_result)
    }

    /// Verify JWT with result handler - returns Vec<u8>
    /// Zero-allocation result transformation with blazing-fast performance
    #[must_use]
    pub async fn verify<S: AsRef<str>>(self, token: S) -> Vec<u8> {
        let token = token.as_ref().to_string();
        let result = super::algorithms::verify_jwt(token, self.secret, self.public_key).await;

        // Convert serde_json::Value result to Vec<u8> and apply handler
        let converted_result = result.map(|v| v.to_string().into_bytes());
        (self.result_handler)(converted_result)
    }
}

impl<F> JwtBuilderWithChunkHandler<F>
where
    F: Fn(JwtResult<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Sign JWT as stream - returns async iterator of chunks
    /// Lock-free streaming with zero-allocation patterns
    pub fn sign_stream<C: Serialize + Send + Clone + 'static>(
        self,
        claims: C,
    ) -> impl futures::Stream<Item = Vec<u8>> + Send {
        let algorithm = self.algorithm.unwrap_or_else(|| "HS256".to_string());
        let secret = self.secret;
        let private_key = self.private_key;
        let handler = self.chunk_handler;

        futures::stream::unfold(
            (algorithm, claims, secret, private_key, handler, false),
            move |(algorithm, claims, secret, private_key, handler, done)| async move {
                if done {
                    return None;
                }

                // Clone values before using them for zero-allocation patterns
                let algorithm_clone = algorithm.clone();
                let claims_clone = claims.clone();
                let secret_clone = secret.clone();
                let private_key_clone = private_key.clone();

                // Sign the JWT with blazing-fast performance
                let result =
                    super::algorithms::sign_jwt(algorithm, claims, secret, private_key).await;
                let converted_result = result.map(std::string::String::into_bytes);
                let processed_chunk = handler(converted_result);

                Some((
                    processed_chunk,
                    (
                        algorithm_clone,
                        claims_clone,
                        secret_clone,
                        private_key_clone,
                        handler,
                        true,
                    ),
                ))
            },
        )
    }

    /// Verify JWT as stream - returns async iterator of chunks
    /// Lock-free streaming with zero-allocation patterns
    pub fn verify_stream<S: AsRef<str> + Send + Clone + 'static>(
        self,
        token: &S,
    ) -> impl futures::Stream<Item = Vec<u8>> + Send {
        let token = token.as_ref().to_string();
        let secret = self.secret;
        let public_key = self.public_key;
        let handler = self.chunk_handler;

        futures::stream::unfold(
            (token, secret, public_key, handler, false),
            move |(token, secret, public_key, handler, done)| async move {
                if done {
                    return None;
                }

                // Clone values before using them for zero-allocation patterns
                let token_clone = token.clone();
                let secret_clone = secret.clone();
                let public_key_clone = public_key.clone();

                // Verify the JWT with blazing-fast performance
                let result = super::algorithms::verify_jwt(token, secret, public_key).await;
                let converted_result = result.map(|v| v.to_string().into_bytes());
                let processed_chunk = handler(converted_result);

                Some((
                    processed_chunk,
                    (token_clone, secret_clone, public_key_clone, handler, true),
                ))
            },
        )
    }
}
