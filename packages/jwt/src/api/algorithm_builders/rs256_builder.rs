//! RS256 JWT Builder - Polymorphic pattern for RSA-SHA256 JWT operations
//!
//! Provides polymorphic builder pattern for RS256 JWT signing with both single-result
//! and batch operations.

// Removed unused imports after fixing redundant field names
use crate::api::algorithms::rsa::sign_rs256;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::Stream;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// RS256 JWT builder - initial state
#[derive(Debug, Clone)]
pub struct RsJwtBuilder;

/// RS256 JWT builder with private key configured
#[derive(Debug, Clone)]
pub struct RsJwtWithPrivateKey {
    private_key: Vec<u8>,
}

/// RS256 JWT builder with private key and claims configured
#[derive(Debug, Clone)]
pub struct RsJwtWithPrivateKeyAndClaims<T> {
    private_key: Vec<u8>,
    claims: T,
}

/// RS256 JWT builder with private key, claims and result handler
#[derive(Debug)]
pub struct RsJwtWithPrivateKeyAndClaimsAndHandler<T, F> {
    private_key: Vec<u8>,
    claims: T,
    handler: F,
}

/// RS256 JWT builder with private key, claims and chunk handler for batch operations
#[derive(Debug)]
pub struct RsJwtWithPrivateKeyAndClaimsAndChunkHandler<T, F> {
    private_key: Vec<u8>,
    #[allow(dead_code)]
    claims: T,
    handler: F,
}

impl Default for RsJwtBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RsJwtBuilder {
    /// Create new RS256 JWT builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Set RSA private key for RS256 signing
    #[must_use]
    pub fn with_private_key(self, private_key: &[u8]) -> RsJwtWithPrivateKey {
        RsJwtWithPrivateKey {
            private_key: private_key.to_vec(),
        }
    }
}

impl RsJwtWithPrivateKey {
    /// Set claims for JWT
    #[must_use]
    pub fn with_claims<T: Serialize + Clone>(self, claims: T) -> RsJwtWithPrivateKeyAndClaims<T> {
        RsJwtWithPrivateKeyAndClaims {
            private_key: self.private_key,
            claims,
        }
    }
}

impl<T: Serialize + Clone> RsJwtWithPrivateKeyAndClaims<T> {
    /// Set result handler for single JWT signing
    #[must_use]
    pub fn on_result<F, R>(self, handler: F) -> RsJwtWithPrivateKeyAndClaimsAndHandler<T, F>
    where
        F: FnOnce(crate::error::JwtResult<Vec<u8>>) -> R,
        R: cryypt_common::NotResult,
    {
        RsJwtWithPrivateKeyAndClaimsAndHandler {
            private_key: self.private_key,
            claims: self.claims,
            handler,
        }
    }

    /// Set chunk handler for batch JWT signing
    #[must_use]
    pub fn on_chunk<F>(self, handler: F) -> RsJwtWithPrivateKeyAndClaimsAndChunkHandler<T, F>
    where
        F: Fn(crate::error::JwtResult<Vec<u8>>) -> Vec<u8>,
    {
        RsJwtWithPrivateKeyAndClaimsAndChunkHandler {
            private_key: self.private_key,
            claims: self.claims,
            handler,
        }
    }
}

impl<T, F, R> RsJwtWithPrivateKeyAndClaimsAndHandler<T, F>
where
    T: Serialize + Clone + Send + 'static,
    F: FnOnce(crate::error::JwtResult<Vec<u8>>) -> R + Send + 'static,
    R: cryypt_common::NotResult + Send + 'static,
{
    /// Sign single JWT with RS256
    #[must_use]
    pub async fn sign(self) -> R {
        let result = async {
            // Yield control to allow other tasks to run
            tokio::task::yield_now().await;

            // Sign JWT with RS256 using production RSA-SHA256 implementation
            let jwt_token = sign_rs256_jwt(&self.claims, &self.private_key)?;
            Ok(jwt_token.into_bytes())
        }
        .await;

        // Apply result handler
        (self.handler)(result)
    }
}

impl<T, F> RsJwtWithPrivateKeyAndClaimsAndChunkHandler<T, F>
where
    T: Serialize + Clone + Send + Sync + 'static,
    F: Fn(crate::error::JwtResult<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Sign batch of JWTs with different claims
    pub fn sign_batch(self, claims_list: Vec<T>) -> impl Stream<Item = Vec<u8>> {
        let (tx, rx) = mpsc::channel(32);
        let private_key = self.private_key;
        let handler = self.handler;

        tokio::spawn(async move {
            for (i, claims) in claims_list.into_iter().enumerate() {
                // Yield control to allow other tasks to run
                tokio::task::yield_now().await;

                // Sign individual JWT
                let result = async {
                    let jwt_token = sign_rs256_jwt(&claims, &private_key)?;
                    Ok(jwt_token.into_bytes())
                }
                .await;

                // Apply handler and send result
                let processed_jwt = handler(result);

                if tx.send(processed_jwt).await.is_err() {
                    break; // Receiver dropped
                }

                // Progress tracking for batch operations (RSA signing is slower)
                if (i + 1) % 5 == 0 {
                    // Could add logging here if needed
                }
            }
        });

        ReceiverStream::new(rx)
    }
}

/// Production RS256 JWT signing implementation using real RSA
fn sign_rs256_jwt<T: Serialize>(claims: &T, private_key: &[u8]) -> crate::error::JwtResult<String> {
    // Create header
    let header = serde_json::json!({
        "alg": "RS256",
        "typ": "JWT"
    });

    // Serialize claims
    let claims_json = serde_json::to_value(claims)
        .map_err(|e| crate::error::JwtError::InvalidToken(e.to_string()))?;

    // Base64 encode header and claims using real base64 library
    let header_bytes = serde_json::to_vec(&header)
        .map_err(|e| crate::error::JwtError::InvalidToken(e.to_string()))?;
    let claims_bytes = serde_json::to_vec(&claims_json)
        .map_err(|e| crate::error::JwtError::InvalidToken(e.to_string()))?;

    let header_b64 = URL_SAFE_NO_PAD.encode(&header_bytes);
    let claims_b64 = URL_SAFE_NO_PAD.encode(&claims_bytes);

    // Create signature payload
    let signature_payload = format!("{header_b64}.{claims_b64}");

    // Create RSA signature using real cryptographic implementation
    let signature = sign_rs256(&signature_payload, private_key)?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

    // Combine into JWT
    let jwt = format!("{header_b64}.{claims_b64}.{signature_b64}");

    Ok(jwt)
}
