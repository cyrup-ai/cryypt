//! HS256 JWT Builder - Polymorphic pattern for HMAC-SHA256 JWT operations
//!
//! Provides polymorphic builder pattern for HS256 JWT signing with both single-result
//! and batch operations.

// Removed unused imports after fixing redundant field names
use crate::crypto::hmac_sha256::hmac_sha256_sign;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use futures::Stream;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// HS256 JWT builder - initial state
#[derive(Debug, Clone)]
pub struct HsJwtBuilder;

/// HS256 JWT builder with secret configured
#[derive(Debug, Clone)]
pub struct HsJwtWithSecret {
    secret: Vec<u8>,
}

/// HS256 JWT builder with secret and claims configured
#[derive(Debug, Clone)]
pub struct HsJwtWithSecretAndClaims<T> {
    secret: Vec<u8>,
    claims: T,
}

/// HS256 JWT builder with secret, claims and result handler
#[derive(Debug)]
pub struct HsJwtWithSecretAndClaimsAndHandler<T, F> {
    secret: Vec<u8>,
    claims: T,
    handler: F,
}

/// HS256 JWT builder with secret, claims and chunk handler for batch operations
#[derive(Debug)]
pub struct HsJwtWithSecretAndClaimsAndChunkHandler<T, F> {
    secret: Vec<u8>,
    #[allow(dead_code)]
    claims: T,
    handler: F,
}

impl Default for HsJwtBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl HsJwtBuilder {
    /// Create new HS256 JWT builder
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Set HMAC secret for HS256 signing
    #[must_use]
    pub fn with_secret(self, secret: &[u8]) -> HsJwtWithSecret {
        HsJwtWithSecret {
            secret: secret.to_vec(),
        }
    }
}

impl HsJwtWithSecret {
    /// Set claims for JWT
    #[must_use]
    pub fn with_claims<T: Serialize + Clone>(self, claims: T) -> HsJwtWithSecretAndClaims<T> {
        HsJwtWithSecretAndClaims {
            secret: self.secret,
            claims,
        }
    }
}

impl<T: Serialize + Clone> HsJwtWithSecretAndClaims<T> {
    /// Set result handler for single JWT signing
    #[must_use]
    pub fn on_result<F, R>(self, handler: F) -> HsJwtWithSecretAndClaimsAndHandler<T, F>
    where
        F: FnOnce(crate::error::JwtResult<Vec<u8>>) -> R,
        R: cryypt_common::NotResult,
    {
        HsJwtWithSecretAndClaimsAndHandler {
            secret: self.secret,
            claims: self.claims,
            handler,
        }
    }

    /// Set chunk handler for batch JWT signing
    #[must_use]
    pub fn on_chunk<F>(self, handler: F) -> HsJwtWithSecretAndClaimsAndChunkHandler<T, F>
    where
        F: Fn(crate::error::JwtResult<Vec<u8>>) -> Vec<u8>,
    {
        HsJwtWithSecretAndClaimsAndChunkHandler {
            secret: self.secret,
            claims: self.claims,
            handler,
        }
    }
}

impl<T, F, R> HsJwtWithSecretAndClaimsAndHandler<T, F>
where
    T: Serialize + Clone + Send + 'static,
    F: FnOnce(crate::error::JwtResult<Vec<u8>>) -> R + Send + 'static,
    R: cryypt_common::NotResult + Send + 'static,
{
    /// Sign single JWT with HS256
    #[must_use]
    pub async fn sign(self) -> R {
        let result = async {
            // Yield control to allow other tasks to run
            tokio::task::yield_now().await;

            // Sign JWT with HS256 using production HMAC-SHA256 implementation
            let jwt_token = sign_hs256_jwt(&self.claims, &self.secret)?;
            Ok(jwt_token.into_bytes())
        }
        .await;

        // Apply result handler
        (self.handler)(result)
    }
}

impl<T, F> HsJwtWithSecretAndClaimsAndChunkHandler<T, F>
where
    T: Serialize + Clone + Send + Sync + 'static,
    F: Fn(crate::error::JwtResult<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Sign batch of JWTs with different claims
    pub fn sign_batch(self, claims_list: Vec<T>) -> impl Stream<Item = Vec<u8>> {
        let (tx, rx) = mpsc::channel(32);
        let secret = self.secret;
        let handler = self.handler;

        tokio::spawn(async move {
            for (i, claims) in claims_list.into_iter().enumerate() {
                // Yield control to allow other tasks to run
                tokio::task::yield_now().await;

                // Sign individual JWT
                let result = async {
                    let jwt_token = sign_hs256_jwt(&claims, &secret)?;
                    Ok(jwt_token.into_bytes())
                }
                .await;

                // Apply handler and send result
                let processed_jwt = handler(result);

                if tx.send(processed_jwt).await.is_err() {
                    break; // Receiver dropped
                }

                // Progress tracking for batch operations
                if (i + 1) % 10 == 0 {
                    // Could add logging here if needed
                }
            }
        });

        ReceiverStream::new(rx)
    }
}

/// Production HS256 JWT signing implementation using real HMAC
fn sign_hs256_jwt<T: Serialize>(claims: &T, secret: &[u8]) -> crate::error::JwtResult<String> {
    // Create header
    let header = serde_json::json!({
        "alg": "HS256",
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

    // Create HMAC signature using real cryptographic implementation
    let signature = hmac_sha256_sign(signature_payload.as_bytes(), secret)?;
    let signature_b64 = URL_SAFE_NO_PAD.encode(&signature);

    // Combine into JWT
    let jwt = format!("{header_b64}.{claims_b64}.{signature_b64}");

    Ok(jwt)
}
