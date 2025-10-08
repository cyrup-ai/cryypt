//! Dilithium signature builder following polymorphic pattern

use crate::algorithm::SignatureAlgorithm;
use crate::api::builder_traits::{SignBuilder, SignatureKeyPairBuilder, VerifyBuilder};
use crate::api::signature_builder::ml_dsa::MlDsaBuilder;
use crate::api::states::NeedKeyPair;
use crate::{PqCryptoError, Result};
use futures::Stream;
use std::marker::PhantomData;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Security levels for Dilithium
#[derive(Debug, Clone, Copy)]
pub enum SecurityLevel {
    Level2 = 44,
    Level3 = 65,
    Level5 = 87,
}

/// Type-state marker for no security level set
pub struct NoSecurityLevel;

/// Type-state marker for security level set
pub struct HasSecurityLevel(pub SecurityLevel);

/// Builder for Dilithium signature operations
pub struct DilithiumBuilder<S> {
    pub(crate) security_level: S,
}

/// Builder with result handler
pub struct DilithiumBuilderWithHandler<S, F, T> {
    pub(crate) security_level: S,
    pub(crate) result_handler: F,
    pub(crate) _phantom: std::marker::PhantomData<T>,
}

/// Builder with chunk handler for streaming pattern
pub struct DilithiumBuilderWithChunk<S, F> {
    pub(crate) security_level: S,
    pub(crate) chunk_handler: F,
}

impl Default for DilithiumBuilder<NoSecurityLevel> {
    fn default() -> Self {
        Self::new()
    }
}

impl DilithiumBuilder<NoSecurityLevel> {
    /// Create a new Dilithium builder
    #[must_use]
    pub fn new() -> Self {
        Self {
            security_level: NoSecurityLevel,
        }
    }

    /// Set security level - README.md pattern
    #[must_use]
    pub fn with_security_level(self, level: SecurityLevel) -> DilithiumBuilder<HasSecurityLevel> {
        DilithiumBuilder {
            security_level: HasSecurityLevel(level),
        }
    }
}

impl<S> DilithiumBuilder<S> {
    /// Add `on_result` handler - transforms pattern matching internally
    pub fn on_result<F>(self, handler: F) -> DilithiumBuilderWithHandler<S, F, Vec<u8>>
    where
        F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        DilithiumBuilderWithHandler {
            security_level: self.security_level,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Add `on_chunk` handler - transforms pattern matching internally
    pub fn on_chunk<F>(self, handler: F) -> DilithiumBuilderWithChunk<S, F>
    where
        F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        DilithiumBuilderWithChunk {
            security_level: self.security_level,
            chunk_handler: handler,
        }
    }
}

// Single result operations
impl<F, T> DilithiumBuilderWithHandler<HasSecurityLevel, F, T>
where
    F: FnOnce(Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Generate keypair
    pub async fn generate_keypair(self) -> T {
        let security_level = self.security_level.0;

        let result = dilithium_generate_keypair_impl(security_level).await;

        (self.result_handler)(result)
    }

    /// Sign message
    pub async fn sign<K, M>(self, secret_key: K, message: M) -> T
    where
        K: Into<Vec<u8>>,
        M: Into<Vec<u8>>,
    {
        let secret_key = secret_key.into();
        let message = message.into();
        let security_level = self.security_level.0;

        let result = dilithium_sign_impl(security_level, secret_key, message).await;

        (self.result_handler)(result)
    }

    /// Verify signature
    pub async fn verify<K, M, S>(self, public_key: K, message: M, signature: S) -> T
    where
        K: Into<Vec<u8>>,
        M: Into<Vec<u8>>,
        S: Into<Vec<u8>>,
    {
        let public_key = public_key.into();
        let message = message.into();
        let signature = signature.into();
        let security_level = self.security_level.0;

        let result = dilithium_verify_impl(security_level, public_key, message, signature).await;

        (self.result_handler)(result)
    }
}

// Streaming operations
impl<F> DilithiumBuilderWithChunk<HasSecurityLevel, F>
where
    F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Generate multiple keypairs with streaming
    pub fn generate_batch(self, count: usize) -> impl Stream<Item = Vec<u8>> {
        let (tx, rx) = mpsc::channel(32);
        let security_level = self.security_level.0;
        let handler = self.chunk_handler;

        tokio::spawn(async move {
            for _ in 0..count {
                // Yield control to allow other tasks to run
                tokio::task::yield_now().await;

                // Generate individual keypair
                let result = dilithium_generate_keypair_impl(security_level).await;

                // Apply handler and send result
                let processed_chunk = handler(result);

                if tx.send(processed_chunk).await.is_err() {
                    break; // Receiver dropped
                }
            }
        });

        ReceiverStream::new(rx)
    }

    /// Sign multiple messages with streaming
    pub fn sign_batch<I, K, M>(self, secret_key: K, messages: I) -> impl Stream<Item = Vec<u8>>
    where
        I: IntoIterator<Item = M> + Send + 'static,
        K: Into<Vec<u8>> + Clone + Send + 'static,
        M: Into<Vec<u8>> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel(32);
        let security_level = self.security_level.0;
        let handler = self.chunk_handler;
        let secret_key = secret_key.into();

        tokio::spawn(async move {
            let messages: Vec<_> = messages.into_iter().collect();
            for message in messages {
                // Yield control to allow other tasks to run
                tokio::task::yield_now().await;

                let message = message.into();

                // Sign individual message
                let result = dilithium_sign_impl(security_level, secret_key.clone(), message).await;

                // Apply handler and send result
                let processed_chunk = handler(result);

                if tx.send(processed_chunk).await.is_err() {
                    break; // Receiver dropped
                }
            }
        });

        ReceiverStream::new(rx)
    }
}

// Production Dilithium operations using real ML-DSA implementation
async fn dilithium_generate_keypair_impl(security_level: SecurityLevel) -> Result<Vec<u8>> {
    // Map security level to ML-DSA algorithm variant
    let algorithm = match security_level {
        SecurityLevel::Level2 => SignatureAlgorithm::MlDsa44,
        SecurityLevel::Level3 => SignatureAlgorithm::MlDsa65,
        SecurityLevel::Level5 => SignatureAlgorithm::MlDsa87,
    };

    // Create ML-DSA builder and generate keypair using real implementation
    let ml_dsa_builder = MlDsaBuilder {
        algorithm,
        state: PhantomData::<NeedKeyPair>,
        public_key: None,
        secret_key: None,
        message: None,
        signature: None,
    };

    // Generate real keypair using ML-DSA
    let keypair_result = ml_dsa_builder.generate().await?;

    // Extract the keypair data (concatenate public and secret keys)
    let public_key = keypair_result.public_key.ok_or_else(|| {
        PqCryptoError::InternalError("Public key missing from generated keypair".to_string())
    })?;
    let secret_key = keypair_result.secret_key.ok_or_else(|| {
        PqCryptoError::InternalError("Secret key missing from generated keypair".to_string())
    })?;

    // Combine keys for dilithium_builder compatibility (public_key + secret_key)
    let mut combined_keypair = public_key;
    combined_keypair.extend(secret_key);

    Ok(combined_keypair)
}

async fn dilithium_sign_impl(
    security_level: SecurityLevel,
    secret_key: Vec<u8>,
    message: Vec<u8>,
) -> Result<Vec<u8>> {
    // Map security level to ML-DSA algorithm variant
    let algorithm = match security_level {
        SecurityLevel::Level2 => SignatureAlgorithm::MlDsa44,
        SecurityLevel::Level3 => SignatureAlgorithm::MlDsa65,
        SecurityLevel::Level5 => SignatureAlgorithm::MlDsa87,
    };

    // Create ML-DSA builder with secret key and message
    let ml_dsa_builder = MlDsaBuilder {
        algorithm,
        state: PhantomData,
        public_key: None,
        secret_key: Some(secret_key),
        message: Some(message),
        signature: None,
    };

    // Sign using real ML-DSA implementation
    let signature_result = ml_dsa_builder.sign().await?;

    Ok(signature_result.signature_vec())
}

async fn dilithium_verify_impl(
    security_level: SecurityLevel,
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Result<Vec<u8>> {
    // Map security level to ML-DSA algorithm variant
    let algorithm = match security_level {
        SecurityLevel::Level2 => SignatureAlgorithm::MlDsa44,
        SecurityLevel::Level3 => SignatureAlgorithm::MlDsa65,
        SecurityLevel::Level5 => SignatureAlgorithm::MlDsa87,
    };

    // Create ML-DSA builder with public key, message, and signature
    let ml_dsa_builder = MlDsaBuilder {
        algorithm,
        state: PhantomData,
        public_key: Some(public_key),
        secret_key: None,
        message: Some(message),
        signature: Some(signature),
    };

    // Verify using real ML-DSA implementation
    let verification_result = ml_dsa_builder.verify().await?; // Using verify trait method

    // Return verification result (1 for valid, 0 for invalid) - matching original API
    // Extract the boolean result from VerificationResult
    Ok(if verification_result.is_valid() {
        vec![1u8]
    } else {
        vec![0u8]
    })
}
