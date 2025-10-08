//! Kyber KEM builder following polymorphic pattern

use crate::api::builder_traits::{
    CiphertextBuilder, DecapsulateBuilder, EncapsulateBuilder, KemKeyPairBuilder,
};
use crate::api::kem_builder::MlKemBuilder;
use crate::api::states::NeedKeyPair;
use crate::{KemAlgorithm, Result};
use futures::Stream;
use std::marker::PhantomData;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// Security levels for Kyber
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    Level1 = 512,
    Level3 = 768,
    Level5 = 1024,
}

/// Type-state marker for no security level set
pub struct NoSecurityLevel;

/// Type-state marker for security level set
pub struct HasSecurityLevel(pub SecurityLevel);

/// Builder for Kyber KEM operations
pub struct KyberBuilder<S> {
    pub(crate) security_level: S,
}

/// Builder with result handler
pub struct KyberBuilderWithHandler<S, F, T> {
    pub(crate) security_level: S,
    pub(crate) result_handler: F,
    pub(crate) _phantom: std::marker::PhantomData<T>,
}

/// Builder with chunk handler for streaming pattern
pub struct KyberBuilderWithChunk<S, F> {
    pub(crate) security_level: S,
    pub(crate) chunk_handler: F,
}

impl Default for KyberBuilder<NoSecurityLevel> {
    fn default() -> Self {
        Self::new()
    }
}

impl KyberBuilder<NoSecurityLevel> {
    /// Create a new Kyber builder
    #[must_use]
    pub fn new() -> Self {
        Self {
            security_level: NoSecurityLevel,
        }
    }

    /// Set security level - README.md pattern
    #[must_use]
    pub fn with_security_level(self, level: SecurityLevel) -> KyberBuilder<HasSecurityLevel> {
        KyberBuilder {
            security_level: HasSecurityLevel(level),
        }
    }
}

impl<S> KyberBuilder<S> {
    /// Add `on_result` handler - transforms pattern matching internally
    pub fn on_result<F>(self, handler: F) -> KyberBuilderWithHandler<S, F, Vec<u8>>
    where
        F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        KyberBuilderWithHandler {
            security_level: self.security_level,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Add `on_chunk` handler - transforms pattern matching internally
    pub fn on_chunk<F>(self, handler: F) -> KyberBuilderWithChunk<S, F>
    where
        F: Fn(Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        KyberBuilderWithChunk {
            security_level: self.security_level,
            chunk_handler: handler,
        }
    }
}

impl KyberBuilder<HasSecurityLevel> {
    /// Direct encapsulation for hybrid cryptography (returns both ciphertext and shared secret)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The public key is invalid or corrupted
    /// - The key size doesn't match the selected security level
    /// - The underlying cryptographic operation fails
    /// - Random number generation fails
    pub async fn encapsulate_hybrid<K>(self, public_key: K) -> Result<(Vec<u8>, Vec<u8>)>
    where
        K: Into<Vec<u8>>,
    {
        let public_key = public_key.into();
        let security_level = self.security_level.0;
        kyber_encapsulate_impl(security_level, public_key).await
    }

    /// Direct decapsulation for hybrid cryptography (returns shared secret)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The secret key is invalid or corrupted
    /// - The ciphertext is invalid or corrupted
    /// - The key or ciphertext size doesn't match the selected security level
    /// - The underlying cryptographic operation fails
    /// - Decapsulation verification fails
    pub async fn decapsulate_hybrid<K, C>(self, secret_key: K, ciphertext: C) -> Result<Vec<u8>>
    where
        K: Into<Vec<u8>>,
        C: Into<Vec<u8>>,
    {
        let secret_key = secret_key.into();
        let ciphertext = ciphertext.into();
        let security_level = self.security_level.0;
        kyber_decapsulate_impl(security_level, secret_key, ciphertext).await
    }
}

// Single result operations
impl<F, T> KyberBuilderWithHandler<HasSecurityLevel, F, T>
where
    F: FnOnce(Result<Vec<u8>>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Generate keypair
    pub async fn generate_keypair(self) -> T {
        let security_level = self.security_level.0;

        let result = kyber_generate_keypair_impl(security_level).await;

        (self.result_handler)(result)
    }

    /// Encapsulate shared secret (returns ciphertext only for API compatibility)
    pub async fn encapsulate<K>(self, public_key: K) -> T
    where
        K: Into<Vec<u8>>,
    {
        let public_key = public_key.into();
        let security_level = self.security_level.0;

        let result = kyber_encapsulate_impl(security_level, public_key)
            .await
            .map(|(ciphertext, _shared_secret)| ciphertext);

        (self.result_handler)(result)
    }

    /// Decapsulate shared secret
    pub async fn decapsulate<K, C>(self, secret_key: K, ciphertext: C) -> T
    where
        K: Into<Vec<u8>>,
        C: Into<Vec<u8>>,
    {
        let secret_key = secret_key.into();
        let ciphertext = ciphertext.into();
        let security_level = self.security_level.0;

        let result = kyber_decapsulate_impl(security_level, secret_key, ciphertext).await;

        (self.result_handler)(result)
    }
}

// Streaming operations
impl<F> KyberBuilderWithChunk<HasSecurityLevel, F>
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
                let result = kyber_generate_keypair_impl(security_level).await;

                // Apply handler and send result
                let processed_chunk = handler(result);

                if tx.send(processed_chunk).await.is_err() {
                    break; // Receiver dropped
                }
            }
        });

        ReceiverStream::new(rx)
    }

    /// Encapsulate multiple shared secrets with streaming
    pub fn encapsulate_batch<I, K>(self, public_keys: I) -> impl Stream<Item = Vec<u8>>
    where
        I: IntoIterator<Item = K> + Send + 'static,
        K: Into<Vec<u8>> + Send + 'static,
    {
        let (tx, rx) = mpsc::channel(32);
        let security_level = self.security_level.0;
        let handler = self.chunk_handler;

        tokio::spawn(async move {
            let keys: Vec<_> = public_keys.into_iter().collect();
            for public_key in keys {
                // Yield control to allow other tasks to run
                tokio::task::yield_now().await;

                let public_key = public_key.into();

                // Encapsulate individual shared secret (return only ciphertext for streaming)
                let result = kyber_encapsulate_impl(security_level, public_key)
                    .await
                    .map(|(ciphertext, _shared_secret)| ciphertext);

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

// Production Kyber operations using real ML-KEM implementation
async fn kyber_generate_keypair_impl(security_level: SecurityLevel) -> Result<Vec<u8>> {
    // Map security level to KEM algorithm variant
    let algorithm = match security_level {
        SecurityLevel::Level1 => KemAlgorithm::MlKem512,
        SecurityLevel::Level3 => KemAlgorithm::MlKem768,
        SecurityLevel::Level5 => KemAlgorithm::MlKem1024,
    };

    // Create ML-KEM builder and generate keypair using real implementation
    let ml_kem_builder = MlKemBuilder {
        algorithm,
        state: PhantomData::<NeedKeyPair>,
        public_key: None,
        secret_key: None,
        ciphertext: None,
    };

    // Generate real keypair using ML-KEM via KemKeyPairBuilder trait
    let keypair_result = KemKeyPairBuilder::generate(ml_kem_builder).await?;

    // Extract the keypair data using accessor methods
    let public_key = keypair_result.public_key_vec()?;
    let secret_key = keypair_result.secret_key_vec()?;

    // Combine keys for kyber_builder compatibility (public_key + secret_key)
    let mut combined_keypair = public_key;
    combined_keypair.extend(secret_key);

    Ok(combined_keypair)
}

async fn kyber_encapsulate_impl(
    security_level: SecurityLevel,
    public_key: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // Map security level to KEM algorithm variant
    let algorithm = match security_level {
        SecurityLevel::Level1 => KemAlgorithm::MlKem512,
        SecurityLevel::Level3 => KemAlgorithm::MlKem768,
        SecurityLevel::Level5 => KemAlgorithm::MlKem1024,
    };

    // Create ML-KEM builder and set public key
    let ml_kem_builder = MlKemBuilder {
        algorithm,
        state: PhantomData::<NeedKeyPair>,
        public_key: None,
        secret_key: None,
        ciphertext: None,
    };

    // Set the public key and encapsulate using ML-KEM implementation
    let ml_kem_with_pk = KemKeyPairBuilder::with_public_key(ml_kem_builder, public_key)?;
    let encapsulation_result = EncapsulateBuilder::encapsulate(ml_kem_with_pk).await?;

    // Return both ciphertext and shared secret for hybrid cryptography
    Ok((
        encapsulation_result.ciphertext().to_vec(),
        encapsulation_result.shared_secret().as_bytes().to_vec(),
    ))
}

async fn kyber_decapsulate_impl(
    security_level: SecurityLevel,
    secret_key: Vec<u8>,
    ciphertext: Vec<u8>,
) -> Result<Vec<u8>> {
    // Map security level to KEM algorithm variant
    let algorithm = match security_level {
        SecurityLevel::Level1 => KemAlgorithm::MlKem512,
        SecurityLevel::Level3 => KemAlgorithm::MlKem768,
        SecurityLevel::Level5 => KemAlgorithm::MlKem1024,
    };

    // Create ML-KEM builder and set secret key, then ciphertext
    let ml_kem_builder = MlKemBuilder {
        algorithm,
        state: PhantomData::<NeedKeyPair>,
        public_key: None,
        secret_key: None,
        ciphertext: None,
    };

    // Set the secret key and ciphertext, then decapsulate using real ML-KEM implementation
    let ml_kem_with_sk = KemKeyPairBuilder::with_secret_key(ml_kem_builder, secret_key)?;
    let ml_kem_with_ct = ml_kem_with_sk.with_ciphertext(ciphertext);
    let decapsulation_result = DecapsulateBuilder::decapsulate(ml_kem_with_ct).await?;

    // Return the shared secret
    Ok(decapsulation_result.shared_secret().as_bytes().to_vec())
}
