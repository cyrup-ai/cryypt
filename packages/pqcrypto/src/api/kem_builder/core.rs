//! Core KEM builder types and basic implementations
//!
//! Contains the main builder structs and their fundamental implementations.

use super::super::KemAlgorithm;
use super::states::*;
use crate::{PqCryptoError, Result};
use cryypt_common::chunk_types::PqCryptoChunk;
use cyrup_sugars::prelude::*;
use std::marker::PhantomData;
use zeroize::Zeroizing;

/// Main entry point for KEM operations
pub struct KemBuilder;

/// KEM builder with result handler for keypair/encapsulation operations (returns tuple)
pub struct KemBuilderWithHandler<F, T> {
    pub(crate) result_handler: F,
    pub(crate) _phantom: std::marker::PhantomData<T>,
}

/// KEM builder with result handler for decapsulation operations (returns Vec<u8>)
pub struct KemBuilderWithDecapHandler<F, T> {
    pub(crate) result_handler: F,
    pub(crate) _phantom: std::marker::PhantomData<T>,
    pub(crate) secret_key: Zeroizing<Vec<u8>>,
    pub(crate) algorithm: KemAlgorithm,
}

/// KEM builder with secret key for decapsulation
pub struct KemBuilderWithSecretKey {
    pub(crate) secret_key: Zeroizing<Vec<u8>>,
    pub(crate) algorithm: KemAlgorithm,
}

impl ChunkHandler<PqCryptoChunk> for KemBuilder {
    fn on_chunk<F>(self, _handler: F) -> Self
    where
        F: Fn(std::result::Result<PqCryptoChunk, String>) -> PqCryptoChunk + Send + Sync + 'static,
    {
        self
    }
}

impl KemBuilder {
    /// Add on_result handler - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> KemBuilderWithHandler<F, T>
    where
        F: FnOnce(crate::Result<(Vec<u8>, Vec<u8>)>) -> T + Send + 'static,
        T: Send + 'static,
    {
        KemBuilderWithHandler {
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set secret key for decapsulation operations
    pub fn with_secret_key(self, key: Vec<u8>) -> Result<KemBuilderWithSecretKey> {
        // Validate key size to determine algorithm
        let algorithm = match key.len() {
            1632 => KemAlgorithm::MlKem512,  // ML-KEM-512 secret key size
            2400 => KemAlgorithm::MlKem768,  // ML-KEM-768 secret key size
            3168 => KemAlgorithm::MlKem1024, // ML-KEM-1024 secret key size
            _ => {
                return Err(PqCryptoError::InvalidKeySize {
                    expected: 2400, // Default to ML-KEM-768
                    actual: key.len(),
                });
            }
        };

        Ok(KemBuilderWithSecretKey {
            secret_key: Zeroizing::new(key),
            algorithm,
        })
    }
}

impl KemBuilderWithSecretKey {
    /// Add on_result handler for decapsulation - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> KemBuilderWithDecapHandler<F, T>
    where
        F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
        T: Send + 'static,
    {
        KemBuilderWithDecapHandler {
            result_handler: handler,
            _phantom: std::marker::PhantomData,
            secret_key: self.secret_key,
            algorithm: self.algorithm,
        }
    }
}

/// ML-KEM builder type with type-state pattern
#[derive(Debug, Clone)]
pub struct MlKemBuilder<State> {
    pub(crate) algorithm: KemAlgorithm,
    pub(crate) state: PhantomData<State>,
    pub(crate) public_key: Option<Zeroizing<Vec<u8>>>,
    pub(crate) secret_key: Option<Zeroizing<Vec<u8>>>,
    pub(crate) ciphertext: Option<Vec<u8>>,
}

impl<State> MlKemBuilder<State> {
    /// Validate public key size for the algorithm
    pub(crate) fn validate_public_key(&self, key: &[u8]) -> Result<()> {
        let expected = self.algorithm.public_key_size();
        if key.len() != expected {
            return Err(PqCryptoError::InvalidKeySize {
                expected,
                actual: key.len(),
            });
        }
        Ok(())
    }

    /// Validate secret key size for the algorithm
    pub(crate) fn validate_secret_key(&self, key: &[u8]) -> Result<()> {
        let expected = self.algorithm.secret_key_size();
        if key.len() != expected {
            return Err(PqCryptoError::InvalidKeySize {
                expected,
                actual: key.len(),
            });
        }
        Ok(())
    }

    /// Get the algorithm used by this builder
    pub fn algorithm(&self) -> KemAlgorithm {
        self.algorithm
    }
}

// Type aliases for better readability
/// ML-KEM builder with a complete key pair (public and secret keys)
pub type MlKemWithKeyPair = MlKemBuilder<HasKeyPair>;
/// ML-KEM builder with only the public key for encapsulation
pub type MlKemWithPublicKey = MlKemBuilder<HasPublicKey>;
/// ML-KEM builder with only the secret key for decapsulation
pub type MlKemWithSecretKey = MlKemBuilder<HasSecretKey>;
/// ML-KEM builder with ciphertext ready for decapsulation
pub type MlKemWithCiphertext = MlKemBuilder<HasCiphertext>;
