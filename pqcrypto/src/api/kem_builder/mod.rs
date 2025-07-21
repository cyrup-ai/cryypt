//! KEM (Key Encapsulation Mechanism) builder module
//!
//! Contains the main ML-KEM builder patterns and core types for post-quantum key encapsulation.

use super::super::{KemAlgorithm};
use super::states::*;
use crate::{PqCryptoError, Result};
use std::marker::PhantomData;

// Declare submodules
pub mod keypair;
pub mod encapsulation;
pub mod decapsulation;

// Re-export key types from submodules for external use
// pub use encapsulation::*;
// pub use decapsulation::*;
// pub use keypair::*;

/// Main entry point for KEM operations
pub struct KemBuilder;

/// KEM builder with result handler for keypair/encapsulation operations (returns tuple)
pub struct KemBuilderWithHandler<F, T> {
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

/// KEM builder with result handler for decapsulation operations (returns Vec<u8>)
pub struct KemBuilderWithDecapHandler<F, T> {
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

/// KEM builder with secret key for decapsulation
pub struct KemBuilderWithSecretKey {
    _phantom: std::marker::PhantomData<()>,
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
    pub fn with_secret_key(self, _key: Vec<u8>) -> KemBuilderWithSecretKey {
        KemBuilderWithSecretKey {
            _phantom: std::marker::PhantomData,
        }
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
        }
    }
}

impl<F, T> KemBuilderWithDecapHandler<F, T>
where
    F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
    T: Send + 'static,
{
    /// Decapsulate and apply result handler
    pub async fn decapsulate(self, _ciphertext: Vec<u8>) -> T {
        let handler = self.result_handler;
        // For now, return a placeholder result until proper KEM implementation
        let result = Ok(vec![0u8; 32]); // Placeholder shared_secret
        handler(result)
    }
}

impl<F, T> KemBuilderWithHandler<F, T>
where
    F: FnOnce(crate::Result<(Vec<u8>, Vec<u8>)>) -> T + Send + 'static,
    T: Send + 'static,
{
    /// Generate keypair and apply result handler
    pub async fn generate_keypair(self) -> T {
        let handler = self.result_handler;
        // For now, return a placeholder result until proper KEM implementation
        let result = Ok((vec![0u8; 32], vec![0u8; 32])); // Placeholder (public_key, secret_key)
        handler(result)
    }
    
    /// Encapsulate and apply result handler
    pub async fn encapsulate(self, _public_key: Vec<u8>) -> T {
        let handler = self.result_handler;
        // For now, return a placeholder result until proper KEM implementation
        let result = Ok((vec![0u8; 32], vec![0u8; 32])); // Placeholder (ciphertext, shared_secret)
        handler(result)
    }

    /// Create a new ML-KEM builder with the specified security level
    pub fn ml_kem(security_level: u16) -> Result<MlKemBuilder<NeedKeyPair>> {
        let algorithm = match security_level {
            512 => KemAlgorithm::MlKem512,
            768 => KemAlgorithm::MlKem768,
            1024 => KemAlgorithm::MlKem1024,
            _ => {
                return Err(PqCryptoError::UnsupportedAlgorithm(format!(
                    "ML-KEM-{} is not supported. Use 512, 768, or 1024",
                    security_level
                )));
            }
        };

        Ok(MlKemBuilder {
            algorithm,
            state: PhantomData,
            public_key: None,
            secret_key: None,
            ciphertext: None,
        })
    }

    /// Create ML-KEM-512 builder (NIST security level 1)
    pub fn ml_kem_512() -> MlKemBuilder<NeedKeyPair> {
        MlKemBuilder {
            algorithm: KemAlgorithm::MlKem512,
            state: PhantomData,
            public_key: None,
            secret_key: None,
            ciphertext: None,
        }
    }

    /// Create ML-KEM-768 builder (NIST security level 3)
    pub fn ml_kem_768() -> MlKemBuilder<NeedKeyPair> {
        MlKemBuilder {
            algorithm: KemAlgorithm::MlKem768,
            state: PhantomData,
            public_key: None,
            secret_key: None,
            ciphertext: None,
        }
    }

    /// Create ML-KEM-1024 builder (NIST security level 5)
    pub fn ml_kem_1024() -> MlKemBuilder<NeedKeyPair> {
        MlKemBuilder {
            algorithm: KemAlgorithm::MlKem1024,
            state: PhantomData,
            public_key: None,
            secret_key: None,
            ciphertext: None,
        }
    }
}

/// ML-KEM builder type with type-state pattern
#[derive(Debug, Clone)]
pub struct MlKemBuilder<State> {
    pub(crate) algorithm: KemAlgorithm,
    pub(crate) state: PhantomData<State>,
    pub(crate) public_key: Option<Vec<u8>>,
    pub(crate) secret_key: Option<Vec<u8>>,
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

// Public key access methods for HasKeyPair state
impl MlKemBuilder<HasKeyPair> {
    /// Get the public key bytes
    pub fn public_key(&self) -> Result<&[u8]> {
        self.public_key
            .as_ref()
            .map(|k| k.as_slice())
            .ok_or_else(|| PqCryptoError::internal("Public key not available in HasKeyPair state"))
    }

    /// Get the secret key bytes  
    pub fn secret_key(&self) -> Result<&[u8]> {
        self.secret_key
            .as_ref()
            .map(|k| k.as_slice())
            .ok_or_else(|| PqCryptoError::internal("Secret key not available in HasKeyPair state"))
    }

    /// Get the public key as a vector
    pub fn public_key_vec(&self) -> Result<Vec<u8>> {
        self.public_key
            .clone()
            .ok_or_else(|| PqCryptoError::internal("Public key not available in HasKeyPair state"))
    }

    /// Get the secret key as a vector
    pub fn secret_key_vec(&self) -> Result<Vec<u8>> {
        self.secret_key
            .clone()
            .ok_or_else(|| PqCryptoError::internal("Secret key not available in HasKeyPair state"))
    }
}