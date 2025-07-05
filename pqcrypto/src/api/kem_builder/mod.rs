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

impl KemBuilder {
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
    pub fn public_key(&self) -> &[u8] {
        self.public_key
            .as_ref()
            .expect("HasKeyPair must have public key")
    }

    /// Get the secret key bytes  
    pub fn secret_key(&self) -> &[u8] {
        self.secret_key
            .as_ref()
            .expect("HasKeyPair must have secret key")
    }

    /// Get the public key as a vector
    pub fn public_key_vec(&self) -> Vec<u8> {
        self.public_key
            .clone()
            .expect("HasKeyPair must have public key")
    }

    /// Get the secret key as a vector
    pub fn secret_key_vec(&self) -> Vec<u8> {
        self.secret_key
            .clone()
            .expect("HasKeyPair must have secret key")
    }
}