//! KEM (Key Encapsulation Mechanism) builder module
//!
//! Contains the main ML-KEM builder patterns and core types for post-quantum key encapsulation.

use super::super::KemAlgorithm;
use super::states::{HasCiphertext, HasKeyPair, HasPublicKey, HasSecretKey, NeedKeyPair};
use crate::{PqCryptoError, Result};
use std::marker::PhantomData;

// Declare submodules
pub mod decapsulation;
pub mod encapsulation;
pub mod keypair;

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
    /// Add `on_result` handler - `README.md` pattern
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
    #[must_use]
    pub fn with_secret_key(self, _key: Vec<u8>) -> KemBuilderWithSecretKey {
        KemBuilderWithSecretKey {
            _phantom: std::marker::PhantomData,
        }
    }
}

impl KemBuilderWithSecretKey {
    /// Add `on_result` handler for decapsulation - `README.md` pattern
    #[allow(clippy::unused_self)] // self consumed for builder pattern state transition
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
    /// Decapsulate using real ML-KEM cryptography  
    pub fn decapsulate(self, secret_key: &[u8], ciphertext: &[u8]) -> T {
        let handler = self.result_handler;

        // Perform real ML-KEM decapsulation using production cryptography
        let result = Self::perform_mlkem_decapsulation(secret_key, ciphertext);
        handler(result)
    }

    /// Internal ML-KEM decapsulation implementation using real cryptography
    #[inline]
    fn perform_mlkem_decapsulation(secret_key: &[u8], ciphertext: &[u8]) -> crate::Result<Vec<u8>> {
        // Use ML-KEM-768 for decapsulation with actual cryptographic implementation
        use pqcrypto_mlkem::mlkem768;
        use pqcrypto_traits::kem::{Ciphertext, SecretKey, SharedSecret};

        // Validate secret key size for ML-KEM-768
        if secret_key.len() != mlkem768::secret_key_bytes() {
            return Err(crate::PqCryptoError::InvalidKeySize {
                expected: mlkem768::secret_key_bytes(),
                actual: secret_key.len(),
            });
        }

        // Validate ciphertext size for ML-KEM-768
        if ciphertext.len() != mlkem768::ciphertext_bytes() {
            return Err(crate::PqCryptoError::InvalidParameters(format!(
                "Invalid ML-KEM-768 ciphertext size: expected {}, got {}",
                mlkem768::ciphertext_bytes(),
                ciphertext.len()
            )));
        }

        // Convert bytes to secret key and ciphertext types
        let sk = mlkem768::SecretKey::from_bytes(secret_key).map_err(|_| {
            crate::PqCryptoError::InvalidKey("Invalid ML-KEM secret key format".to_string())
        })?;

        let ct = mlkem768::Ciphertext::from_bytes(ciphertext).map_err(|_| {
            crate::PqCryptoError::InvalidParameters("Invalid ML-KEM ciphertext format".to_string())
        })?;

        // Perform decapsulation
        let shared_secret = mlkem768::decapsulate(&ct, &sk);
        Ok(shared_secret.as_bytes().to_vec())
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

        // Generate real ML-KEM keypair using production cryptography
        let result = async {
            // Use ML-KEM-768 as default security level for keypair generation
            use pqcrypto_mlkem::mlkem768;
            use pqcrypto_traits::kem::{PublicKey, SecretKey};

            let (public_key, secret_key) = mlkem768::keypair();
            Ok((
                public_key.as_bytes().to_vec(),
                secret_key.as_bytes().to_vec(),
            ))
        }
        .await;

        handler(result)
    }

    /// Encapsulate and apply result handler
    pub async fn encapsulate(self, public_key: Vec<u8>) -> T {
        let handler = self.result_handler;

        // Perform real ML-KEM encapsulation using production cryptography
        let result = async {
            // Use ML-KEM-768 for encapsulation with actual cryptographic implementation
            use pqcrypto_mlkem::mlkem768;
            use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};

            // Validate public key size for ML-KEM-768
            if public_key.len() != mlkem768::public_key_bytes() {
                return Err(crate::PqCryptoError::InvalidKeySize {
                    expected: mlkem768::public_key_bytes(),
                    actual: public_key.len(),
                });
            }

            // Convert bytes to public key type
            let pk = mlkem768::PublicKey::from_bytes(&public_key).map_err(|_| {
                crate::PqCryptoError::InvalidKey("Invalid ML-KEM public key format".to_string())
            })?;

            // Perform encapsulation
            let (shared_secret, ciphertext) = mlkem768::encapsulate(&pk);
            Ok((
                ciphertext.as_bytes().to_vec(),
                shared_secret.as_bytes().to_vec(),
            ))
        }
        .await;

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
                    "ML-KEM-{security_level} is not supported. Use 512, 768, or 1024"
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
    #[must_use]
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
    ///
    /// # Errors
    ///
    /// Returns an error if the public key is not available in the current state.
    pub fn public_key(&self) -> Result<&[u8]> {
        self.public_key
            .as_deref()
            .ok_or_else(|| PqCryptoError::internal("Public key not available in HasKeyPair state"))
    }

    /// Get the secret key bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key is not available in the current state.
    pub fn secret_key(&self) -> Result<&[u8]> {
        self.secret_key
            .as_deref()
            .ok_or_else(|| PqCryptoError::internal("Secret key not available in HasKeyPair state"))
    }

    /// Get the public key as a vector
    ///
    /// # Errors
    ///
    /// Returns an error if the public key is not available in the current state.
    pub fn public_key_vec(&self) -> Result<Vec<u8>> {
        self.public_key
            .clone()
            .ok_or_else(|| PqCryptoError::internal("Public key not available in HasKeyPair state"))
    }

    /// Get the secret key as a vector
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key is not available in the current state.
    pub fn secret_key_vec(&self) -> Result<Vec<u8>> {
        self.secret_key
            .clone()
            .ok_or_else(|| PqCryptoError::internal("Secret key not available in HasKeyPair state"))
    }
}
