//! Handler operations and legacy API methods
//!
//! Contains result handler implementations and compatibility methods.

use super::super::KemAlgorithm;
use super::core::*;
use super::states::*;
use crate::{PqCryptoError, Result};
use pqcrypto_mlkem::{mlkem512, mlkem768, mlkem1024};
use std::marker::PhantomData;
use zeroize::Zeroizing;

impl KemBuilderWithSecretKey {
    /// Decapsulate directly without handler
    pub async fn decapsulate(self, ciphertext: Vec<u8>) -> Result<Vec<u8>> {
        match self.algorithm {
            KemAlgorithm::MlKem512 => {
                if ciphertext.len() != 768 {
                    return Err(PqCryptoError::InvalidKeySize {
                        expected: 768,
                        actual: ciphertext.len(),
                    });
                }

                let ct = mlkem512::Ciphertext::from_bytes(&ciphertext).map_err(|_| {
                    PqCryptoError::invalid_ciphertext("Invalid ML-KEM-512 ciphertext")
                })?;
                let sk = mlkem512::SecretKey::from_bytes(&self.secret_key)
                    .map_err(|_| PqCryptoError::invalid_key("Invalid ML-KEM-512 secret key"))?;

                let shared_secret = mlkem512::decapsulate(&ct, &sk);
                Ok(shared_secret.as_bytes().to_vec())
            }
            KemAlgorithm::MlKem768 => {
                if ciphertext.len() != 1088 {
                    return Err(PqCryptoError::InvalidKeySize {
                        expected: 1088,
                        actual: ciphertext.len(),
                    });
                }

                let ct = mlkem768::Ciphertext::from_bytes(&ciphertext).map_err(|_| {
                    PqCryptoError::invalid_ciphertext("Invalid ML-KEM-768 ciphertext")
                })?;
                let sk = mlkem768::SecretKey::from_bytes(&self.secret_key)
                    .map_err(|_| PqCryptoError::invalid_key("Invalid ML-KEM-768 secret key"))?;

                let shared_secret = mlkem768::decapsulate(&ct, &sk);
                Ok(shared_secret.as_bytes().to_vec())
            }
            KemAlgorithm::MlKem1024 => {
                if ciphertext.len() != 1568 {
                    return Err(PqCryptoError::InvalidKeySize {
                        expected: 1568,
                        actual: ciphertext.len(),
                    });
                }

                let ct = mlkem1024::Ciphertext::from_bytes(&ciphertext).map_err(|_| {
                    PqCryptoError::invalid_ciphertext("Invalid ML-KEM-1024 ciphertext")
                })?;
                let sk = mlkem1024::SecretKey::from_bytes(&self.secret_key)
                    .map_err(|_| PqCryptoError::invalid_key("Invalid ML-KEM-1024 secret key"))?;

                let shared_secret = mlkem1024::decapsulate(&ct, &sk);
                Ok(shared_secret.as_bytes().to_vec())
            }
        }
    }
}

impl<F, T> KemBuilderWithDecapHandler<F, T>
where
    F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
    T: Send + 'static,
{
    /// Decapsulate and apply result handler
    pub async fn decapsulate(self, ciphertext: Vec<u8>) -> T {
        let handler = self.result_handler;

        // Create temporary builder to perform decapsulation
        let temp_builder = KemBuilderWithSecretKey {
            secret_key: self.secret_key.clone(),
            algorithm: self.algorithm,
        };

        let result = temp_builder.decapsulate(ciphertext).await;
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
        let result = Self::generate_keypair_ml_kem_768().await;
        handler(result)
    }

    /// Encapsulate and apply result handler
    pub async fn encapsulate(self, public_key: Vec<u8>) -> T {
        let handler = self.result_handler;
        let result = Self::encapsulate_with_key(public_key).await;
        handler(result)
    }

    /// Generate ML-KEM-768 keypair (default security level)
    async fn generate_keypair_ml_kem_768() -> Result<(Vec<u8>, Vec<u8>)> {
        let (pk, sk) = mlkem768::keypair();
        Ok((pk.as_bytes().to_vec(), sk.as_bytes().to_vec()))
    }

    /// Encapsulate with given public key
    async fn encapsulate_with_key(public_key: Vec<u8>) -> Result<(Vec<u8>, Vec<u8>)> {
        // Determine algorithm from key size
        let algorithm = match public_key.len() {
            800 => KemAlgorithm::MlKem512,
            1184 => KemAlgorithm::MlKem768,
            1568 => KemAlgorithm::MlKem1024,
            _ => {
                return Err(PqCryptoError::InvalidKeySize {
                    expected: 1184,
                    actual: public_key.len(),
                });
            }
        };

        match algorithm {
            KemAlgorithm::MlKem512 => {
                let pk = mlkem512::PublicKey::from_bytes(&public_key)
                    .map_err(|_| PqCryptoError::invalid_key("Invalid ML-KEM-512 public key"))?;
                let (shared_secret, ciphertext) = mlkem512::encapsulate(&pk);
                Ok((
                    ciphertext.as_bytes().to_vec(),
                    shared_secret.as_bytes().to_vec(),
                ))
            }
            KemAlgorithm::MlKem768 => {
                let pk = mlkem768::PublicKey::from_bytes(&public_key)
                    .map_err(|_| PqCryptoError::invalid_key("Invalid ML-KEM-768 public key"))?;
                let (shared_secret, ciphertext) = mlkem768::encapsulate(&pk);
                Ok((
                    ciphertext.as_bytes().to_vec(),
                    shared_secret.as_bytes().to_vec(),
                ))
            }
            KemAlgorithm::MlKem1024 => {
                let pk = mlkem1024::PublicKey::from_bytes(&public_key)
                    .map_err(|_| PqCryptoError::invalid_key("Invalid ML-KEM-1024 public key"))?;
                let (shared_secret, ciphertext) = mlkem1024::encapsulate(&pk);
                Ok((
                    ciphertext.as_bytes().to_vec(),
                    shared_secret.as_bytes().to_vec(),
                ))
            }
        }
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
