//! Key operations and cryptographic implementations
//!
//! Contains keypair access methods and core cryptographic operations.

use super::super::KemAlgorithm;
use super::core::*;
use super::states::*;
use crate::{PqCryptoError, Result};
use pqcrypto_mlkem::{mlkem512, mlkem768, mlkem1024};

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
            .as_ref()
            .map(|k| k.as_slice().to_vec())
            .ok_or_else(|| PqCryptoError::internal("Public key not available in HasKeyPair state"))
    }

    /// Get the secret key as a vector
    pub fn secret_key_vec(&self) -> Result<Vec<u8>> {
        self.secret_key
            .as_ref()
            .map(|k| k.as_slice().to_vec())
            .ok_or_else(|| PqCryptoError::internal("Secret key not available in HasKeyPair state"))
    }

    /// Encapsulate using the public key
    pub async fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        let public_key = self.public_key_vec()?;

        match self.algorithm {
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

    /// Decapsulate using the secret key
    pub async fn decapsulate(&self, ciphertext: Vec<u8>) -> Result<Vec<u8>> {
        let secret_key = self.secret_key_vec()?;

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
                let sk = mlkem512::SecretKey::from_bytes(&secret_key)
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
                let sk = mlkem768::SecretKey::from_bytes(&secret_key)
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
                let sk = mlkem1024::SecretKey::from_bytes(&secret_key)
                    .map_err(|_| PqCryptoError::invalid_key("Invalid ML-KEM-1024 secret key"))?;

                let shared_secret = mlkem1024::decapsulate(&ct, &sk);
                Ok(shared_secret.as_bytes().to_vec())
            }
        }
    }
}
