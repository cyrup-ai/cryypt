//! Decapsulation operations for ML-KEM
//!
//! Contains key decapsulation functionality to recover shared secrets from ciphertext.

use super::super::super::{DecapsulationResult, KemAlgorithm, SharedSecret};
use super::super::{
    builder_traits::{AsyncDecapsulationResult, CiphertextBuilder, DecapsulateBuilder},
    states::{HasCiphertext, HasKeyPair, HasSecretKey},
};
use super::MlKemBuilder;
use crate::PqCryptoError;
use pqcrypto_traits::kem::{
    Ciphertext as PqCiphertext, SecretKey as PqSecretKey, SharedSecret as PqSharedSecret,
};
use std::marker::PhantomData;

// Add ciphertext to builders that have secret keys
impl CiphertextBuilder for MlKemBuilder<HasSecretKey> {
    type Output = MlKemBuilder<HasCiphertext>;

    fn with_ciphertext<T: Into<Vec<u8>>>(self, ciphertext: T) -> Self::Output {
        MlKemBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            ciphertext: Some(ciphertext.into()),
        }
    }
}

impl CiphertextBuilder for MlKemBuilder<HasKeyPair> {
    type Output = MlKemBuilder<HasCiphertext>;

    fn with_ciphertext<T: Into<Vec<u8>>>(self, ciphertext: T) -> Self::Output {
        MlKemBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            ciphertext: Some(ciphertext.into()),
        }
    }
}

// Implementation for HasCiphertext state - can decapsulate if has secret key
impl DecapsulateBuilder for MlKemBuilder<HasCiphertext> {
    fn decapsulate(self) -> impl AsyncDecapsulationResult {
        async move {
            let algorithm = self.algorithm;
            let secret_key = self.secret_key.ok_or_else(|| {
                PqCryptoError::InvalidKey("Secret key required for decapsulation".to_string())
            })?;
            let ciphertext = self
                .ciphertext
                .ok_or_else(|| PqCryptoError::InternalError("Ciphertext not set".to_string()))?;

            // Validate ciphertext size
            let expected_size = algorithm.ciphertext_size();
            if ciphertext.len() != expected_size {
                return Err(PqCryptoError::InvalidKeySize {
                    expected: expected_size,
                    actual: ciphertext.len(),
                });
            }

            let shared_secret_bytes = match algorithm {
                KemAlgorithm::MlKem512 => {
                    use pqcrypto_mlkem::mlkem512::{Ciphertext, SecretKey, decapsulate};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid ML-KEM-512 secret key".to_string())
                    })?;
                    let ct = Ciphertext::from_bytes(&ciphertext).map_err(|_| {
                        PqCryptoError::InvalidEncryptedData(
                            "Invalid ML-KEM-512 ciphertext".to_string(),
                        )
                    })?;
                    let ss = decapsulate(&ct, &sk);
                    PqSharedSecret::as_bytes(&ss).to_vec()
                }
                KemAlgorithm::MlKem768 => {
                    use pqcrypto_mlkem::mlkem768::{Ciphertext, SecretKey, decapsulate};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid ML-KEM-768 secret key".to_string())
                    })?;
                    let ct = Ciphertext::from_bytes(&ciphertext).map_err(|_| {
                        PqCryptoError::InvalidEncryptedData(
                            "Invalid ML-KEM-768 ciphertext".to_string(),
                        )
                    })?;
                    let ss = decapsulate(&ct, &sk);
                    PqSharedSecret::as_bytes(&ss).to_vec()
                }
                KemAlgorithm::MlKem1024 => {
                    use pqcrypto_mlkem::mlkem1024::{Ciphertext, SecretKey, decapsulate};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid ML-KEM-1024 secret key".to_string())
                    })?;
                    let ct = Ciphertext::from_bytes(&ciphertext).map_err(|_| {
                        PqCryptoError::InvalidEncryptedData(
                            "Invalid ML-KEM-1024 ciphertext".to_string(),
                        )
                    })?;
                    let ss = decapsulate(&ct, &sk);
                    PqSharedSecret::as_bytes(&ss).to_vec()
                }
            };

            let shared_secret = SharedSecret::new(algorithm, shared_secret_bytes);
            Ok(DecapsulationResult::new(algorithm, shared_secret))
        }
    }
}
