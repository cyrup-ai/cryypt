//! Encapsulation operations for ML-KEM
//!
//! Contains key encapsulation functionality to generate shared secrets from public keys.

use super::super::super::{EncapsulationResult, KemAlgorithm, SharedSecret};
use super::super::{
    builder_traits::{AsyncEncapsulationResult, EncapsulateBuilder},
    states::{HasKeyPair, HasPublicKey},
};
use super::MlKemBuilder;
use crate::PqCryptoError;
use pqcrypto_traits::kem::{
    Ciphertext as PqCiphertext, PublicKey as PqPublicKey, SharedSecret as PqSharedSecret,
};
use std::marker::PhantomData;

// Implementation for HasPublicKey state - can encapsulate
impl EncapsulateBuilder for MlKemBuilder<HasPublicKey> {
    fn encapsulate(self) -> impl AsyncEncapsulationResult {
        async move {
            let public_key = self
                .public_key
                .ok_or_else(|| PqCryptoError::InternalError("Public key not set".to_string()))?;

            let (shared_secret_bytes, ciphertext) = match self.algorithm {
                KemAlgorithm::MlKem512 => {
                    use pqcrypto_mlkem::mlkem512::{PublicKey, encapsulate};
                    let pk = PublicKey::from_bytes(&public_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid ML-KEM-512 public key".to_string())
                    })?;
                    let (ss, ct) = encapsulate(&pk);
                    (
                        PqSharedSecret::as_bytes(&ss).to_vec(),
                        PqCiphertext::as_bytes(&ct).to_vec(),
                    )
                }
                KemAlgorithm::MlKem768 => {
                    use pqcrypto_mlkem::mlkem768::{PublicKey, encapsulate};
                    let pk = PublicKey::from_bytes(&public_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid ML-KEM-768 public key".to_string())
                    })?;
                    let (ss, ct) = encapsulate(&pk);
                    (
                        PqSharedSecret::as_bytes(&ss).to_vec(),
                        PqCiphertext::as_bytes(&ct).to_vec(),
                    )
                }
                KemAlgorithm::MlKem1024 => {
                    use pqcrypto_mlkem::mlkem1024::{PublicKey, encapsulate};
                    let pk = PublicKey::from_bytes(&public_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid ML-KEM-1024 public key".to_string())
                    })?;
                    let (ss, ct) = encapsulate(&pk);
                    (
                        PqSharedSecret::as_bytes(&ss).to_vec(),
                        PqCiphertext::as_bytes(&ct).to_vec(),
                    )
                }
            };

            let shared_secret = SharedSecret::new(self.algorithm, shared_secret_bytes);
            Ok(EncapsulationResult::new(
                self.algorithm,
                ciphertext,
                shared_secret,
            ))
        }
    }
}

// Implementation for HasKeyPair state - can encapsulate using the public key
impl EncapsulateBuilder for MlKemBuilder<HasKeyPair> {
    fn encapsulate(self) -> impl AsyncEncapsulationResult {
        async move {
            MlKemBuilder::<HasPublicKey> {
                algorithm: self.algorithm,
                state: PhantomData,
                public_key: self.public_key,
                secret_key: None,
                ciphertext: None,
            }
            .encapsulate()
            .await
        }
    }
}
