//! ML-KEM builder implementation with type-state pattern
//!
//! Contains the type-state builder pattern implementation for ML-KEM operations.

use super::super::KemAlgorithm;
use super::core::*;
use super::states::*;
use crate::{PqCryptoError, Result};
use pqcrypto_mlkem::{mlkem512, mlkem768, mlkem1024};
use std::marker::PhantomData;
use zeroize::Zeroizing;

// Implementation for NeedKeyPair state
impl MlKemBuilder<NeedKeyPair> {
    /// Generate a new keypair for this algorithm
    pub async fn generate_keypair(self) -> Result<MlKemBuilder<HasKeyPair>> {
        let (public_key, secret_key) = match self.algorithm {
            KemAlgorithm::MlKem512 => {
                let (pk, sk) = mlkem512::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            KemAlgorithm::MlKem768 => {
                let (pk, sk) = mlkem768::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
            KemAlgorithm::MlKem1024 => {
                let (pk, sk) = mlkem1024::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            }
        };

        Ok(MlKemBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(Zeroizing::new(public_key)),
            secret_key: Some(Zeroizing::new(secret_key)),
            ciphertext: None,
        })
    }

    /// Set an existing public key for encapsulation
    pub fn with_public_key(self, key: Vec<u8>) -> Result<MlKemBuilder<HasPublicKey>> {
        self.validate_public_key(&key)?;

        Ok(MlKemBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(Zeroizing::new(key)),
            secret_key: None,
            ciphertext: None,
        })
    }

    /// Set an existing secret key for decapsulation
    pub fn with_secret_key(self, key: Vec<u8>) -> Result<MlKemBuilder<HasSecretKey>> {
        self.validate_secret_key(&key)?;

        Ok(MlKemBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: None,
            secret_key: Some(Zeroizing::new(key)),
            ciphertext: None,
        })
    }
}
