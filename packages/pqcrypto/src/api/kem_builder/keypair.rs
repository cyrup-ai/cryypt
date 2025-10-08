//! Key pair generation and management for ML-KEM
//!
//! Contains key generation and key configuration functionality for post-quantum ML-KEM.

use super::super::super::KemAlgorithm;
use super::super::{
    builder_traits::KemKeyPairBuilder,
    states::{HasKeyPair, HasPublicKey, HasSecretKey, NeedKeyPair},
};
use super::MlKemBuilder;
use crate::Result;
use pqcrypto_traits::kem::{PublicKey as PqPublicKey, SecretKey as PqSecretKey};

use std::marker::PhantomData;

// Implementation for NeedKeyPair state
impl KemKeyPairBuilder for MlKemBuilder<NeedKeyPair> {
    type Output = MlKemBuilder<HasKeyPair>;
    type PublicKeyOutput = MlKemBuilder<HasPublicKey>;
    type SecretKeyOutput = MlKemBuilder<HasSecretKey>;

    async fn generate(self) -> Result<Self::Output> {
        let (pk, sk) = match self.algorithm {
            KemAlgorithm::MlKem512 => {
                let (pk, sk) = pqcrypto_mlkem::mlkem512::keypair();
                (
                    PqPublicKey::as_bytes(&pk).to_vec(),
                    PqSecretKey::as_bytes(&sk).to_vec(),
                )
            }
            KemAlgorithm::MlKem768 => {
                let (pk, sk) = pqcrypto_mlkem::mlkem768::keypair();
                (
                    PqPublicKey::as_bytes(&pk).to_vec(),
                    PqSecretKey::as_bytes(&sk).to_vec(),
                )
            }
            KemAlgorithm::MlKem1024 => {
                let (pk, sk) = pqcrypto_mlkem::mlkem1024::keypair();
                (
                    PqPublicKey::as_bytes(&pk).to_vec(),
                    PqSecretKey::as_bytes(&sk).to_vec(),
                )
            }
        };

        Ok(MlKemBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(pk),
            secret_key: Some(sk),
            ciphertext: None,
        })
    }

    fn with_keypair<T: Into<Vec<u8>>>(self, public_key: T, secret_key: T) -> Result<Self::Output> {
        let pk = public_key.into();
        let sk = secret_key.into();

        self.validate_public_key(&pk)?;
        self.validate_secret_key(&sk)?;

        Ok(MlKemBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(pk),
            secret_key: Some(sk),
            ciphertext: None,
        })
    }

    fn with_public_key<T: Into<Vec<u8>>>(
        self,
        public_key: T,
    ) -> Result<MlKemBuilder<HasPublicKey>> {
        let pk = public_key.into();
        self.validate_public_key(&pk)?;

        Ok(MlKemBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(pk),
            secret_key: None,
            ciphertext: None,
        })
    }

    fn with_secret_key<T: Into<Vec<u8>>>(
        self,
        secret_key: T,
    ) -> Result<MlKemBuilder<HasSecretKey>> {
        let sk = secret_key.into();
        self.validate_secret_key(&sk)?;

        Ok(MlKemBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: None,
            secret_key: Some(sk),
            ciphertext: None,
        })
    }
}
