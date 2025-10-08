//! ML-DSA key generation and management operations

use super::super::super::{
    builder_traits::SignatureKeyPairBuilder,
    states::{HasKeyPair, HasPublicKey, HasSecretKey, NeedKeyPair},
};
use super::super::common::BaseSignatureBuilder;
use super::types::MlDsaBuilder;
use crate::algorithm::SignatureAlgorithm;
use crate::{PqCryptoError, Result};
use pqcrypto_traits::sign::{PublicKey as PqPublicKey, SecretKey as PqSecretKey};

use std::marker::PhantomData;

impl SignatureKeyPairBuilder for MlDsaBuilder<NeedKeyPair> {
    type Output = MlDsaBuilder<HasKeyPair>;
    type PublicKeyOutput = MlDsaBuilder<HasPublicKey>;
    type SecretKeyOutput = MlDsaBuilder<HasSecretKey>;

    async fn generate(self) -> Result<Self::Output> {
        let (pk, sk) = match self.algorithm {
            SignatureAlgorithm::MlDsa44 => {
                let (pk, sk) = pqcrypto_mldsa::mldsa44::keypair();
                (
                    PqPublicKey::as_bytes(&pk).to_vec(),
                    PqSecretKey::as_bytes(&sk).to_vec(),
                )
            }
            SignatureAlgorithm::MlDsa65 => {
                let (pk, sk) = pqcrypto_mldsa::mldsa65::keypair();
                (
                    PqPublicKey::as_bytes(&pk).to_vec(),
                    PqSecretKey::as_bytes(&sk).to_vec(),
                )
            }
            SignatureAlgorithm::MlDsa87 => {
                let (pk, sk) = pqcrypto_mldsa::mldsa87::keypair();
                (
                    PqPublicKey::as_bytes(&pk).to_vec(),
                    PqSecretKey::as_bytes(&sk).to_vec(),
                )
            }
            _ => {
                return Err(PqCryptoError::InternalError(
                    "Invalid algorithm for ML-DSA".to_string(),
                ));
            }
        };

        Ok(MlDsaBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(pk),
            secret_key: Some(sk),
            message: None,
            signature: None,
        })
    }

    fn with_keypair<T: Into<Vec<u8>>>(self, public_key: T, secret_key: T) -> Result<Self::Output> {
        let pk = public_key.into();
        let sk = secret_key.into();

        self.validate_public_key(&pk)?;
        self.validate_secret_key(&sk)?;

        Ok(MlDsaBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(pk),
            secret_key: Some(sk),
            message: None,
            signature: None,
        })
    }

    fn with_public_key<T: Into<Vec<u8>>>(
        self,
        public_key: T,
    ) -> Result<MlDsaBuilder<HasPublicKey>> {
        let pk = public_key.into();
        self.validate_public_key(&pk)?;

        Ok(MlDsaBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: Some(pk),
            secret_key: None,
            message: None,
            signature: None,
        })
    }

    fn with_secret_key<T: Into<Vec<u8>>>(
        self,
        secret_key: T,
    ) -> Result<MlDsaBuilder<HasSecretKey>> {
        let sk = secret_key.into();
        self.validate_secret_key(&sk)?;

        Ok(MlDsaBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: None,
            secret_key: Some(sk),
            message: None,
            signature: None,
        })
    }
}

// Public key access methods for ML-DSA HasKeyPair state
impl MlDsaBuilder<HasKeyPair> {
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
