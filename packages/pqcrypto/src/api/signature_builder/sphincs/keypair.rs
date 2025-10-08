//! SPHINCS+ key pair generation and management

use super::super::super::super::SignatureAlgorithm;
use super::super::super::{
    builder_traits::SignatureKeyPairBuilder,
    states::{HasKeyPair, HasPublicKey, HasSecretKey, NeedKeyPair},
};
use super::core::SphincsBuilder;
use crate::{PqCryptoError, Result};
use pqcrypto_traits::sign::{PublicKey as PqPublicKey, SecretKey as PqSecretKey};

use std::marker::PhantomData;

// SPHINCS+ implementations
impl SignatureKeyPairBuilder for SphincsBuilder<NeedKeyPair> {
    type Output = SphincsBuilder<HasKeyPair>;
    type PublicKeyOutput = SphincsBuilder<HasPublicKey>;
    type SecretKeyOutput = SphincsBuilder<HasSecretKey>;

    async fn generate(self) -> Result<Self::Output> {
        let (pk, sk) = match self.algorithm {
            SignatureAlgorithm::SphincsShaSha256_128fSimple => {
                let (pk, sk) = pqcrypto_sphincsplus::sphincssha2128fsimple::keypair();
                (
                    PqPublicKey::as_bytes(&pk).to_vec(),
                    PqSecretKey::as_bytes(&sk).to_vec(),
                )
            }
            SignatureAlgorithm::SphincsShaSha256_128sSimple => {
                let (pk, sk) = pqcrypto_sphincsplus::sphincssha2128ssimple::keypair();
                (
                    PqPublicKey::as_bytes(&pk).to_vec(),
                    PqSecretKey::as_bytes(&sk).to_vec(),
                )
            }
            SignatureAlgorithm::SphincsShaSha256_192fSimple => {
                let (pk, sk) = pqcrypto_sphincsplus::sphincssha2192fsimple::keypair();
                (
                    PqPublicKey::as_bytes(&pk).to_vec(),
                    PqSecretKey::as_bytes(&sk).to_vec(),
                )
            }
            SignatureAlgorithm::SphincsShaSha256_192sSimple => {
                let (pk, sk) = pqcrypto_sphincsplus::sphincssha2192ssimple::keypair();
                (
                    PqPublicKey::as_bytes(&pk).to_vec(),
                    PqSecretKey::as_bytes(&sk).to_vec(),
                )
            }
            SignatureAlgorithm::SphincsShaSha256_256fSimple => {
                let (pk, sk) = pqcrypto_sphincsplus::sphincssha2256fsimple::keypair();
                (
                    PqPublicKey::as_bytes(&pk).to_vec(),
                    PqSecretKey::as_bytes(&sk).to_vec(),
                )
            }
            SignatureAlgorithm::SphincsShaSha256_256sSimple => {
                let (pk, sk) = pqcrypto_sphincsplus::sphincssha2256ssimple::keypair();
                (
                    PqPublicKey::as_bytes(&pk).to_vec(),
                    PqSecretKey::as_bytes(&sk).to_vec(),
                )
            }
            _ => {
                return Err(PqCryptoError::InternalError(
                    "Invalid algorithm for SPHINCS+".to_string(),
                ));
            }
        };

        Ok(SphincsBuilder {
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

        Ok(SphincsBuilder {
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
    ) -> Result<SphincsBuilder<HasPublicKey>> {
        let pk = public_key.into();
        self.validate_public_key(&pk)?;

        Ok(SphincsBuilder {
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
    ) -> Result<SphincsBuilder<HasSecretKey>> {
        let sk = secret_key.into();
        self.validate_secret_key(&sk)?;

        Ok(SphincsBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: None,
            secret_key: Some(sk),
            message: None,
            signature: None,
        })
    }
}

impl<State> SphincsBuilder<State> {
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
}
