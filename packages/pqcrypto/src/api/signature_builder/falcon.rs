//! FALCON (Fast-Fourier Lattice-based Compact Signatures over NTRU) implementation

use super::super::super::{SignatureAlgorithm, SignatureResult, VerificationResult};
use super::super::{
    builder_traits::{
        AsyncSignatureResult, AsyncVerificationResult, MessageBuilder, SignBuilder,
        SignatureDataBuilder, SignatureKeyPairBuilder, VerifyBuilder,
    },
    states::{HasKeyPair, HasMessage, HasPublicKey, HasSecretKey, HasSignature, NeedKeyPair},
};
use super::common::BaseSignatureBuilder;
use crate::{PqCryptoError, Result};
use pqcrypto_traits::sign::{
    DetachedSignature as PqDetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};

use std::marker::PhantomData;

/// FALCON builder type
pub struct FalconBuilder<State> {
    pub(super) algorithm: SignatureAlgorithm,
    pub(super) state: PhantomData<State>,
    pub(super) public_key: Option<Vec<u8>>,
    pub(super) secret_key: Option<Vec<u8>>,
    pub(super) message: Option<Vec<u8>>,
    pub(super) signature: Option<Vec<u8>>,
}

impl<State> super::common::BaseSignatureBuilder for FalconBuilder<State> {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

// FALCON implementations
impl SignatureKeyPairBuilder for FalconBuilder<NeedKeyPair> {
    type Output = FalconBuilder<HasKeyPair>;
    type PublicKeyOutput = FalconBuilder<HasPublicKey>;
    type SecretKeyOutput = FalconBuilder<HasSecretKey>;

    async fn generate(self) -> Result<Self::Output> {
        let (pk, sk) = match self.algorithm {
            SignatureAlgorithm::Falcon512 => {
                let (pk, sk) = pqcrypto_falcon::falcon512::keypair();
                (
                    PqPublicKey::as_bytes(&pk).to_vec(),
                    PqSecretKey::as_bytes(&sk).to_vec(),
                )
            }
            SignatureAlgorithm::Falcon1024 => {
                let (pk, sk) = pqcrypto_falcon::falcon1024::keypair();
                (
                    PqPublicKey::as_bytes(&pk).to_vec(),
                    PqSecretKey::as_bytes(&sk).to_vec(),
                )
            }
            _ => {
                return Err(PqCryptoError::InternalError(
                    "Invalid algorithm for FALCON".to_string(),
                ));
            }
        };

        Ok(FalconBuilder {
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

        Ok(FalconBuilder {
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
    ) -> Result<FalconBuilder<HasPublicKey>> {
        let pk = public_key.into();
        self.validate_public_key(&pk)?;

        Ok(FalconBuilder {
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
    ) -> Result<FalconBuilder<HasSecretKey>> {
        let sk = secret_key.into();
        self.validate_secret_key(&sk)?;

        Ok(FalconBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: None,
            secret_key: Some(sk),
            message: None,
            signature: None,
        })
    }
}

// Type aliases for FALCON
/// FALCON builder with a complete key pair (public and secret keys)
pub type FalconWithKeyPair = FalconBuilder<HasKeyPair>;
/// FALCON builder with only the secret key for signing
pub type FalconWithSecretKey = FalconBuilder<HasSecretKey>;
/// FALCON builder with only the public key for verification
pub type FalconWithPublicKey = FalconBuilder<HasPublicKey>;
/// FALCON builder with message ready for signing
pub type FalconWithMessage = FalconBuilder<HasMessage>;
/// FALCON builder with signature ready for verification
pub type FalconWithSignature = FalconBuilder<HasSignature>;

// Public key access methods for FALCON HasKeyPair state
impl FalconBuilder<HasKeyPair> {
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

// Message builder implementations for FALCON
impl<State> MessageBuilder for FalconBuilder<State> {
    type Output = FalconBuilder<HasMessage>;

    fn with_message<T: Into<Vec<u8>>>(self, message: T) -> Self::Output {
        FalconBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            message: Some(message.into()),
            signature: self.signature,
        }
    }
}

// Signature data builder implementations for FALCON
impl<State> SignatureDataBuilder for FalconBuilder<State> {
    type Output = FalconBuilder<HasSignature>;

    fn with_signature<T: Into<Vec<u8>>>(self, signature: T) -> Self::Output {
        FalconBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            message: self.message,
            signature: Some(signature.into()),
        }
    }
}

// Sign builder implementation for FALCON with message
impl SignBuilder for FalconBuilder<HasMessage> {
    fn sign(self) -> impl AsyncSignatureResult {
        async move {
            let secret_key = self.secret_key.ok_or_else(|| {
                PqCryptoError::InvalidKey("Secret key required for signing".to_string())
            })?;
            let message = self
                .message
                .ok_or_else(|| PqCryptoError::InternalError("Message not set".to_string()))?;

            let signature = match self.algorithm {
                SignatureAlgorithm::Falcon512 => {
                    use pqcrypto_falcon::falcon512::{SecretKey, detached_sign};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid FALCON-512 secret key".to_string())
                    })?;
                    let sig = detached_sign(&message, &sk);
                    PqDetachedSignature::as_bytes(&sig).to_vec()
                }
                SignatureAlgorithm::Falcon1024 => {
                    use pqcrypto_falcon::falcon1024::{SecretKey, detached_sign};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid FALCON-1024 secret key".to_string())
                    })?;
                    let sig = detached_sign(&message, &sk);
                    PqDetachedSignature::as_bytes(&sig).to_vec()
                }
                _ => {
                    return Err(PqCryptoError::InternalError(
                        "Invalid algorithm for FALCON".to_string(),
                    ));
                }
            };

            Ok(SignatureResult::new(self.algorithm, signature, None))
        }
    }
}

// Verify builder implementation for FALCON with signature
impl VerifyBuilder for FalconBuilder<HasSignature> {
    fn verify(self) -> impl AsyncVerificationResult {
        async move {
            let public_key = self.public_key.ok_or_else(|| {
                PqCryptoError::InvalidKey("Public key required for verification".to_string())
            })?;
            let message = self.message.ok_or_else(|| {
                PqCryptoError::InvalidParameters("Message required for verification".to_string())
            })?;
            let signature = self
                .signature
                .ok_or_else(|| PqCryptoError::InternalError("Signature not set".to_string()))?;

            let is_valid = match self.algorithm {
                SignatureAlgorithm::Falcon512 => {
                    use pqcrypto_falcon::falcon512::{
                        DetachedSignature, PublicKey, verify_detached_signature,
                    };
                    let pk = PublicKey::from_bytes(&public_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid FALCON-512 public key".to_string())
                    })?;
                    let sig = DetachedSignature::from_bytes(&signature).map_err(|_| {
                        PqCryptoError::InvalidParameters("Invalid FALCON-512 signature".to_string())
                    })?;
                    verify_detached_signature(&sig, &message, &pk).is_ok()
                }
                SignatureAlgorithm::Falcon1024 => {
                    use pqcrypto_falcon::falcon1024::{
                        DetachedSignature, PublicKey, verify_detached_signature,
                    };
                    let pk = PublicKey::from_bytes(&public_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid FALCON-1024 public key".to_string())
                    })?;
                    let sig = DetachedSignature::from_bytes(&signature).map_err(|_| {
                        PqCryptoError::InvalidParameters(
                            "Invalid FALCON-1024 signature".to_string(),
                        )
                    })?;
                    verify_detached_signature(&sig, &message, &pk).is_ok()
                }
                _ => {
                    return Err(PqCryptoError::InternalError(
                        "Invalid algorithm for FALCON".to_string(),
                    ));
                }
            };

            Ok(VerificationResult::new(self.algorithm, is_valid, None))
        }
    }
}
