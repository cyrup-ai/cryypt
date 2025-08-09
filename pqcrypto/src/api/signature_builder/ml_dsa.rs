//! ML-DSA (Module-Lattice-Based Digital Signature Algorithm) implementation

use super::super::super::{SignatureAlgorithm, SignatureResult, VerificationResult};
use super::super::{builder_traits::*, states::*};
use super::BaseSignatureBuilder;
use crate::{PqCryptoError, Result};
use pqcrypto_traits::sign::{
    DetachedSignature as PqDetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};
use std::future::Future;
use std::marker::PhantomData;

/// ML-DSA builder type
pub struct MlDsaBuilder<State> {
    pub(super) algorithm: SignatureAlgorithm,
    pub(super) state: PhantomData<State>,
    pub(super) public_key: Option<Vec<u8>>,
    pub(super) secret_key: Option<Vec<u8>>,
    pub(super) message: Option<Vec<u8>>,
    pub(super) signature: Option<Vec<u8>>,
}

impl<State> super::BaseSignatureBuilder for MlDsaBuilder<State> {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

// ML-DSA implementations
impl SignatureKeyPairBuilder for MlDsaBuilder<NeedKeyPair> {
    type Output = MlDsaBuilder<HasKeyPair>;
    type PublicKeyOutput = MlDsaBuilder<HasPublicKey>;
    type SecretKeyOutput = MlDsaBuilder<HasSecretKey>;

    fn generate(self) -> impl Future<Output = Result<Self::Output>> + Send {
        async move {
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

// Type aliases for ML-DSA
/// ML-DSA builder with a complete key pair (public and secret keys)
pub type MlDsaWithKeyPair = MlDsaBuilder<HasKeyPair>;
/// ML-DSA builder with only the secret key for signing
pub type MlDsaWithSecretKey = MlDsaBuilder<HasSecretKey>;
/// ML-DSA builder with only the public key for verification
pub type MlDsaWithPublicKey = MlDsaBuilder<HasPublicKey>;
/// ML-DSA builder with message ready for signing
pub type MlDsaWithMessage = MlDsaBuilder<HasMessage>;
/// ML-DSA builder with signature ready for verification
pub type MlDsaWithSignature = MlDsaBuilder<HasSignature>;

// Public key access methods for ML-DSA HasKeyPair state
impl MlDsaBuilder<HasKeyPair> {
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
            .clone()
            .ok_or_else(|| PqCryptoError::internal("Public key not available in HasKeyPair state"))
    }

    /// Get the secret key as a vector
    pub fn secret_key_vec(&self) -> Result<Vec<u8>> {
        self.secret_key
            .clone()
            .ok_or_else(|| PqCryptoError::internal("Secret key not available in HasKeyPair state"))
    }
}

// Message builder implementations for ML-DSA
impl<State> MessageBuilder for MlDsaBuilder<State> {
    type Output = MlDsaBuilder<HasMessage>;

    fn with_message<T: Into<Vec<u8>>>(self, message: T) -> Self::Output {
        MlDsaBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            message: Some(message.into()),
            signature: self.signature,
        }
    }
}

// Signature data builder implementations for ML-DSA
impl<State> SignatureDataBuilder for MlDsaBuilder<State> {
    type Output = MlDsaBuilder<HasSignature>;

    fn with_signature<T: Into<Vec<u8>>>(self, signature: T) -> Self::Output {
        MlDsaBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            message: self.message,
            signature: Some(signature.into()),
        }
    }
}

// Sign builder implementation for ML-DSA with message
impl SignBuilder for MlDsaBuilder<HasMessage> {
    fn sign(self) -> impl AsyncSignatureResult {
        async move {
            let secret_key = self.secret_key.ok_or_else(|| {
                PqCryptoError::InvalidKey("Secret key required for signing".to_string())
            })?;
            let message = self
                .message
                .ok_or_else(|| PqCryptoError::InternalError("Message not set".to_string()))?;

            let signature = match self.algorithm {
                SignatureAlgorithm::MlDsa44 => {
                    use pqcrypto_mldsa::mldsa44::{SecretKey, detached_sign};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid ML-DSA-44 secret key".to_string())
                    })?;
                    let sig = detached_sign(&message, &sk);
                    PqDetachedSignature::as_bytes(&sig).to_vec()
                }
                SignatureAlgorithm::MlDsa65 => {
                    use pqcrypto_mldsa::mldsa65::{SecretKey, detached_sign};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid ML-DSA-65 secret key".to_string())
                    })?;
                    let sig = detached_sign(&message, &sk);
                    PqDetachedSignature::as_bytes(&sig).to_vec()
                }
                SignatureAlgorithm::MlDsa87 => {
                    use pqcrypto_mldsa::mldsa87::{SecretKey, detached_sign};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid ML-DSA-87 secret key".to_string())
                    })?;
                    let sig = detached_sign(&message, &sk);
                    PqDetachedSignature::as_bytes(&sig).to_vec()
                }
                _ => {
                    return Err(PqCryptoError::InternalError(
                        "Invalid algorithm for ML-DSA".to_string(),
                    ));
                }
            };

            Ok(SignatureResult::new(self.algorithm, signature, None))
        }
    }
}

// Verify builder implementation for ML-DSA with signature
impl VerifyBuilder for MlDsaBuilder<HasSignature> {
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
                SignatureAlgorithm::MlDsa44 => {
                    use pqcrypto_mldsa::mldsa44::{
                        DetachedSignature, PublicKey, verify_detached_signature,
                    };
                    let pk = PublicKey::from_bytes(&public_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid ML-DSA-44 public key".to_string())
                    })?;
                    let sig = DetachedSignature::from_bytes(&signature).map_err(|_| {
                        PqCryptoError::InvalidParameters("Invalid ML-DSA-44 signature".to_string())
                    })?;
                    verify_detached_signature(&sig, &message, &pk).is_ok()
                }
                SignatureAlgorithm::MlDsa65 => {
                    use pqcrypto_mldsa::mldsa65::{
                        DetachedSignature, PublicKey, verify_detached_signature,
                    };
                    let pk = PublicKey::from_bytes(&public_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid ML-DSA-65 public key".to_string())
                    })?;
                    let sig = DetachedSignature::from_bytes(&signature).map_err(|_| {
                        PqCryptoError::InvalidParameters("Invalid ML-DSA-65 signature".to_string())
                    })?;
                    verify_detached_signature(&sig, &message, &pk).is_ok()
                }
                SignatureAlgorithm::MlDsa87 => {
                    use pqcrypto_mldsa::mldsa87::{
                        DetachedSignature, PublicKey, verify_detached_signature,
                    };
                    let pk = PublicKey::from_bytes(&public_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid ML-DSA-87 public key".to_string())
                    })?;
                    let sig = DetachedSignature::from_bytes(&signature).map_err(|_| {
                        PqCryptoError::InvalidParameters("Invalid ML-DSA-87 signature".to_string())
                    })?;
                    verify_detached_signature(&sig, &message, &pk).is_ok()
                }
                _ => {
                    return Err(PqCryptoError::InternalError(
                        "Invalid algorithm for ML-DSA".to_string(),
                    ));
                }
            };

            Ok(VerificationResult::new(self.algorithm, is_valid, None))
        }
    }
}
