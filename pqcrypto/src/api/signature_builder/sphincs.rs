//! SPHINCS+ (Stateless Hash-based Digital Signature Scheme) implementation

use super::super::super::{SignatureAlgorithm, SignatureResult, VerificationResult};
use super::super::{builder_traits::*, states::*};
use crate::{PqCryptoError, Result};
use pqcrypto_traits::sign::{
    DetachedSignature as PqDetachedSignature, PublicKey as PqPublicKey, SecretKey as PqSecretKey,
};
use std::future::Future;
use std::marker::PhantomData;

/// SPHINCS+ builder type
pub struct SphincsBuilder<State> {
    pub(super) algorithm: SignatureAlgorithm,
    pub(super) state: PhantomData<State>,
    pub(super) public_key: Option<Vec<u8>>,
    pub(super) secret_key: Option<Vec<u8>>,
    pub(super) message: Option<Vec<u8>>,
    pub(super) signature: Option<Vec<u8>>,
}

impl<State> super::BaseSignatureBuilder for SphincsBuilder<State> {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }
}

// SPHINCS+ implementations
impl SignatureKeyPairBuilder for SphincsBuilder<NeedKeyPair> {
    type Output = SphincsBuilder<HasKeyPair>;
    type PublicKeyOutput = SphincsBuilder<HasPublicKey>;
    type SecretKeyOutput = SphincsBuilder<HasSecretKey>;

    fn generate(self) -> impl Future<Output = Result<Self::Output>> + Send {
        async move {
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

// Type aliases for SPHINCS+
/// SPHINCS+ builder with a complete key pair (public and secret keys)
pub type SphincsWithKeyPair = SphincsBuilder<HasKeyPair>;
/// SPHINCS+ builder with only the secret key for signing
pub type SphincsWithSecretKey = SphincsBuilder<HasSecretKey>;
/// SPHINCS+ builder with only the public key for verification
pub type SphincsWithPublicKey = SphincsBuilder<HasPublicKey>;
/// SPHINCS+ builder with message ready for signing
pub type SphincsWithMessage = SphincsBuilder<HasMessage>;
/// SPHINCS+ builder with signature ready for verification
pub type SphincsWithSignature = SphincsBuilder<HasSignature>;

// Public key access methods for SPHINCS+ HasKeyPair state
impl SphincsBuilder<HasKeyPair> {
    /// Get the public key bytes
    pub fn public_key(&self) -> &[u8] {
        self.public_key
            .as_ref()
            .expect("HasKeyPair must have public key")
    }

    /// Get the secret key bytes  
    pub fn secret_key(&self) -> &[u8] {
        self.secret_key
            .as_ref()
            .expect("HasKeyPair must have secret key")
    }

    /// Get the public key as a vector
    pub fn public_key_vec(&self) -> Vec<u8> {
        self.public_key
            .clone()
            .expect("HasKeyPair must have public key")
    }

    /// Get the secret key as a vector
    pub fn secret_key_vec(&self) -> Vec<u8> {
        self.secret_key
            .clone()
            .expect("HasKeyPair must have secret key")
    }
}

// Message builder implementations for SPHINCS+
impl<State> MessageBuilder for SphincsBuilder<State> {
    type Output = SphincsBuilder<HasMessage>;

    fn with_message<T: Into<Vec<u8>>>(self, message: T) -> Self::Output {
        SphincsBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            message: Some(message.into()),
            signature: self.signature,
        }
    }
}

// Signature data builder implementations for SPHINCS+
impl<State> SignatureDataBuilder for SphincsBuilder<State> {
    type Output = SphincsBuilder<HasSignature>;

    fn with_signature<T: Into<Vec<u8>>>(self, signature: T) -> Self::Output {
        SphincsBuilder {
            algorithm: self.algorithm,
            state: PhantomData,
            public_key: self.public_key,
            secret_key: self.secret_key,
            message: self.message,
            signature: Some(signature.into()),
        }
    }
}

// Sign builder implementation for SPHINCS+ with message
impl SignBuilder for SphincsBuilder<HasMessage> {
    fn sign(self) -> impl AsyncSignatureResult {
        async move {
            let secret_key = self.secret_key.ok_or_else(|| {
                PqCryptoError::InvalidKey("Secret key required for signing".to_string())
            })?;
            let message = self
                .message
                .ok_or_else(|| PqCryptoError::InternalError("Message not set".to_string()))?;

            let signature = match self.algorithm {
                SignatureAlgorithm::SphincsShaSha256_128fSimple => {
                    use pqcrypto_sphincsplus::sphincssha2128fsimple::{detached_sign, SecretKey};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid SPHINCS+ secret key".to_string())
                    })?;
                    let sig = detached_sign(&message, &sk);
                    PqDetachedSignature::as_bytes(&sig).to_vec()
                }
                SignatureAlgorithm::SphincsShaSha256_128sSimple => {
                    use pqcrypto_sphincsplus::sphincssha2128ssimple::{detached_sign, SecretKey};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid SPHINCS+ secret key".to_string())
                    })?;
                    let sig = detached_sign(&message, &sk);
                    PqDetachedSignature::as_bytes(&sig).to_vec()
                }
                SignatureAlgorithm::SphincsShaSha256_192fSimple => {
                    use pqcrypto_sphincsplus::sphincssha2192fsimple::{detached_sign, SecretKey};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid SPHINCS+ secret key".to_string())
                    })?;
                    let sig = detached_sign(&message, &sk);
                    PqDetachedSignature::as_bytes(&sig).to_vec()
                }
                SignatureAlgorithm::SphincsShaSha256_192sSimple => {
                    use pqcrypto_sphincsplus::sphincssha2192ssimple::{detached_sign, SecretKey};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid SPHINCS+ secret key".to_string())
                    })?;
                    let sig = detached_sign(&message, &sk);
                    PqDetachedSignature::as_bytes(&sig).to_vec()
                }
                SignatureAlgorithm::SphincsShaSha256_256fSimple => {
                    use pqcrypto_sphincsplus::sphincssha2256fsimple::{detached_sign, SecretKey};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid SPHINCS+ secret key".to_string())
                    })?;
                    let sig = detached_sign(&message, &sk);
                    PqDetachedSignature::as_bytes(&sig).to_vec()
                }
                SignatureAlgorithm::SphincsShaSha256_256sSimple => {
                    use pqcrypto_sphincsplus::sphincssha2256ssimple::{detached_sign, SecretKey};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid SPHINCS+ secret key".to_string())
                    })?;
                    let sig = detached_sign(&message, &sk);
                    PqDetachedSignature::as_bytes(&sig).to_vec()
                }
                _ => {
                    return Err(PqCryptoError::InternalError(
                        "Invalid algorithm for SPHINCS+".to_string(),
                    ));
                }
            };

            Ok(SignatureResult::new(self.algorithm, signature, None))
        }
    }
}

// Verify builder implementation for SPHINCS+ with signature
impl VerifyBuilder for SphincsBuilder<HasSignature> {
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
                SignatureAlgorithm::SphincsShaSha256_128fSimple => {
                    use pqcrypto_sphincsplus::sphincssha2128fsimple::{
                        verify_detached_signature, DetachedSignature, PublicKey,
                    };
                    let pk = PublicKey::from_bytes(&public_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid SPHINCS+ public key".to_string())
                    })?;
                    let sig = DetachedSignature::from_bytes(&signature).map_err(|_| {
                        PqCryptoError::InvalidParameters("Invalid SPHINCS+ signature".to_string())
                    })?;
                    verify_detached_signature(&sig, &message, &pk).is_ok()
                }
                SignatureAlgorithm::SphincsShaSha256_128sSimple => {
                    use pqcrypto_sphincsplus::sphincssha2128ssimple::{
                        verify_detached_signature, DetachedSignature, PublicKey,
                    };
                    let pk = PublicKey::from_bytes(&public_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid SPHINCS+ public key".to_string())
                    })?;
                    let sig = DetachedSignature::from_bytes(&signature).map_err(|_| {
                        PqCryptoError::InvalidParameters("Invalid SPHINCS+ signature".to_string())
                    })?;
                    verify_detached_signature(&sig, &message, &pk).is_ok()
                }
                SignatureAlgorithm::SphincsShaSha256_192fSimple => {
                    use pqcrypto_sphincsplus::sphincssha2192fsimple::{
                        verify_detached_signature, DetachedSignature, PublicKey,
                    };
                    let pk = PublicKey::from_bytes(&public_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid SPHINCS+ public key".to_string())
                    })?;
                    let sig = DetachedSignature::from_bytes(&signature).map_err(|_| {
                        PqCryptoError::InvalidParameters("Invalid SPHINCS+ signature".to_string())
                    })?;
                    verify_detached_signature(&sig, &message, &pk).is_ok()
                }
                SignatureAlgorithm::SphincsShaSha256_192sSimple => {
                    use pqcrypto_sphincsplus::sphincssha2192ssimple::{
                        verify_detached_signature, DetachedSignature, PublicKey,
                    };
                    let pk = PublicKey::from_bytes(&public_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid SPHINCS+ public key".to_string())
                    })?;
                    let sig = DetachedSignature::from_bytes(&signature).map_err(|_| {
                        PqCryptoError::InvalidParameters("Invalid SPHINCS+ signature".to_string())
                    })?;
                    verify_detached_signature(&sig, &message, &pk).is_ok()
                }
                SignatureAlgorithm::SphincsShaSha256_256fSimple => {
                    use pqcrypto_sphincsplus::sphincssha2256fsimple::{
                        verify_detached_signature, DetachedSignature, PublicKey,
                    };
                    let pk = PublicKey::from_bytes(&public_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid SPHINCS+ public key".to_string())
                    })?;
                    let sig = DetachedSignature::from_bytes(&signature).map_err(|_| {
                        PqCryptoError::InvalidParameters("Invalid SPHINCS+ signature".to_string())
                    })?;
                    verify_detached_signature(&sig, &message, &pk).is_ok()
                }
                SignatureAlgorithm::SphincsShaSha256_256sSimple => {
                    use pqcrypto_sphincsplus::sphincssha2256ssimple::{
                        verify_detached_signature, DetachedSignature, PublicKey,
                    };
                    let pk = PublicKey::from_bytes(&public_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid SPHINCS+ public key".to_string())
                    })?;
                    let sig = DetachedSignature::from_bytes(&signature).map_err(|_| {
                        PqCryptoError::InvalidParameters("Invalid SPHINCS+ signature".to_string())
                    })?;
                    verify_detached_signature(&sig, &message, &pk).is_ok()
                }
                _ => {
                    return Err(PqCryptoError::InternalError(
                        "Invalid algorithm for SPHINCS+".to_string(),
                    ));
                }
            };

            Ok(VerificationResult::new(self.algorithm, is_valid, None))
        }
    }
}