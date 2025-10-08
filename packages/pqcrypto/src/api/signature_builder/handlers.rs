//! Handler implementations for signature builder operations

use super::super::builder_traits::{MessageBuilder, SignBuilder, SignatureKeyPairBuilder};
use super::super::states::NeedKeyPair;
use super::core::{
    SignatureBuilderWithHandler, SignatureBuilderWithSignHandler, SignatureBuilderWithVerifyHandler,
};
use super::ml_dsa::MlDsaBuilder;
use crate::{PqCryptoError, SignatureAlgorithm};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use std::marker::PhantomData;

impl<F, T> SignatureBuilderWithSignHandler<F, T>
where
    F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
    T: Send + 'static,
{
    /// Sign message and apply result handler
    pub async fn sign(self, message: &[u8]) -> T {
        let handler = self.result_handler;

        // Use ML-DSA-65 as default algorithm for signing
        let builder = MlDsaBuilder::<NeedKeyPair> {
            algorithm: SignatureAlgorithm::MlDsa65,
            state: PhantomData,
            public_key: None,
            secret_key: None,
            message: Some(message.to_vec()),
            signature: None,
        };

        // Generate keypair and sign in one operation
        let result = match builder.generate().await {
            Ok(keypair_builder) => {
                match keypair_builder.with_message(message.to_vec()).sign().await {
                    Ok(signature_result) => Ok(signature_result.signature_vec()),
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e),
        };

        handler(result)
    }
}

impl<F, T> SignatureBuilderWithVerifyHandler<F, T>
where
    F: FnOnce(crate::Result<bool>) -> T + Send + 'static,
    T: Send + 'static,
{
    /// Verify signature using real ML-DSA cryptography
    pub fn verify(self, public_key: &[u8], signature: &[u8], message: &[u8]) -> T {
        let handler = self.result_handler;

        // Perform real ML-DSA signature verification using production cryptography
        let result = Self::perform_mldsa_verification(public_key, signature, message);
        handler(result)
    }

    /// Internal ML-DSA verification implementation using real cryptography
    #[inline]
    fn perform_mldsa_verification(
        public_key: &[u8],
        signature: &[u8],
        message: &[u8],
    ) -> crate::Result<bool> {
        // Use ML-DSA-65 as default algorithm (can be parameterized in future)
        let algorithm = SignatureAlgorithm::MlDsa65;

        let is_valid = match algorithm {
            SignatureAlgorithm::MlDsa44 => {
                use pqcrypto_mldsa::mldsa44::{
                    DetachedSignature, PublicKey, verify_detached_signature,
                };
                let pk = PublicKey::from_bytes(public_key).map_err(|_| {
                    PqCryptoError::InvalidKey("Invalid ML-DSA-44 public key".to_string())
                })?;
                let sig = DetachedSignature::from_bytes(signature).map_err(|_| {
                    PqCryptoError::InvalidParameters("Invalid ML-DSA-44 signature".to_string())
                })?;
                verify_detached_signature(&sig, message, &pk).is_ok()
            }
            SignatureAlgorithm::MlDsa65 => {
                use pqcrypto_mldsa::mldsa65::{
                    DetachedSignature, PublicKey, verify_detached_signature,
                };
                let pk = PublicKey::from_bytes(public_key).map_err(|_| {
                    PqCryptoError::InvalidKey("Invalid ML-DSA-65 public key".to_string())
                })?;
                let sig = DetachedSignature::from_bytes(signature).map_err(|_| {
                    PqCryptoError::InvalidParameters("Invalid ML-DSA-65 signature".to_string())
                })?;
                verify_detached_signature(&sig, message, &pk).is_ok()
            }
            SignatureAlgorithm::MlDsa87 => {
                use pqcrypto_mldsa::mldsa87::{
                    DetachedSignature, PublicKey, verify_detached_signature,
                };
                let pk = PublicKey::from_bytes(public_key).map_err(|_| {
                    PqCryptoError::InvalidKey("Invalid ML-DSA-87 public key".to_string())
                })?;
                let sig = DetachedSignature::from_bytes(signature).map_err(|_| {
                    PqCryptoError::InvalidParameters("Invalid ML-DSA-87 signature".to_string())
                })?;
                verify_detached_signature(&sig, message, &pk).is_ok()
            }
            _ => {
                return Err(PqCryptoError::UnsupportedAlgorithm(format!(
                    "Algorithm {algorithm:?} not supported for ML-DSA verification"
                )));
            }
        };

        Ok(is_valid)
    }
}

impl<F, T> SignatureBuilderWithHandler<F, T>
where
    F: FnOnce(crate::Result<(Vec<u8>, Vec<u8>)>) -> T + Send + 'static,
    T: Send + 'static,
{
    /// Generate keypair and apply result handler
    pub async fn generate_keypair(self) -> T {
        let handler = self.result_handler;

        // Use ML-DSA-65 as default algorithm for keypair generation
        let builder = MlDsaBuilder::<NeedKeyPair> {
            algorithm: SignatureAlgorithm::MlDsa65,
            state: PhantomData,
            public_key: None,
            secret_key: None,
            message: None,
            signature: None,
        };

        let result = match builder.generate().await {
            Ok(keypair_builder) => {
                match (
                    keypair_builder.public_key_vec(),
                    keypair_builder.secret_key_vec(),
                ) {
                    (Ok(pk), Ok(sk)) => Ok((pk, sk)),
                    _ => Err(PqCryptoError::internal("Failed to extract keypair")),
                }
            }
            Err(e) => Err(e),
        };

        handler(result)
    }
}
