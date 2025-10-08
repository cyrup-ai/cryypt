//! ML-DSA verification implementations for different variants

use super::super::super::{
    builder_traits::{AsyncVerificationResult, VerifyBuilder},
    states::HasSignature,
};
use super::types::MlDsaBuilder;
use crate::PqCryptoError;
use crate::algorithm::SignatureAlgorithm;
use crate::result::VerificationResult;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

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
