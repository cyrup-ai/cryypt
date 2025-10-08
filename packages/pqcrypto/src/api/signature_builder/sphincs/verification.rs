//! SPHINCS+ signature verification operations

use super::super::super::super::{SignatureAlgorithm, VerificationResult};
use super::super::super::{
    builder_traits::{AsyncVerificationResult, VerifyBuilder},
    states::HasSignature,
};
use super::core::SphincsBuilder;
use crate::PqCryptoError;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

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
                        DetachedSignature, PublicKey, verify_detached_signature,
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
                        DetachedSignature, PublicKey, verify_detached_signature,
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
                        DetachedSignature, PublicKey, verify_detached_signature,
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
                        DetachedSignature, PublicKey, verify_detached_signature,
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
                        DetachedSignature, PublicKey, verify_detached_signature,
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
                        DetachedSignature, PublicKey, verify_detached_signature,
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
