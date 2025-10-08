//! ML-DSA signing implementations for different variants

use super::super::super::{
    builder_traits::{AsyncSignatureResult, SignBuilder},
    states::HasMessage,
};
use super::types::MlDsaBuilder;
use crate::PqCryptoError;
use crate::algorithm::SignatureAlgorithm;
use crate::result::SignatureResult;
use pqcrypto_traits::sign::{DetachedSignature as PqDetachedSignature, SecretKey};

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
                    use pqcrypto_traits::sign::SecretKey as PqSecretKey;
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
