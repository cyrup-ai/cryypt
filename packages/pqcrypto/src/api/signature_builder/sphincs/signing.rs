//! SPHINCS+ signing operations

use super::super::super::super::{SignatureAlgorithm, SignatureResult};
use super::super::super::{
    builder_traits::{AsyncSignatureResult, SignBuilder},
    states::HasMessage,
};
use super::core::SphincsBuilder;
use crate::PqCryptoError;
use pqcrypto_traits::sign::{DetachedSignature as PqDetachedSignature, SecretKey};

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
                    use pqcrypto_sphincsplus::sphincssha2128fsimple::{SecretKey, detached_sign};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid SPHINCS+ secret key".to_string())
                    })?;
                    let sig = detached_sign(&message, &sk);
                    PqDetachedSignature::as_bytes(&sig).to_vec()
                }
                SignatureAlgorithm::SphincsShaSha256_128sSimple => {
                    use pqcrypto_sphincsplus::sphincssha2128ssimple::{SecretKey, detached_sign};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid SPHINCS+ secret key".to_string())
                    })?;
                    let sig = detached_sign(&message, &sk);
                    PqDetachedSignature::as_bytes(&sig).to_vec()
                }
                SignatureAlgorithm::SphincsShaSha256_192fSimple => {
                    use pqcrypto_sphincsplus::sphincssha2192fsimple::{SecretKey, detached_sign};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid SPHINCS+ secret key".to_string())
                    })?;
                    let sig = detached_sign(&message, &sk);
                    PqDetachedSignature::as_bytes(&sig).to_vec()
                }
                SignatureAlgorithm::SphincsShaSha256_192sSimple => {
                    use pqcrypto_sphincsplus::sphincssha2192ssimple::{SecretKey, detached_sign};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid SPHINCS+ secret key".to_string())
                    })?;
                    let sig = detached_sign(&message, &sk);
                    PqDetachedSignature::as_bytes(&sig).to_vec()
                }
                SignatureAlgorithm::SphincsShaSha256_256fSimple => {
                    use pqcrypto_sphincsplus::sphincssha2256fsimple::{SecretKey, detached_sign};
                    let sk = SecretKey::from_bytes(&secret_key).map_err(|_| {
                        PqCryptoError::InvalidKey("Invalid SPHINCS+ secret key".to_string())
                    })?;
                    let sig = detached_sign(&message, &sk);
                    PqDetachedSignature::as_bytes(&sig).to_vec()
                }
                SignatureAlgorithm::SphincsShaSha256_256sSimple => {
                    use pqcrypto_sphincsplus::sphincssha2256ssimple::{SecretKey, detached_sign};
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
