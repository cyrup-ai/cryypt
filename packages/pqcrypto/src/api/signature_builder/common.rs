//! Common traits and types for signature builders

use super::super::super::SignatureAlgorithm;
use crate::Result;

/// Base trait for signature builders
pub(super) trait BaseSignatureBuilder {
    fn algorithm(&self) -> SignatureAlgorithm;

    fn validate_public_key(&self, key: &[u8]) -> Result<()> {
        let expected = self.algorithm().public_key_size();
        if key.len() != expected {
            return Err(crate::PqCryptoError::InvalidKeySize {
                expected,
                actual: key.len(),
            });
        }
        Ok(())
    }

    fn validate_secret_key(&self, key: &[u8]) -> Result<()> {
        let expected = self.algorithm().secret_key_size();
        if key.len() != expected {
            return Err(crate::PqCryptoError::InvalidKeySize {
                expected,
                actual: key.len(),
            });
        }
        Ok(())
    }
}
