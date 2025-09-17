//! SPHINCS+ type aliases and key access methods

use super::super::super::states::*;
use super::core::SphincsBuilder;
use crate::{PqCryptoError, Result};

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
    pub fn public_key(&self) -> Result<&[u8]> {
        self.public_key
            .as_deref()
            .ok_or_else(|| PqCryptoError::internal("Public key not available in HasKeyPair state"))
    }

    /// Get the secret key bytes  
    pub fn secret_key(&self) -> Result<&[u8]> {
        self.secret_key
            .as_deref()
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
