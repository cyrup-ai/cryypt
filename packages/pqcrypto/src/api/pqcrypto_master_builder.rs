//! PQCrypto master builder for polymorphic API

use super::kyber_builder::KyberBuilder;
use super::dilithium_builder::DilithiumBuilder;

/// Master builder for post-quantum cryptography operations
pub struct PqCryptoMasterBuilder;

impl Default for PqCryptoMasterBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl PqCryptoMasterBuilder {
    /// Create a new PQCrypto master builder
    pub fn new() -> Self {
        Self
    }

    /// Create Kyber KEM builder
    pub fn kyber(self) -> KyberBuilder<super::kyber_builder::NoSecurityLevel> {
        KyberBuilder::new()
    }

    /// Create Dilithium signature builder
    pub fn dilithium(self) -> DilithiumBuilder<super::dilithium_builder::NoSecurityLevel> {
        DilithiumBuilder::new()
    }
}