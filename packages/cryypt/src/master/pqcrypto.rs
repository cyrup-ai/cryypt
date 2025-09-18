//! Post-Quantum Cryptography Master Builder
//!
//! Master builder for post-quantum cryptography operations (Kyber, Dilithium)

/// Master builder for post-quantum cryptography operations
#[cfg(feature = "pqcrypto")]
pub struct PqcryptoMasterBuilder;

#[cfg(feature = "pqcrypto")]
impl PqcryptoMasterBuilder {
    /// Use ML-KEM (Kyber) key encapsulation mechanism - README.md pattern
    #[must_use]
    pub fn kyber(self) -> cryypt_pqcrypto::api::KemBuilder {
        cryypt_pqcrypto::api::KemBuilder
    }

    /// Use ML-DSA (Dilithium) digital signature algorithm - README.md pattern
    #[must_use]
    pub fn dilithium(self) -> cryypt_pqcrypto::api::SignatureBuilder {
        cryypt_pqcrypto::api::SignatureBuilder
    }

    /// Create Kyber KEM builder - polymorphic pattern
    #[must_use]
    pub fn with_security_level(
        self,
        level: u16,
    ) -> cryypt_pqcrypto::api::KyberBuilder<cryypt_pqcrypto::api::KyberHasSecurityLevel> {
        let security_level = match level {
            512 => cryypt_pqcrypto::api::KyberSecurityLevel::Level1,
            1024 => cryypt_pqcrypto::api::KyberSecurityLevel::Level5,
            _ => cryypt_pqcrypto::api::KyberSecurityLevel::Level3, // Default to Level 3 (includes 768)
        };
        cryypt_pqcrypto::api::KyberBuilder::new().with_security_level(security_level)
    }
}
