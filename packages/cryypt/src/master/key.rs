//! Key Master Builder
//!
//! Master builder for key operations (generate, retrieve)

/// Master builder for key operations
#[cfg(feature = "key")]
pub struct KeyMasterBuilder;

#[cfg(feature = "key")]
impl KeyMasterBuilder {
    /// AES key operations - polymorphic pattern
    #[must_use]
    pub fn aes(self) -> cryypt_key::api::AesKeyBuilder {
        cryypt_key::api::AesKeyBuilder::new()
    }

    /// RSA key operations - polymorphic pattern
    #[must_use]
    pub fn rsa(self) -> cryypt_key::api::RsaKeyBuilder {
        cryypt_key::api::RsaKeyBuilder::new()
    }

    /// Generate a new key - README.md pattern
    #[must_use]
    pub fn generate(self) -> cryypt_key::api::KeyGenerator {
        cryypt_key::api::KeyGenerator::new()
    }

    /// Retrieve an existing key - README.md pattern
    #[must_use]
    pub fn retrieve(self) -> cryypt_key::api::KeyRetriever {
        cryypt_key::api::KeyRetriever::new()
    }
}
