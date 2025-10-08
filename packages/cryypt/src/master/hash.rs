//! Hash Master Builder
//!
//! Master builder for hashing operations (SHA256, SHA3, Blake2b)

/// Master builder for hashing operations
#[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
pub struct HashMasterBuilder;

#[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
impl HashMasterBuilder {
    /// Use SHA-256 hashing - README.md pattern
    #[cfg(feature = "sha256")]
    #[must_use]
    pub fn sha256(self) -> cryypt_hashing::Sha256Builder {
        cryypt_hashing::Hash::sha256()
    }

    /// Use SHA3-256 hashing - README.md pattern
    #[cfg(feature = "sha3")]
    #[must_use]
    pub fn sha3_256(self) -> cryypt_hashing::Sha3_256Builder {
        cryypt_hashing::Hash::sha3_256()
    }

    /// Use `BLAKE2b` hashing - README.md pattern
    #[cfg(feature = "blake2b")]
    #[must_use]
    pub fn blake2b(self) -> cryypt_hashing::Blake2bBuilder {
        cryypt_hashing::Hash::blake2b()
    }

    /// Use BLAKE3 hashing - README.md pattern
    #[must_use]
    pub fn blake3(self) -> cryypt_hashing::Blake3Builder {
        cryypt_hashing::Blake3Builder::new()
    }
}
