//! Cryptographic hashing algorithms following README.md patterns exactly

#![forbid(unsafe_code)]

pub mod api;
pub mod async_result;
pub mod error;
pub mod hash_result;
pub mod streaming;

// Re-export error types
pub use error::{HashError, Result};

// Re-export the main APIs per README.md
pub use api::{
    Blake2bBuilder, Blake3Builder, Hash, Sha3_256Builder, Sha3_384Builder, Sha3_512Builder,
    Sha256Builder,
};

// Re-export hash result types
pub use async_result::{AsyncHashResult, AsyncHashResultWithError, AsyncHashResultWithHandler};
pub use hash_result::HashResult;

// Re-export common macros and handlers from cryypt_common
pub use cryypt_common::{on_error, on_result};

/// Main entry point - README.md pattern: "Cryypt offers two equivalent APIs"
pub struct Cryypt;

impl Cryypt {
    /// Master builder for hash operations - README.md pattern
    #[must_use]
    pub fn hash() -> HashMasterBuilder {
        HashMasterBuilder
    }
}

/// Master builder for hash operations
pub struct HashMasterBuilder;

impl HashMasterBuilder {
    /// Use SHA-256 hashing - README.md pattern
    #[must_use]
    pub fn sha256(self) -> Sha256Builder {
        Sha256Builder::new()
    }

    /// Use SHA3-256 hashing - README.md pattern
    #[must_use]
    pub fn sha3_256(self) -> Sha3_256Builder {
        Sha3_256Builder::new()
    }

    /// Use SHA3-384 hashing - README.md pattern
    #[must_use]
    pub fn sha3_384(self) -> Sha3_384Builder {
        Sha3_384Builder::new()
    }

    /// Use SHA3-512 hashing - README.md pattern
    #[must_use]
    pub fn sha3_512(self) -> Sha3_512Builder {
        Sha3_512Builder::new()
    }

    /// Use Blake2b hashing - README.md pattern
    #[must_use]
    pub fn blake2b(self) -> Blake2bBuilder {
        Blake2bBuilder::new()
    }

    /// Use Blake3 hashing - README.md pattern
    #[must_use]
    pub fn blake3(self) -> Blake3Builder {
        Blake3Builder::new()
    }
}
