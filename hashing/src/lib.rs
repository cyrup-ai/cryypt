//! Cryptographic hashing algorithms following README.md patterns exactly

#![forbid(unsafe_code)]

pub mod api;
pub mod error;
pub mod hash_result;
pub mod async_result;

// Re-export error types
pub use error::{HashError, Result};

// Re-export the main APIs per README.md
pub use api::{Hash, Sha256Builder, Sha3_256Builder, Sha3_384Builder, Sha3_512Builder, Blake2bBuilder};

// Re-export hash result types
pub use hash_result::HashResult;
pub use async_result::{AsyncHashResult, AsyncHashResultWithHandler, AsyncHashResultWithError};

// Re-export common handlers from cryypt_common
pub use cryypt_common::{on_result, on_chunk, on_error};


/// Main entry point - README.md pattern: "Cryypt offers two equivalent APIs"
pub struct Cryypt;

impl Cryypt {
    /// Master builder for hash operations - README.md pattern
    pub fn hash() -> HashMasterBuilder {
        HashMasterBuilder
    }
}

/// Master builder for hash operations
pub struct HashMasterBuilder;

impl HashMasterBuilder {
    /// Use SHA-256 hashing - README.md pattern
    pub fn sha256(self) -> Sha256Builder {
        Sha256Builder::new()
    }

    /// Use SHA3-256 hashing - README.md pattern
    pub fn sha3_256(self) -> Sha3_256Builder {
        Sha3_256Builder::new()
    }

    /// Use SHA3-384 hashing - README.md pattern
    pub fn sha3_384(self) -> Sha3_384Builder {
        Sha3_384Builder::new()
    }

    /// Use SHA3-512 hashing - README.md pattern
    pub fn sha3_512(self) -> Sha3_512Builder {
        Sha3_512Builder::new()
    }

    /// Use Blake2b hashing - README.md pattern
    pub fn blake2b(self) -> Blake2bBuilder {
        Blake2bBuilder::new()
    }
}