//! Cryptographic hashing algorithms following README.md patterns exactly

#![forbid(unsafe_code)]

pub mod api;
pub mod error;
pub mod hash_result;
mod result_macro;
mod chunk_macro;

// Re-export error types
pub use error::{HashError, Result};

// Re-export the main APIs per README.md
pub use api::{Hash, Sha256Builder, Sha3_256Builder, Blake2bBuilder};

// Re-export hash result type
pub use hash_result::HashResult;

// Export macros for internal use
pub(crate) use chunk_macro::hash_on_chunk_impl;
pub(crate) use result_macro::hash_on_result_impl;

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

    /// Use Blake2b hashing - README.md pattern
    pub fn blake2b(self) -> Blake2bBuilder {
        Blake2bBuilder::new()
    }
}