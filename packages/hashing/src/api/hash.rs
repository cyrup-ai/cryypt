//! Modular hash API - clean architecture following single responsibility principle
//!
//! Replaces the monolithic 1007-line implementation with modular structure:
//! - algorithms/sha256.rs - SHA-256 implementation
//! - algorithms/sha3.rs - SHA3 family (256, 384, 512)
//! - algorithms/blake2b.rs - Blake2b implementation

// Import the modular structure
pub mod algorithms;

// Re-export the main entry point
pub use algorithms::{
    Blake2bBuilder, Sha3_256Builder, Sha3_384Builder, Sha3_512Builder, Sha256Builder,
};

/// Entry point for hash operations - README.md pattern
/// Clean, modular replacement for monolithic implementation
pub struct Hash;

impl Hash {
    /// Use SHA-256 - README.md pattern
    #[must_use]
    pub fn sha256() -> Sha256Builder {
        Sha256Builder::new()
    }

    /// Use SHA3-256 - README.md pattern  
    #[must_use]
    pub fn sha3_256() -> Sha3_256Builder {
        Sha3_256Builder::new()
    }

    /// Use SHA3-384 - README.md pattern
    #[must_use]
    pub fn sha3_384() -> Sha3_384Builder {
        Sha3_384Builder::new()
    }

    /// Use SHA3-512 - README.md pattern  
    #[must_use]
    pub fn sha3_512() -> Sha3_512Builder {
        Sha3_512Builder::new()
    }

    /// Use Blake2b - README.md pattern
    #[must_use]
    pub fn blake2b() -> Blake2bBuilder {
        Blake2bBuilder::new()
    }
}
