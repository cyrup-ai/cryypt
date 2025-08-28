//! Hash algorithm implementations
//!
//! Modular hash algorithm builders following single responsibility principle.

pub mod blake2b;
pub mod sha256;
pub mod sha3;

// Re-export all builders for convenience
pub use blake2b::*;
pub use sha3::*;
pub use sha256::*;
