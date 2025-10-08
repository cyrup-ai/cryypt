//! Hash builder module with decomposed implementations

// Re-export the common HashBuilder and its base methods
pub use common::HashBuilder;

// Import individual implementations
mod blake2b;
mod common;
mod sha256;
pub mod sha3;
mod stream;

// Re-export streaming types
pub use stream::{HashAlgorithm, HashStream};