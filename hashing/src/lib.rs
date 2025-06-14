//! Cryptographic hashing algorithms

pub mod api;
pub mod error;
pub mod hash_result;

// Re-export error types
pub use error::{HashError, Result};

// Re-export the fluent API
pub use api::Hash;
