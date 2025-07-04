//! Cryptographic hashing algorithms

pub mod api;
pub mod error;
pub mod hash_result;
mod result_macro;
mod chunk_macro;

// Re-export error types
pub use error::{HashError, Result};

// Re-export the fluent API
pub use api::Hash;

// Re-export hash result type
pub use hash_result::HashResult;

// Re-export the on_result! macro
pub use hash_on_result as on_result;

// on_chunk is already exported via #[macro_export]
