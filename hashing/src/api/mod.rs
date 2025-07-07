//! Fluent hashing API following README.md patterns
//!
//! NEW PATTERN: Actions take data as arguments
//! Usage: `Hash::sha256().on_result(handler).compute(data).await`

pub mod hash;
pub mod sha256_builder;

pub use hash::{Hash, Sha3_256Builder, Sha3_384Builder, Sha3_512Builder, Blake2bBuilder};
pub use sha256_builder::{Sha256Builder, Sha256WithHandler, Sha256WithKey, Sha256WithKeyAndHandler};