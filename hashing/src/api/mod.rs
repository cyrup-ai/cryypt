//! Fluent hashing API following README.md patterns
//!
//! NEW PATTERN: Actions take data as arguments
//! Usage: `Hash::sha256().on_result(handler).compute(data).await`

pub mod hash;

pub use hash::{Hash, Sha256Builder, Sha3_256Builder, Blake2bBuilder};