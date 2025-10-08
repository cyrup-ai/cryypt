//! Fluent hashing API following README.md patterns
//!
//! NEW PATTERN: Actions take data as arguments
//! Usage: `Hash::sha256().on_result(handler).compute(data).await`

pub mod blake2b_builder;
pub mod blake3_builder;
pub mod hash_entry;
pub mod hash_functions;
pub mod sha256_builder;
pub mod sha3_builder;

// Re-export main entry point
pub use hash_entry::Hash;

// Re-export all builder types
pub use blake2b_builder::{
    Blake2bBuilder, Blake2bBuilderWithChunk, Blake2bBuilderWithError, Blake2bBuilderWithHandler,
    Blake2bBuilderWithSize, Blake2bBuilderWithSizeAndHandler,
};

pub use blake3_builder::{Blake3Builder, Blake3WithChunkHandler, Blake3WithHandler};

pub use sha256_builder::{
    Sha256Builder, Sha256BuilderWithChunk, Sha256BuilderWithError, Sha256BuilderWithHandler,
    Sha256BuilderWithKey, Sha256BuilderWithKeyAndHandler,
};

pub use sha3_builder::{
    Sha3_256Builder, Sha3_256BuilderWithChunk, Sha3_256BuilderWithError,
    Sha3_256BuilderWithHandler, Sha3_384Builder, Sha3_384BuilderWithHandler, Sha3_512Builder,
    Sha3_512BuilderWithHandler,
};

// Keep backward compatibility with existing hash module
pub mod hash;
pub use hash::{
    Blake2bBuilder as LegacyBlake2bBuilder, Hash as LegacyHash,
    Sha3_256Builder as LegacySha3_256Builder, Sha3_384Builder as LegacySha3_384Builder,
    Sha3_512Builder as LegacySha3_512Builder,
};

pub use sha256_builder as legacy_sha256_builder;
pub use sha256_builder::{
    Sha256Builder as LegacySha256Builder, Sha256BuilderWithHandler as Sha256WithHandler,
    Sha256BuilderWithKey as Sha256WithKey,
    Sha256BuilderWithKeyAndHandler as Sha256WithKeyAndHandler,
};
