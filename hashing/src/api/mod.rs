//! Fluent hashing API with zero boxing
//!
//! Usage: `let result = Hash::sha256().with_data(b"...").with_salt(b"...").with_passes(16).hash().await`

mod blake2b_builder;
mod builder_traits;
mod hash;
mod hash_builder;
mod passes;
mod sha256_builder;
mod sha3_builder;
mod states;

pub use blake2b_builder::Blake2bBuilder;
pub use builder_traits::{AsyncHashResult, DataBuilder, HashExecutor, PassesBuilder, SaltBuilder};
pub use hash::{Blake2bHash, Hash, Sha256Hash, Sha3_256Hash, Sha3_384Hash, Sha3_512Hash};
pub use hash_builder::HashBuilder;
pub use passes::HashPasses;
pub use sha256_builder::Sha256Builder;
pub use sha3_builder::Sha3Builder;
pub use states::{HasData, HasPasses, HasSalt, NoData, NoPasses, NoSalt};
