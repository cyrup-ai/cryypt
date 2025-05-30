//! Fluent hashing API with zero boxing
//!
//! Usage: `let result = Hash::sha256().with_data(b"...").with_salt(b"...").with_passes(16).hash().await`

mod blake2b_builder;
mod builder_traits;
mod sha256_builder;
mod sha3_builder;
mod passes;
mod states;
mod hash_builder;
mod hash;

pub use blake2b_builder::Blake2bBuilder;
pub use builder_traits::{DataBuilder, SaltBuilder, PassesBuilder, HashExecutor, AsyncHashResult};
pub use sha3_builder::Sha3Builder;
pub use sha256_builder::Sha256Builder;
pub use passes::HashPasses;
pub use states::{NoData, HasData, NoSalt, HasSalt, NoPasses, HasPasses};
pub use hash_builder::HashBuilder;
pub use hash::{Hash, Sha256Hash, Sha3_256Hash, Sha3_384Hash, Sha3_512Hash, Blake2bHash};
