//! Fluent hashing API following README.md patterns
//!
//! Usage: `let result = Hash::sha256().on_result!(|r| { Ok => Ok(r), Err(e) => Err(e) }).compute(data).await?`

mod hash;
mod hash_builder;
mod passes;
mod states;

pub use hash::{Blake2bHash, Hash, Sha256Hash, Sha3_256Hash, Sha3_384Hash, Sha3_512Hash};
pub use hash_builder::{HashBuilder, HashStream};
pub use passes::HashPasses;
pub use states::{HasData, HasPasses, HasSalt, NoData, NoPasses, NoSalt};
