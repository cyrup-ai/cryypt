//! AES encryption builders following README.md patterns exactly - decomposed modules

// Declare existing submodules
pub mod aad;
pub mod decrypt;
pub mod encrypt;
pub mod stream;

// Declare new decomposed submodules
mod builder_types;
mod decrypt_operations;
mod encrypt_operations;
mod stream_operations;

// Re-export all public types and functions from decomposed modules
pub use builder_types::{AesBuilder, AesWithKey, AesWithKeyAndChunkHandler, AesWithKeyAndHandler};
