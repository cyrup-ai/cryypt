//! # Cyrup Key Management
//!
//! Key management library following README.md patterns exactly.
//!
//! ## Features
//!
//! - **Key Generation**: Secure key generation with entropy sources
//! - **Key Storage**: File-based and keychain storage backends
//! - **Key Retrieval**: Version-based key retrieval
//! - **True Async**: Channel-based async operations
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use cryypt_key::{Key, store::FileKeyStore, bits_macro::Bits};
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let master_key = [1u8; 32]; // In production, generate this securely
//!
//! // Generate key - NEW PATTERN: builder chain with action
//! let key = Key::size(256u32.bits())
//!     .with_store(FileKeyStore::at("./keys").with_master_key(master_key))
//!     .with_namespace("my-app")
//!     .version(1)
//!     .generate()
//!     .await?;
//! # Ok(())
//! # }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

// Internal macro implementations (hidden from users per ARCHITECTURE.md)
mod result_macro;
mod on_result;

pub mod api;
pub mod bits_macro;
pub mod entropy;
pub mod error;
pub mod key_id;
pub mod key_result;
pub mod store;
pub mod traits;

// Re-export core types
pub use error::{KeyError, Result};
pub use key_id::{KeyId, SimpleKeyId};
pub use key_result::KeyResult;

// Export on_result for main cryypt crate
pub use on_result::on_result;

// Re-export the main API
pub use api::{KeyBuilder, KeyBuilderWithStore, KeyBuilderWithStoreAndNamespace, KeyBuilderReady, ActualKey};
pub use store::FileKeyStore;

/// Main entry point - README.md pattern: Key operations
pub struct Key;

impl Key {
    /// Create key builder with specified size - README.md pattern
    pub fn size(size_bits: impl Into<u32>) -> KeyBuilder {
        KeyBuilder::new(size_bits.into())
    }
}

/// Prelude module for convenient imports
pub mod prelude {
    pub use crate::{
        Key, KeyError, Result,
        api::{KeyBuilder, KeyBuilderReady, ActualKey},
        store::FileKeyStore,
        bits_macro::Bits,
    };
}