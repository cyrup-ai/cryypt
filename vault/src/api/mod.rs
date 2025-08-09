//! Vault API module
//!
//! Contains fluent builders for vault operations following README.md patterns

pub mod vault_operations;

// Re-export the main operation builders
pub use vault_operations::{
    VaultGetHandler, VaultWithKey, VaultWithKeyAndHandler, VaultWithKeyAndTtl,
    VaultWithKeyAndTtlAndHandler,
};
