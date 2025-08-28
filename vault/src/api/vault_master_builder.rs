//! Vault master builder for polymorphic API

use super::surrealdb_builder::SurrealDbBuilder;

/// Master builder for vault operations
pub struct VaultMasterBuilder;

impl VaultMasterBuilder {
    /// Create a new vault master builder
    pub fn new() -> Self {
        Self
    }

    /// Create SurrealDB vault builder
    pub fn surrealdb(self) -> SurrealDbBuilder<super::surrealdb_builder::NoConnection> {
        SurrealDbBuilder::new()
    }
}