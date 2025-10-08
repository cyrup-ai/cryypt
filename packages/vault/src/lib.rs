pub mod api;
pub mod auth;
pub mod config;
pub mod core;
pub mod db;
pub mod error;
pub mod logging;
pub mod operation;
pub mod security;
pub mod tui;

// TUI-specific modules
pub use tui::aws_interface;
pub use tui::pass_interface;

// Re-export the public API
pub use auth::{JwtHandler, VaultJwtClaims, extract_jwt_from_env};
pub use config::VaultConfig;
pub use core::{Vault, VaultValue};
pub use db::LocalVaultProvider;
pub use error::{VaultError, VaultResult};
pub use operation::{BoxedVaultOperation, VaultOperation};

// Re-export working vault operation builders
pub use api::{
    SurrealDbBuilder, SurrealDbBuilderWithChunk, SurrealDbBuilderWithHandler, VaultMasterBuilder,
};

// For backward compatibility
#[deprecated(since = "0.1.0", note = "Use LocalVaultProvider instead")]
pub type BasicVaultProvider = LocalVaultProvider;
