#![allow(clippy::new_without_default)]
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::unnecessary_to_owned)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::let_underscore_future)]
#![allow(clippy::module_inception)]
#![allow(clippy::derivable_impls)]
#![allow(clippy::default_constructed_unit_structs)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::single_match)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::type_complexity)]
#![allow(clippy::collapsible_else_if)]
#![allow(clippy::too_many_arguments)]

pub mod api;
pub mod auth;
pub mod config;
pub mod core;
pub mod db;
pub mod error;
pub mod logging;
pub mod operation;
pub mod tui;

// TUI-specific modules
pub use tui::aws_interface;
pub use tui::pass_interface;

// Re-export the public API
pub use api::VaultMasterBuilder;
pub use auth::{JwtHandler, VaultJwtClaims, extract_jwt_from_env};
pub use config::VaultConfig;
pub use core::{Vault, VaultValue};
pub use db::LocalVaultProvider;
pub use error::{VaultError, VaultResult};
pub use operation::{BoxedVaultOperation, VaultOperation};

// Re-export vault operation builders - commented out until vault_operations module is implemented
// pub use api::vault_operations::{
//     VaultGetHandler, VaultWithKey, VaultWithKeyAndHandler, VaultWithKeyAndTtl,
//     VaultWithKeyAndTtlAndHandler,
// };

// For backward compatibility
#[deprecated(since = "0.1.0", note = "Use LocalVaultProvider instead")]
pub type BasicVaultProvider = LocalVaultProvider;
