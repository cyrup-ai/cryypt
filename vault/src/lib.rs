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
pub use config::VaultConfig;
pub use core::{Vault, VaultValue};
pub use error::{VaultError, VaultResult};
pub use db::LocalVaultProvider;
pub use operation::{BoxedVaultOperation, VaultOperation};

// For backward compatibility
#[deprecated(since = "0.1.0", note = "Use LocalVaultProvider instead")]
pub type BasicVaultProvider = LocalVaultProvider;
