pub mod config;
pub mod core;
pub mod db;
pub mod error;
pub mod local;
pub mod operation;

// Re-export the public API
pub use config::VaultConfig;
pub use core::{Vault, VaultValue};
pub use error::{VaultError, VaultResult};
pub use local::LocalVaultProvider;
pub use operation::{BoxedVaultOperation, VaultOperation};

// For backward compatibility
#[deprecated(since = "0.1.0", note = "Use LocalVaultProvider instead")]
pub type BasicVaultProvider = LocalVaultProvider;
