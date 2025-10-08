//! Vault Master Builder
//!
//! Master builder for vault operations with path configuration and result handlers

/// Master builder for vault operations
#[cfg(feature = "vault")]
pub struct VaultMasterBuilder;

/// Vault builder with path configuration
#[cfg(feature = "vault")]
pub struct VaultWithPath {
    pub(super) path: String,
    pub(super) config: Option<cryypt_vault::config::VaultConfig>,
    pub(super) passphrase: Option<String>,
}

/// Vault builder with path and result handler
#[cfg(feature = "vault")]
pub struct VaultWithPathAndHandler<F, T> {
    pub(super) path: String,
    pub(super) config: Option<cryypt_vault::config::VaultConfig>,
    pub(super) passphrase: Option<String>,
    pub(super) result_handler: F,
    pub(super) _phantom: std::marker::PhantomData<T>,
}

#[cfg(feature = "vault")]
impl VaultMasterBuilder {
    /// Create a new vault at path - README.md pattern
    pub fn create<P: AsRef<str>>(self, path: P) -> VaultWithPath {
        VaultWithPath {
            path: path.as_ref().to_string(),
            config: None,
            passphrase: None,
        }
    }

    /// Create a vault with configuration - README.md pattern
    #[must_use]
    pub fn with_config(self, config: cryypt_vault::config::VaultConfig) -> VaultWithPath {
        VaultWithPath {
            path: "./vault".to_string(),
            config: Some(config),
            passphrase: None,
        }
    }

    /// Create a vault at specified path - README.md pattern
    pub fn at_path<P: AsRef<std::path::Path>>(self, path: P) -> VaultWithPath {
        VaultWithPath {
            path: path.as_ref().to_string_lossy().to_string(),
            config: None,
            passphrase: None,
        }
    }

    /// Create `SurrealDB` vault builder - polymorphic pattern
    #[must_use]
    pub fn surrealdb(
        self,
    ) -> cryypt_vault::api::SurrealDbBuilder<cryypt_vault::api::surrealdb_builder::NoConnection>
    {
        cryypt_vault::api::SurrealDbBuilder::new()
    }
}
