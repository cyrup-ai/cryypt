//! Vault Implementation Details
//!
//! Implementation of vault builder methods and future traits

#[cfg(feature = "vault")]
use super::vault::{VaultWithPath, VaultWithPathAndHandler};

#[cfg(feature = "vault")]
impl VaultWithPath {
    /// Add passphrase to vault builder
    pub fn with_passphrase<P: AsRef<str>>(mut self, passphrase: P) -> Self {
        self.passphrase = Some(passphrase.as_ref().to_string());
        self
    }

    /// Add configuration to vault builder
    pub fn with_config(mut self, config: cryypt_vault::config::VaultConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Add `on_result` handler - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> VaultWithPathAndHandler<F, T>
    where
        F: FnOnce(cryypt_vault::error::VaultResult<cryypt_vault::core::Vault>) -> T
            + Send
            + 'static,
        T: Send + 'static,
    {
        VaultWithPathAndHandler {
            path: self.path,
            config: self.config,
            passphrase: self.passphrase,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Convert to future for .await syntax
    pub fn create_and_unlock(self) -> cryypt_vault::core::Vault {
        // Create vault with configuration if provided
        let result = if let Some(config) = self.config {
            cryypt_vault::core::Vault::with_fortress_encryption(config)
        } else {
            Ok(cryypt_vault::core::Vault::new())
        };

        // Default unwrapping: Ok(vault) => vault, Err(_) => new empty vault
        match result {
            Ok(vault) => vault,
            Err(_) => cryypt_vault::core::Vault::new(),
        }
    }
}

// Implement IntoFuture for VaultWithPath to enable .await
#[cfg(feature = "vault")]
impl std::future::IntoFuture for VaultWithPath {
    type Output = cryypt_vault::core::Vault;
    type IntoFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            // Create vault with configuration if provided
            let result = if let Some(config) = self.config {
                cryypt_vault::core::Vault::with_fortress_encryption(config)
            } else {
                Ok(cryypt_vault::core::Vault::new())
            };

            // Default unwrapping: Ok(vault) => vault, Err(_) => new empty vault
            match result {
                Ok(vault) => vault,
                Err(_) => cryypt_vault::core::Vault::new(),
            }
        })
    }
}

#[cfg(feature = "vault")]
impl<F, T> VaultWithPathAndHandler<F, T>
where
    F: FnOnce(cryypt_vault::error::VaultResult<cryypt_vault::core::Vault>) -> T + Send + 'static,
    T: Send + 'static,
{
    /// Apply result handler and create vault
    pub async fn execute(self) -> T {
        let handler = self.result_handler;

        // Create vault configuration using path if provided
        let config = if let Some(mut config) = self.config {
            // Update vault path if provided
            if !self.path.is_empty() && self.path != "./vault" {
                config.vault_path = std::path::PathBuf::from(&self.path);
            }
            config
        } else if !self.path.is_empty() {
            // Create new config with specified path
            cryypt_vault::config::VaultConfig {
                vault_path: std::path::PathBuf::from(&self.path),
                ..Default::default()
            }
        } else {
            // Use default config
            cryypt_vault::config::VaultConfig::default()
        };

        // Create vault with configuration
        let result = cryypt_vault::core::Vault::with_fortress_encryption(config);

        // If vault creation succeeded and passphrase is provided, unlock it
        let final_result = match result {
            Ok(vault) => {
                if let Some(passphrase) = &self.passphrase {
                    // Attempt to unlock with provided passphrase
                    match vault.unlock(passphrase).await {
                        Ok(unlock_request) => {
                            match unlock_request.await {
                                Ok(()) => Ok(vault),
                                Err(_unlock_err) => {
                                    // Unlock failed but return vault (user can unlock later)
                                    Ok(vault)
                                }
                            }
                        }
                        Err(_) => {
                            // Failed to create unlock request, return vault anyway
                            Ok(vault)
                        }
                    }
                } else {
                    Ok(vault)
                }
            }
            Err(e) => Err(e),
        };

        // Apply result handler
        handler(final_result)
    }
}

// Implement IntoFuture for VaultWithPathAndHandler to enable .await
#[cfg(feature = "vault")]
impl<F, T> std::future::IntoFuture for VaultWithPathAndHandler<F, T>
where
    F: FnOnce(cryypt_vault::error::VaultResult<cryypt_vault::core::Vault>) -> T + Send + 'static,
    T: Send + 'static,
{
    type Output = T;
    type IntoFuture = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.execute())
    }
}
