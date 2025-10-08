//! High-level AWS Secret Manager interface
//!
//! Contains the high-level AwsSecretManager wrapper that provides initialization state management.

use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::client::AwsSecretsInterface;
use super::secrets::AwsSecretStream;
use super::types::{AwsError, SecretSummary};

/// Implement the AWS Secrets Manager interface using the "Hidden Box/Pin" pattern
#[derive(Debug, Default)]
pub struct AwsSecretManager {
    interface: AwsSecretsInterface,
    initialized: bool,
}

impl AwsSecretManager {
    /// Create a new AWS Secret Manager
    pub fn new(region: String, profile: String) -> Self {
        AwsSecretManager {
            interface: AwsSecretsInterface::new(region, profile),
            initialized: false,
        }
    }
}

impl AwsSecretManager {
    /// Initialize the AWS Secret Manager
    pub async fn initialize(&mut self) -> Result<(), AwsError> {
        self.interface.initialize().await?;
        self.initialized = true;
        Ok(())
    }

    /// List all secrets
    pub async fn list_secrets(&self) -> Result<Vec<SecretSummary>, AwsError> {
        if !self.initialized {
            return Err(AwsError::ClientNotInitialized);
        }

        self.interface.list_secrets().await
    }

    /// Get a secret value
    pub async fn get_secret_value(&self, name: &str) -> Result<Zeroizing<String>, AwsError> {
        if !self.initialized {
            return Err(AwsError::ClientNotInitialized);
        }

        self.interface.get_secret_value(name).await
    }

    /// Search for secrets
    pub async fn search_secrets(&self, pattern: &str) -> Result<Vec<SecretSummary>, AwsError> {
        if !self.initialized {
            return Err(AwsError::ClientNotInitialized);
        }

        self.interface.search_secrets(pattern).await
    }

    /// Stream all secrets
    pub async fn stream_secrets(&self) -> AwsSecretStream {
        let (tx, rx) = mpsc::channel(32);

        if !self.initialized {
            let _ = tx.send(Err(AwsError::ClientNotInitialized)).await;
            return AwsSecretStream::new(rx);
        }

        let interface = self.interface.clone();

        tokio::spawn(async move {
            match interface.list_secrets().await {
                Ok(secrets) => {
                    for secret in secrets {
                        if tx.send(Ok(secret)).await.is_err() {
                            break;
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                }
            }
        });

        AwsSecretStream::new(rx)
    }

    /// Create a new secret
    pub async fn create_secret(
        &self,
        name: &str,
        value: &str,
        description: Option<&str>,
    ) -> Result<String, AwsError> {
        if !self.initialized {
            return Err(AwsError::ClientNotInitialized);
        }

        self.interface.create_secret(name, value, description).await
    }

    /// Update an existing secret
    pub async fn update_secret(&self, name: &str, value: &str) -> Result<(), AwsError> {
        if !self.initialized {
            return Err(AwsError::ClientNotInitialized);
        }

        self.interface.update_secret(name, value).await
    }

    /// Delete a secret
    pub async fn delete_secret(&self, name: &str, force_delete: bool) -> Result<(), AwsError> {
        if !self.initialized {
            return Err(AwsError::ClientNotInitialized);
        }

        self.interface.delete_secret(name, force_delete).await
    }
}
