//! AWS Secrets Manager operations
//!
//! Contains all Secrets Manager operations including get, put, list, search, create, update, and delete.

use aws_sdk_secretsmanager::types::{Filter, FilterNameStringType};
use tokio::sync::mpsc;
use zeroize::Zeroizing;

use super::client::AwsSecretsInterface;
use super::types::{AwsError, SecretSummary};

impl AwsSecretsInterface {
    /// List all secrets in the AWS Secrets Manager
    pub async fn list_secrets(&self) -> Result<Vec<SecretSummary>, AwsError> {
        let client = self.client.as_ref().ok_or(AwsError::ClientNotInitialized)?;

        let result = client
            .list_secrets()
            .send()
            .await
            .map_err(|e| AwsError::SdkOperationError(e.to_string()))?;
        let secrets = result.secret_list();

        let mut secret_summaries = Vec::new();
        for secret in secrets {
            let name = secret.name().unwrap_or_default().to_string();
            let arn = secret.arn().unwrap_or_default().to_string();
            let description = secret.description().unwrap_or_default().to_string();

            secret_summaries.push(SecretSummary {
                name,
                arn,
                description,
            });
        }

        Ok(secret_summaries)
    }

    /// Get a secret value by name
    pub async fn get_secret_value(&self, secret_name: &str) -> Result<Zeroizing<String>, AwsError> {
        let client = self.client.as_ref().ok_or(AwsError::ClientNotInitialized)?;

        let result = client
            .get_secret_value()
            .secret_id(secret_name)
            .send()
            .await
            .map_err(|e| AwsError::SdkOperationError(e.to_string()))?;

        let secret_string = result
            .secret_string()
            .ok_or(AwsError::SecretNotFound(secret_name.to_string()))?
            .to_string();

        Ok(Zeroizing::new(secret_string))
    }

    /// Search for secrets by name pattern
    pub async fn search_secrets(&self, pattern: &str) -> Result<Vec<SecretSummary>, AwsError> {
        let client = self.client.as_ref().ok_or(AwsError::ClientNotInitialized)?;

        let filter = Filter::builder()
            .key(FilterNameStringType::Name)
            .values(pattern)
            .build();

        let result = client
            .list_secrets()
            .filters(filter)
            .send()
            .await
            .map_err(|e| AwsError::SdkOperationError(e.to_string()))?;

        let secrets = result.secret_list();

        let mut secret_summaries = Vec::new();
        for secret in secrets {
            let name = secret.name().unwrap_or_default().to_string();
            let arn = secret.arn().unwrap_or_default().to_string();
            let description = secret.description().unwrap_or_default().to_string();

            secret_summaries.push(SecretSummary {
                name,
                arn,
                description,
            });
        }

        Ok(secret_summaries)
    }

    /// Create a new secret
    pub async fn create_secret(
        &self,
        name: &str,
        value: &str,
        description: Option<&str>,
    ) -> Result<String, AwsError> {
        let client = self.client.as_ref().ok_or(AwsError::ClientNotInitialized)?;

        let mut request = client.create_secret().name(name).secret_string(value);

        if let Some(desc) = description {
            request = request.description(desc);
        }

        let result = request
            .send()
            .await
            .map_err(|e| AwsError::SdkOperationError(e.to_string()))?;

        let arn = result
            .arn()
            .ok_or(AwsError::OperationFailed("Failed to get ARN".to_string()))?
            .to_string();

        Ok(arn)
    }

    /// Update an existing secret
    pub async fn update_secret(&self, name: &str, value: &str) -> Result<(), AwsError> {
        let client = self.client.as_ref().ok_or(AwsError::ClientNotInitialized)?;

        client
            .put_secret_value()
            .secret_id(name)
            .secret_string(value)
            .send()
            .await
            .map_err(|e| AwsError::SdkOperationError(e.to_string()))?;

        Ok(())
    }

    /// Delete a secret
    pub async fn delete_secret(&self, name: &str, force_delete: bool) -> Result<(), AwsError> {
        let client = self.client.as_ref().ok_or(AwsError::ClientNotInitialized)?;

        client
            .delete_secret()
            .secret_id(name)
            .force_delete_without_recovery(force_delete)
            .send()
            .await
            .map_err(|e| AwsError::SdkOperationError(e.to_string()))?;

        Ok(())
    }
}

/// The AwsSecretStream allows for asynchronous streaming of secrets
pub struct AwsSecretStream {
    receiver: mpsc::Receiver<Result<SecretSummary, AwsError>>,
}

impl AwsSecretStream {
    /// Create a new AwsSecretStream from a receiver channel
    pub fn new(receiver: mpsc::Receiver<Result<SecretSummary, AwsError>>) -> Self {
        AwsSecretStream { receiver }
    }

    /// Get the next secret asynchronously
    pub async fn next(&mut self) -> Option<Result<SecretSummary, AwsError>> {
        self.receiver.recv().await
    }
}
