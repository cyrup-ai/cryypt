use aws_config::profile::ProfileFileCredentialsProvider;
use aws_config::Region;
use aws_sdk_secretsmanager::{Client, Error};
use aws_sdk_secretsmanager::model::Filter;
use aws_sdk_secretsmanager::model::FilterNameString;
use tokio::sync::mpsc;
use std::str::FromStr;
use zeroize::Zeroizing;
use log::{debug, error, info};

/// Interface for interacting with AWS Secrets Manager
pub struct AwsSecretsInterface {
    client: Option<Client>,
    region: String,
    profile: String,
}

/// Implementation of AWS Secrets Manager interface
impl AwsSecretsInterface {
    /// Create a new AWS Secrets Manager interface
    pub fn new(region: String, profile: String) -> Self {
        AwsSecretsInterface {
            client: None,
            region,
            profile,
        }
    }

    /// Create a default AWS Secrets Manager interface (us-east-1, default profile)
    pub fn default() -> Self {
        AwsSecretsInterface {
            client: None,
            region: "us-east-1".to_string(),
            profile: "default".to_string(),
        }
    }

    /// Initialize the AWS Secrets Manager client
    pub async fn initialize(&mut self) -> Result<(), AwsError> {
        let region = Region::new(self.region.clone());
        let credentials_provider = ProfileFileCredentialsProvider::builder()
            .profile_name(&self.profile)
            .build();

        let config = aws_config::from_env()
            .credentials_provider(credentials_provider)
            .region(region)
            .load()
            .await;

        self.client = Some(Client::new(&config));
        Ok(())
    }

    /// List all secrets in the AWS Secrets Manager
    pub async fn list_secrets(&self) -> Result<Vec<SecretSummary>, AwsError> {
        let client = self.client.as_ref().ok_or(AwsError::ClientNotInitialized)?;
        
        let result = client.list_secrets().send().await?;
        let secrets = result.secret_list().unwrap_or_default();
        
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
        
        let result = client.get_secret_value()
            .secret_id(secret_name)
            .send()
            .await?;
        
        let secret_string = result.secret_string()
            .ok_or(AwsError::SecretNotFound(secret_name.to_string()))?
            .to_string();
        
        Ok(Zeroizing::new(secret_string))
    }

    /// Search for secrets by name pattern
    pub async fn search_secrets(&self, pattern: &str) -> Result<Vec<SecretSummary>, AwsError> {
        let client = self.client.as_ref().ok_or(AwsError::ClientNotInitialized)?;
        
        let filter = Filter::builder()
            .key(FilterNameString::Name)
            .values(pattern)
            .build();
        
        let result = client.list_secrets()
            .filters(filter)
            .send()
            .await?;
        
        let secrets = result.secret_list().unwrap_or_default();
        
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
        description: Option<&str>
    ) -> Result<String, AwsError> {
        let client = self.client.as_ref().ok_or(AwsError::ClientNotInitialized)?;
        
        let mut request = client.create_secret()
            .name(name)
            .secret_string(value);
        
        if let Some(desc) = description {
            request = request.description(desc);
        }
        
        let result = request.send().await?;
        
        let arn = result.arn().ok_or(AwsError::OperationFailed("Failed to get ARN".to_string()))?
            .to_string();
        
        Ok(arn)
    }
    
    /// Update an existing secret
    pub async fn update_secret(
        &self, 
        name: &str, 
        value: &str
    ) -> Result<(), AwsError> {
        let client = self.client.as_ref().ok_or(AwsError::ClientNotInitialized)?;
        
        client.put_secret_value()
            .secret_id(name)
            .secret_string(value)
            .send()
            .await?;
        
        Ok(())
    }
    
    /// Delete a secret
    pub async fn delete_secret(
        &self, 
        name: &str, 
        force_delete: bool
    ) -> Result<(), AwsError> {
        let client = self.client.as_ref().ok_or(AwsError::ClientNotInitialized)?;
        
        client.delete_secret()
            .secret_id(name)
            .force_delete_without_recovery(force_delete)
            .send()
            .await?;
        
        Ok(())
    }
}

/// Summary of an AWS Secret
#[derive(Debug, Clone)]
pub struct SecretSummary {
    pub name: String,
    pub arn: String,
    pub description: String,
}

/// Error type for AWS operations
#[derive(Debug, thiserror::Error)]
pub enum AwsError {
    #[error("AWS SDK error: {0}")]
    SdkError(#[from] Error),
    
    #[error("Client not initialized")]
    ClientNotInitialized,
    
    #[error("Secret not found: {0}")]
    SecretNotFound(String),
    
    #[error("Operation failed: {0}")]
    OperationFailed(String),
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

/// Implement the AWS Secrets Manager interface using the "Hidden Box/Pin" pattern
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
    
    /// Create a default AWS Secret Manager
    pub fn default() -> Self {
        AwsSecretManager {
            interface: AwsSecretsInterface::default(),
            initialized: false,
        }
    }
    
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
        description: Option<&str>
    ) -> Result<String, AwsError> {
        if !self.initialized {
            return Err(AwsError::ClientNotInitialized);
        }
        
        self.interface.create_secret(name, value, description).await
    }
    
    /// Update an existing secret
    pub async fn update_secret(
        &self, 
        name: &str, 
        value: &str
    ) -> Result<(), AwsError> {
        if !self.initialized {
            return Err(AwsError::ClientNotInitialized);
        }
        
        self.interface.update_secret(name, value).await
    }
    
    /// Delete a secret
    pub async fn delete_secret(
        &self, 
        name: &str, 
        force_delete: bool
    ) -> Result<(), AwsError> {
        if !self.initialized {
            return Err(AwsError::ClientNotInitialized);
        }
        
        self.interface.delete_secret(name, force_delete).await
    }
}

// Make AwsSecretsInterface cloneable for use in async contexts
impl Clone for AwsSecretsInterface {
    fn clone(&self) -> Self {
        AwsSecretsInterface {
            client: self.client.clone(),
            region: self.region.clone(),
            profile: self.profile.clone(),
        }
    }
}
