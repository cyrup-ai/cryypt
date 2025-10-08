//! AWS client setup and configuration
//!
//! Contains AWS client initialization, credential handling, and region configuration.

use aws_config::Region;
use aws_config::profile::ProfileFileCredentialsProvider;
use aws_sdk_secretsmanager::Client;

use super::types::AwsError;

/// Interface for interacting with AWS Secrets Manager
#[derive(Debug)]
pub struct AwsSecretsInterface {
    pub(crate) client: Option<Client>,
    pub(crate) region: String,
    pub(crate) profile: String,
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
}

impl Default for AwsSecretsInterface {
    fn default() -> Self {
        AwsSecretsInterface {
            client: None,
            region: "us-east-1".to_string(),
            profile: "default".to_string(),
        }
    }
}

impl AwsSecretsInterface {
    /// Initialize the AWS Secrets Manager client
    pub async fn initialize(&mut self) -> Result<(), AwsError> {
        let region = Region::new(self.region.clone());
        let credentials_provider = ProfileFileCredentialsProvider::builder()
            .profile_name(&self.profile)
            .build();

        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .credentials_provider(credentials_provider)
            .region(region)
            .load()
            .await;

        self.client = Some(Client::new(&config));
        Ok(())
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
