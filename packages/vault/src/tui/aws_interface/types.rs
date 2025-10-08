//! AWS types and error definitions
//!
//! Contains common types and error handling for AWS operations.

use aws_sdk_secretsmanager::Error;

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

    #[error("SDK operation error: {0}")]
    SdkOperationError(String),
}
