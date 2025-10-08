//! AWS interface module
//!
//! Contains AWS client setup, Secrets Manager operations, and high-level management interface.
//! Note: This file currently only contains Secrets Manager functionality. KMS and SSM
//! functionality would be added to their respective modules when implemented.

pub mod client;
pub mod manager;
pub mod secrets;
pub mod types;

pub use client::AwsSecretsInterface;
pub use manager::AwsSecretManager;
pub use secrets::AwsSecretStream;
pub use types::{AwsError, SecretSummary};
