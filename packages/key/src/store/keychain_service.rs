//! Channel-based keychain service using `async_task` patterns
//!
//! Replaces problematic Parker-based static singleton with `RequestResponsePattern`
//! to eliminate thread safety violations per TURD.md Phase 1 requirements.

use crate::KeyError;
use async_task::patterns::{PatternBuilder, RequestResponsePattern};
use base64::{Engine, engine::general_purpose::STANDARD};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum KeychainRequest {
    Store {
        service_name: String,
        key_id: String,
        data: Vec<u8>,
    },
    Retrieve {
        service_name: String,
        key_id: String,
    },
    Delete {
        service_name: String,
        key_id: String,
    },
    Exists {
        service_name: String,
        key_id: String,
    },
}

#[derive(Debug)]
pub enum KeychainResponse {
    Stored,
    Retrieved(Vec<u8>),
    Deleted,
    Exists(bool),
}

pub struct KeychainServiceManager {
    pattern: RequestResponsePattern<KeychainRequest, Result<KeychainResponse, KeyError>>,
}

impl KeychainServiceManager {
    pub async fn new() -> Result<Self, KeyError> {
        let pattern = PatternBuilder::request_response();

        // Start the handler using existing async task patterns
        pattern
            .start_handler(|req| async move {
                match req {
                    KeychainRequest::Store {
                        service_name,
                        key_id,
                        data,
                    } => {
                        // Direct keychain operations without Parker
                        Self::perform_store(&service_name, &key_id, &data)
                            .map(|()| KeychainResponse::Stored)
                    }
                    KeychainRequest::Retrieve {
                        service_name,
                        key_id,
                    } => Self::perform_retrieve(&service_name, &key_id)
                        .map(KeychainResponse::Retrieved),
                    KeychainRequest::Delete {
                        service_name,
                        key_id,
                    } => Self::perform_delete(&service_name, &key_id)
                        .map(|()| KeychainResponse::Deleted),
                    KeychainRequest::Exists {
                        service_name,
                        key_id,
                    } => Self::perform_exists(&service_name, &key_id).map(KeychainResponse::Exists),
                }
            })
            .await
            .map_err(|e| KeyError::Internal(format!("Failed to start keychain handler: {e}")))?;

        Ok(Self { pattern })
    }

    pub async fn store(
        &self,
        service_name: String,
        key_id: String,
        data: Vec<u8>,
    ) -> Result<(), KeyError> {
        let request = KeychainRequest::Store {
            service_name,
            key_id,
            data,
        };
        match self
            .pattern
            .request(request)
            .await
            .map_err(|e| KeyError::Internal(e.to_string()))?
        {
            Ok(KeychainResponse::Stored) => Ok(()),
            Ok(_) => Err(KeyError::Internal("Unexpected response".to_string())),
            Err(e) => Err(e),
        }
    }

    pub async fn retrieve(
        &self,
        service_name: String,
        key_id: String,
    ) -> Result<Vec<u8>, KeyError> {
        let request = KeychainRequest::Retrieve {
            service_name,
            key_id,
        };
        match self
            .pattern
            .request(request)
            .await
            .map_err(|e| KeyError::Internal(e.to_string()))?
        {
            Ok(KeychainResponse::Retrieved(data)) => Ok(data),
            Ok(_) => Err(KeyError::Internal("Unexpected response".to_string())),
            Err(e) => Err(e),
        }
    }

    pub async fn delete(&self, service_name: String, key_id: String) -> Result<(), KeyError> {
        let request = KeychainRequest::Delete {
            service_name,
            key_id,
        };
        match self
            .pattern
            .request(request)
            .await
            .map_err(|e| KeyError::Internal(e.to_string()))?
        {
            Ok(KeychainResponse::Deleted) => Ok(()),
            Ok(_) => Err(KeyError::Internal("Unexpected response".to_string())),
            Err(e) => Err(e),
        }
    }

    pub async fn exists(&self, service_name: String, key_id: String) -> Result<bool, KeyError> {
        let request = KeychainRequest::Exists {
            service_name,
            key_id,
        };
        match self
            .pattern
            .request(request)
            .await
            .map_err(|e| KeyError::Internal(e.to_string()))?
        {
            Ok(KeychainResponse::Exists(exists)) => Ok(exists),
            Ok(_) => Err(KeyError::Internal("Unexpected response".to_string())),
            Err(e) => Err(e),
        }
    }

    /// List operation (returns error as keychains don't support enumeration)
    pub fn list(_service_name: String, _pattern: String) -> Result<Vec<String>, KeyError> {
        Err(KeyError::Internal(
            "Keychain does not support listing keys".to_string(),
        ))
    }

    /// Direct keychain store operation (thread-safe without Parker)
    fn perform_store(service: &str, key_id: &str, data: &[u8]) -> Result<(), KeyError> {
        let encoded = Zeroizing::new(STANDARD.encode(data));

        let keyring = keyring::Entry::new(service, key_id)
            .map_err(|e| KeyError::Internal(format!("Keychain error: {e}")))?;

        keyring
            .set_password(&encoded)
            .map_err(|e| KeyError::Internal(format!("Failed to store in keychain: {e}")))
    }

    /// Direct keychain retrieve operation (thread-safe without Parker)
    fn perform_retrieve(service: &str, key_id: &str) -> Result<Vec<u8>, KeyError> {
        let keyring = keyring::Entry::new(service, key_id)
            .map_err(|e| KeyError::Internal(format!("Keychain error: {e}")))?;

        let encoded = keyring
            .get_password()
            .map_err(|e| KeyError::Internal(format!("Failed to read from keychain: {e}")))?;

        STANDARD
            .decode(&encoded)
            .map_err(|e| KeyError::Internal(format!("Invalid key format: {e}")))
    }

    /// Direct keychain exists operation (thread-safe without Parker)
    fn perform_exists(service: &str, key_id: &str) -> Result<bool, KeyError> {
        let keyring = keyring::Entry::new(service, key_id)
            .map_err(|e| KeyError::Internal(format!("Keychain error: {e}")))?;

        match keyring.get_password() {
            Ok(_) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(KeyError::Internal(format!("Keychain error: {e}"))),
        }
    }

    /// Direct keychain delete operation (thread-safe without Parker)
    fn perform_delete(service: &str, key_id: &str) -> Result<(), KeyError> {
        let keyring = keyring::Entry::new(service, key_id)
            .map_err(|e| KeyError::Internal(format!("Keychain error: {e}")))?;

        keyring
            .delete_credential()
            .map_err(|e| KeyError::Internal(format!("Failed to delete from keychain: {e}")))
    }
}

/// Global keychain service instance using safe async patterns
use tokio::sync::OnceCell;
static KEYCHAIN_SERVICE: OnceCell<KeychainServiceManager> = OnceCell::const_new();

/// Get or initialize the global keychain service (thread-safe with channel patterns)
pub async fn get_keychain_service() -> Result<&'static KeychainServiceManager, KeyError> {
    KEYCHAIN_SERVICE
        .get_or_try_init(|| async { KeychainServiceManager::new().await })
        .await
        .map_err(|e| KeyError::Internal(format!("Failed to initialize keychain service: {e}")))
}

/// Create a new isolated keychain service instance (for tests and special cases)
/// This bypasses the global singleton to avoid concurrency issues in test environments
pub async fn create_isolated_keychain_service() -> Result<KeychainServiceManager, KeyError> {
    KeychainServiceManager::new().await
}
