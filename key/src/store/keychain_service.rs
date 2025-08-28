//! Async keychain service using channels (README.md compliant)
//!
//! Implements "True async with channels" architecture by isolating blocking keychain
//! operations in a dedicated service thread that communicates via async channels.

use crate::KeyError;
use tokio::sync::{mpsc, oneshot};
use base64::{Engine, engine::general_purpose::STANDARD};
use zeroize::Zeroizing;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// Configuration for keychain service
#[derive(Debug, Clone)]
pub struct KeychainServiceConfig {
    /// Channel buffer size for operations
    pub channel_buffer_size: usize,
    /// Service thread name for debugging
    pub thread_name: String,
}

impl Default for KeychainServiceConfig {
    fn default() -> Self {
        Self {
            channel_buffer_size: 100,
            thread_name: "keychain-service".to_string(),
        }
    }
}

/// Operations supported by the keychain service
#[derive(Debug)]
pub enum KeychainOperation {
    Store { 
        service: String, 
        key_id: String, 
        data: Zeroizing<Vec<u8>>, 
        respond_to: oneshot::Sender<Result<(), KeyError>> 
    },
    Retrieve { 
        service: String, 
        key_id: String, 
        respond_to: oneshot::Sender<Result<Vec<u8>, KeyError>> 
    },
    Exists { 
        service: String, 
        key_id: String, 
        respond_to: oneshot::Sender<Result<bool, KeyError>> 
    },
    Delete { 
        service: String, 
        key_id: String, 
        respond_to: oneshot::Sender<Result<(), KeyError>> 
    },
    List { 
        service: String, 
        pattern: String, 
        respond_to: oneshot::Sender<Result<Vec<String>, KeyError>> 
    },
    /// Shutdown signal for graceful service termination
    #[allow(dead_code)]
    Shutdown {
        respond_to: oneshot::Sender<Result<(), KeyError>>
    },
}

/// Async keychain service that handles blocking operations in a dedicated thread
pub struct KeychainService {
    operation_tx: mpsc::Sender<KeychainOperation>,
    service_thread: Option<std::thread::JoinHandle<()>>,
    shutdown_signal: Arc<AtomicBool>,
}

impl KeychainService {
    /// Create new keychain service with default configuration
    pub fn new() -> Result<Self, KeyError> {
        Self::with_config(KeychainServiceConfig::default())
    }

    /// Create new keychain service with custom configuration
    pub fn with_config(config: KeychainServiceConfig) -> Result<Self, KeyError> {
        let (operation_tx, operation_rx) = mpsc::channel(config.channel_buffer_size);
        let shutdown_signal = Arc::new(AtomicBool::new(false));
        let shutdown_signal_clone = Arc::clone(&shutdown_signal);
        
        // Spawn dedicated thread for blocking keychain operations with proper name
        let thread_name = config.thread_name.clone();
        let service_thread = std::thread::Builder::new()
            .name(thread_name)
            .spawn(move || {
                Self::service_thread(operation_rx, shutdown_signal_clone);
            })
            .map_err(|e| KeyError::Internal(format!("Failed to spawn keychain service thread: {}", e)))?;
        
        Ok(Self { 
            operation_tx,
            service_thread: Some(service_thread),
            shutdown_signal,
        })
    }

    /// Service thread that handles blocking keychain operations
    fn service_thread(mut operation_rx: mpsc::Receiver<KeychainOperation>, shutdown_signal: Arc<AtomicBool>) {
        // Use tokio runtime for channel operations in service thread
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build() {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("Failed to create keychain service runtime: {}", e);
                return;
            }
        };

        rt.block_on(async {
            loop {
                // Check shutdown signal
                if shutdown_signal.load(Ordering::Relaxed) {
                    break;
                }

                // Use select to handle both incoming operations and shutdown
                tokio::select! {
                    operation = operation_rx.recv() => {
                        match operation {
                            Some(op) => {
                                let is_shutdown = matches!(op, KeychainOperation::Shutdown { .. });
                                Self::handle_operation(op);
                                if is_shutdown {
                                    break;
                                }
                            }
                            None => {
                                // Channel closed, exit gracefully
                                break;
                            }
                        }
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                        // Periodic check for shutdown signal
                        continue;
                    }
                }
            }
        });
    }

    /// Handle individual keychain operation (blocking operations isolated here)
    fn handle_operation(operation: KeychainOperation) {
        match operation {
            KeychainOperation::Store { service, key_id, data, respond_to } => {
                let result = Self::perform_store(&service, &key_id, &data);
                let _ = respond_to.send(result);
            }
            KeychainOperation::Retrieve { service, key_id, respond_to } => {
                let result = Self::perform_retrieve(&service, &key_id);
                let _ = respond_to.send(result);
            }
            KeychainOperation::Exists { service, key_id, respond_to } => {
                let result = Self::perform_exists(&service, &key_id);
                let _ = respond_to.send(result);
            }
            KeychainOperation::Delete { service, key_id, respond_to } => {
                let result = Self::perform_delete(&service, &key_id);
                let _ = respond_to.send(result);
            }
            KeychainOperation::List { service, pattern, respond_to } => {
                let result = Self::perform_list(&service, &pattern);
                let _ = respond_to.send(result);
            }
            KeychainOperation::Shutdown { respond_to } => {
                let _ = respond_to.send(Ok(()));
            }
        }
    }

    /// Blocking keychain store operation (isolated in service thread)
    fn perform_store(service: &str, key_id: &str, data: &[u8]) -> Result<(), KeyError> {
        let encoded = Zeroizing::new(STANDARD.encode(data));
        
        let keyring = keyring::Entry::new(service, key_id)
            .map_err(|e| KeyError::Internal(format!("Keychain error: {}", e)))?;

        keyring.set_password(&encoded)
            .map_err(|e| KeyError::Internal(format!("Failed to store in keychain: {}", e)))
    }

    /// Blocking keychain retrieve operation (isolated in service thread)
    fn perform_retrieve(service: &str, key_id: &str) -> Result<Vec<u8>, KeyError> {
        let keyring = keyring::Entry::new(service, key_id)
            .map_err(|e| KeyError::Internal(format!("Keychain error: {}", e)))?;

        let encoded = keyring.get_password()
            .map_err(|e| KeyError::Internal(format!("Failed to read from keychain: {}", e)))?;

        STANDARD.decode(&encoded)
            .map_err(|e| KeyError::Internal(format!("Invalid key format: {}", e)))
    }

    /// Blocking keychain exists operation (isolated in service thread)
    fn perform_exists(service: &str, key_id: &str) -> Result<bool, KeyError> {
        let keyring = keyring::Entry::new(service, key_id)
            .map_err(|e| KeyError::Internal(format!("Keychain error: {}", e)))?;

        match keyring.get_password() {
            Ok(_) => Ok(true),
            Err(keyring::Error::NoEntry) => Ok(false),
            Err(e) => Err(KeyError::Internal(format!("Keychain error: {}", e))),
        }
    }

    /// Blocking keychain delete operation (isolated in service thread)
    fn perform_delete(service: &str, key_id: &str) -> Result<(), KeyError> {
        let keyring = keyring::Entry::new(service, key_id)
            .map_err(|e| KeyError::Internal(format!("Keychain error: {}", e)))?;

        keyring.delete_credential()
            .map_err(|e| KeyError::Internal(format!("Failed to delete from keychain: {}", e)))
    }

    /// Keychain list operation (returns error as keychains don't support enumeration)
    fn perform_list(_service: &str, _pattern: &str) -> Result<Vec<String>, KeyError> {
        Err(KeyError::Internal(
            "Keychain does not support listing keys".to_string(),
        ))
    }

    /// Async store operation via channel
    pub async fn store(&self, service: String, key_id: String, data: Vec<u8>) -> Result<(), KeyError> {
        let (tx, rx) = oneshot::channel();
        let data = Zeroizing::new(data);
        
        self.operation_tx.send(KeychainOperation::Store {
            service, key_id, data, respond_to: tx
        }).await.map_err(|_| KeyError::Internal("Keychain service unavailable".to_string()))?;

        rx.await.map_err(|_| KeyError::Internal("Keychain operation failed".to_string()))?
    }

    /// Async retrieve operation via channel
    pub async fn retrieve(&self, service: String, key_id: String) -> Result<Vec<u8>, KeyError> {
        let (tx, rx) = oneshot::channel();
        
        self.operation_tx.send(KeychainOperation::Retrieve {
            service, key_id, respond_to: tx
        }).await.map_err(|_| KeyError::Internal("Keychain service unavailable".to_string()))?;

        rx.await.map_err(|_| KeyError::Internal("Keychain operation failed".to_string()))?
    }

    /// Async exists operation via channel
    pub async fn exists(&self, service: String, key_id: String) -> Result<bool, KeyError> {
        let (tx, rx) = oneshot::channel();
        
        self.operation_tx.send(KeychainOperation::Exists {
            service, key_id, respond_to: tx
        }).await.map_err(|_| KeyError::Internal("Keychain service unavailable".to_string()))?;

        rx.await.map_err(|_| KeyError::Internal("Keychain operation failed".to_string()))?
    }

    /// Async delete operation via channel
    pub async fn delete(&self, service: String, key_id: String) -> Result<(), KeyError> {
        let (tx, rx) = oneshot::channel();
        
        self.operation_tx.send(KeychainOperation::Delete {
            service, key_id, respond_to: tx
        }).await.map_err(|_| KeyError::Internal("Keychain service unavailable".to_string()))?;

        rx.await.map_err(|_| KeyError::Internal("Keychain operation failed".to_string()))?
    }

    /// Async list operation via channel (returns error as expected)
    pub async fn list(&self, service: String, pattern: String) -> Result<Vec<String>, KeyError> {
        let (tx, rx) = oneshot::channel();
        
        self.operation_tx.send(KeychainOperation::List {
            service, pattern, respond_to: tx
        }).await.map_err(|_| KeyError::Internal("Keychain service unavailable".to_string()))?;

        rx.await.map_err(|_| KeyError::Internal("Keychain operation failed".to_string()))?
    }

    /// Gracefully shutdown the keychain service
    #[allow(dead_code)]
    pub async fn shutdown(&mut self) -> Result<(), KeyError> {
        // Signal shutdown
        self.shutdown_signal.store(true, Ordering::Relaxed);
        
        // Send shutdown operation
        let (tx, rx) = oneshot::channel();
        self.operation_tx.send(KeychainOperation::Shutdown {
            respond_to: tx
        }).await.map_err(|_| KeyError::Internal("Failed to send shutdown signal".to_string()))?;

        // Wait for acknowledgment
        let _ = rx.await.map_err(|_| KeyError::Internal("Shutdown acknowledgment failed".to_string()))?;

        // Join the service thread
        if let Some(handle) = self.service_thread.take() {
            handle.join().map_err(|_| KeyError::Internal("Failed to join service thread".to_string()))?;
        }

        Ok(())
    }
}

/// Implement Drop for automatic cleanup
impl Drop for KeychainService {
    fn drop(&mut self) {
        // Signal shutdown
        self.shutdown_signal.store(true, Ordering::Relaxed);
        
        // Best effort to join the thread
        if let Some(handle) = self.service_thread.take() {
            let _ = handle.join();
        }
    }
}

/// Global keychain service instance (lazy initialization)
use tokio::sync::OnceCell;
static KEYCHAIN_SERVICE: OnceCell<KeychainService> = OnceCell::const_new();

/// Get or initialize the global keychain service
pub async fn get_keychain_service() -> Result<&'static KeychainService, KeyError> {
    KEYCHAIN_SERVICE.get_or_try_init(|| async {
        KeychainService::new()
    }).await.map_err(|e| KeyError::Internal(format!("Failed to initialize keychain service: {}", e)))
}

