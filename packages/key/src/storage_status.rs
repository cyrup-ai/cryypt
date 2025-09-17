//! Storage operation status tracking

/// Comprehensive storage operation status tracking
#[derive(Debug, Clone, PartialEq)]
pub enum StorageOperationStatus {
    /// Operation completed successfully
    Success,

    /// Key was not found in storage
    KeyNotFound {
        /// Key identifier that was not found
        key_id: String,
    },

    /// Storage backend encountered an error
    BackendError {
        /// Operation that failed
        operation: String,
        /// Error details from backend
        details: String,
    },

    /// Storage backend is temporarily unavailable
    Unavailable {
        /// Reason for unavailability
        reason: String,
    },

    /// Storage backend connection failed
    ConnectionFailed {
        /// Type of storage backend
        backend_type: String,
        /// Connection failure details
        details: String,
    },
}

impl StorageOperationStatus {
    /// Check if the operation was successful
    #[must_use]
    pub fn is_success(&self) -> bool {
        matches!(self, StorageOperationStatus::Success)
    }

    /// Check if the error indicates a missing key
    #[must_use]
    pub fn is_key_not_found(&self) -> bool {
        matches!(self, StorageOperationStatus::KeyNotFound { .. })
    }

    /// Check if the error indicates a backend problem
    #[must_use]
    pub fn is_backend_error(&self) -> bool {
        matches!(
            self,
            StorageOperationStatus::BackendError { .. }
                | StorageOperationStatus::Unavailable { .. }
                | StorageOperationStatus::ConnectionFailed { .. }
        )
    }

    /// Convert status to appropriate `KeyError`
    #[must_use]
    pub fn to_key_error(&self) -> crate::KeyError {
        match self {
            StorageOperationStatus::Success => {
                crate::KeyError::Internal("Cannot convert success status to error".to_string())
            }
            StorageOperationStatus::KeyNotFound { key_id } => crate::KeyError::KeyNotFound {
                id: key_id.clone(),
                version: 1,
            },
            StorageOperationStatus::BackendError { operation, details } => {
                crate::KeyError::StorageBackendError {
                    operation: operation.clone(),
                    details: details.clone(),
                }
            }
            StorageOperationStatus::Unavailable { reason } => crate::KeyError::StorageUnavailable {
                reason: reason.clone(),
            },
            StorageOperationStatus::ConnectionFailed {
                backend_type,
                details,
            } => crate::KeyError::StorageConnectionFailed {
                backend_type: backend_type.clone(),
                details: details.clone(),
            },
        }
    }
}

/// Trait for storage operations that can track their status
pub trait StorageStatusTracking {
    /// Get the current operation status
    fn get_status(&self) -> StorageOperationStatus;

    /// Set the operation status
    fn set_status(&mut self, status: StorageOperationStatus);

    /// Check if the last operation was successful
    fn last_operation_successful(&self) -> bool {
        self.get_status().is_success()
    }
}
