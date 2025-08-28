use thiserror::Error;

/// Database-specific error types for robust error handling
#[derive(Error, Debug)]
pub enum DatabaseError {
    #[error("Connection failed: {message}")]
    ConnectionFailed { message: String },

    #[error("Connection timeout after {timeout_ms}ms")]
    ConnectionTimeout { timeout_ms: u64 },

    #[error("Connection lost: {reason}")]
    ConnectionLost { reason: String },

    #[error("Migration failed: {migration_name} - {error}")]
    MigrationFailed {
        migration_name: String,
        error: String,
    },

    #[error("Schema validation failed: {details}")]
    SchemaValidationFailed { details: String },

    #[error("Transaction failed: {operation} - {error}")]
    TransactionFailed { operation: String, error: String },

    #[error("Query execution failed: {query} - {error}")]
    QueryFailed { query: String, error: String },

    #[error("Serialization error: {details}")]
    SerializationError { details: String },

    #[error("Deserialization error: {details}")]
    DeserializationError { details: String },

    #[error("Database file corruption detected: {path}")]
    DatabaseCorruption { path: String },

    #[error("Insufficient permissions for database operation: {operation}")]
    InsufficientPermissions { operation: String },

    #[error("Database configuration error: {config_key} - {error}")]
    ConfigurationError { config_key: String, error: String },

    #[error("Health check failed: {check_name} - {reason}")]
    HealthCheckFailed { check_name: String, reason: String },

    #[error("Retry limit exceeded: {operation} - attempted {attempts} times")]
    RetryLimitExceeded { operation: String, attempts: u32 },

    #[error("Namespace error: {namespace} - {error}")]
    NamespaceError { namespace: String, error: String },

    #[error("Database error: {error}")]
    DatabaseSpecific { error: String },

    #[error("IO error: {error}")]
    IoError {
        #[from]
        error: std::io::Error,
    },

    #[error("SurrealDB error: {error}")]
    SurrealDbError {
        #[from]
        error: surrealdb::Error,
    },
}

impl DatabaseError {
    /// Check if the error is recoverable through retry
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            DatabaseError::ConnectionTimeout { .. }
                | DatabaseError::ConnectionLost { .. }
                | DatabaseError::QueryFailed { .. }
                | DatabaseError::TransactionFailed { .. }
        )
    }

    /// Check if the error indicates a connection issue
    pub fn is_connection_error(&self) -> bool {
        matches!(
            self,
            DatabaseError::ConnectionFailed { .. }
                | DatabaseError::ConnectionTimeout { .. }
                | DatabaseError::ConnectionLost { .. }
        )
    }

    /// Get suggested retry delay in milliseconds
    pub fn retry_delay_ms(&self) -> Option<u64> {
        match self {
            DatabaseError::ConnectionTimeout { .. } => Some(1000),
            DatabaseError::ConnectionLost { .. } => Some(2000),
            DatabaseError::QueryFailed { .. } => Some(500),
            DatabaseError::TransactionFailed { .. } => Some(750),
            _ => None,
        }
    }
}

/// Result type for database operations
pub type DatabaseResult<T> = Result<T, DatabaseError>;
