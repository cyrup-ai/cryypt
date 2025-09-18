#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Key derivation error: {0}")]
    KeyDerivation(String),
    #[error("Item not found")]
    ItemNotFound,
    #[error("Vault locked")]
    VaultLocked,
    #[error("Invalid passphrase")]
    InvalidPassphrase,
    #[error(
        "Weak passphrase - must be at least 12 characters with uppercase, lowercase, numbers and special characters"
    )]
    WeakPassphrase,
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Value type error: {0}")]
    ValueType(String),
    #[error("Too many failed attempts. Try again in {0:?}")]
    TooManyAttempts(std::time::Duration),
    #[error("Operation timed out after {0:?}")]
    TimeoutError(std::time::Duration),
    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),
    #[error("Database error: {0}")]
    Database(#[from] surrealdb::Error),
    #[error("Database error: {0}")]
    DatabaseError(String),
    #[error("Migration error: {0}")]
    Migration(String),
    #[error("Time error: {0}")]
    Time(#[from] time::error::Error),
    #[error("Provider error: {0}")]
    Provider(String),
    #[error("Configuration error: {0}")]
    Configuration(String),
    #[error("Memory protection error: {0}")]
    MemoryProtection(String),
    #[error("Memory corruption detected")]
    MemoryCorruption,
    #[error("Crypto error: {0}")]
    Crypto(String),
    #[error("Operation not supported: {0}")]
    UnsupportedOperation(String),
    #[error("Conflict: {0}")]
    Conflict(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    #[error("Key rotation error: {0}")]
    KeyRotation(String),
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    #[error("Internal error: {0}")]
    Internal(String),
    #[error("Other error: {0}")]
    Other(String),
}

impl VaultError {
    /// Create an authentication failed error
    pub fn authentication_failed(_msg: &str) -> Self {
        VaultError::InvalidPassphrase
    }

    /// Create a weak passphrase error
    pub fn weak_passphrase(_msg: &str) -> Self {
        VaultError::WeakPassphrase
    }

    /// Create transaction error variants
    pub fn transaction_already_committed(tx_id: String, _msg: String) -> Self {
        VaultError::InvalidInput(format!("Transaction {} already committed", tx_id))
    }

    pub fn transaction_already_rolled_back(tx_id: String) -> Self {
        VaultError::InvalidInput(format!("Transaction {} already rolled back", tx_id))
    }

    pub fn transaction_begin_failed(_tx_id: String, msg: String) -> Self {
        VaultError::DatabaseError(format!("Transaction begin failed: {msg}"))
    }

    pub fn transaction_commit_failed(_tx_id: String, msg: String) -> Self {
        VaultError::DatabaseError(format!("Transaction commit failed: {msg}"))
    }

    pub fn transaction_operation_failed(_tx_id: String, msg: String) -> Self {
        VaultError::DatabaseError(format!("Transaction operation failed: {msg}"))
    }

    pub fn transaction_closed(tx_id: String) -> Self {
        VaultError::InvalidInput(format!("Transaction {} is closed", tx_id))
    }

    pub fn database_operation_failed(_tx_id: String, msg: String) -> Self {
        VaultError::DatabaseError(format!("Database operation failed: {msg}"))
    }
}

pub type VaultResult<T> = Result<T, VaultError>;

// Import cipher error types
use cryypt_cipher::CryptError;

// Implement conversion from CryptError to VaultError
impl From<CryptError> for VaultError {
    fn from(err: CryptError) -> Self {
        match err {
            CryptError::KeyDerivation(msg) => VaultError::KeyDerivation(msg),
            CryptError::EncryptionFailed(msg) => VaultError::Encryption(msg),
            CryptError::DecryptionFailed(msg) => VaultError::Decryption(msg),
            CryptError::InvalidKeySize { expected, actual } => VaultError::Crypto(format!(
                "Invalid key size: expected {}, got {}",
                expected, actual
            )),
            CryptError::InvalidNonceLength { expected, actual } => VaultError::Crypto(format!(
                "Invalid nonce size: expected {}, got {}",
                expected, actual
            )),
            CryptError::InvalidEncryptedData(msg) => VaultError::Crypto(msg),
            CryptError::Io(e) => VaultError::Io(e),
            CryptError::Internal(msg) => VaultError::Other(msg),
            _ => VaultError::Other(err.to_string()),
        }
    }
}
