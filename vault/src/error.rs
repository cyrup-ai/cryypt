
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
    #[error("Weak passphrase - must be at least 12 characters with uppercase, lowercase, numbers and special characters")]
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
    #[error("Other error: {0}")]
    Other(String),
}

pub type VaultResult<T> = Result<T, VaultError>;

// Import CryptoError from secretrust_core if available
use secretrust_core::military_grade::CryptoError;

// Implement conversion from CryptoError to VaultError
impl From<CryptoError> for VaultError {
    fn from(err: CryptoError) -> Self {
        match err {
            CryptoError::InsufficientEntropy => VaultError::Crypto("Insufficient entropy".into()),
            CryptoError::EncryptionFailed(msg) => VaultError::Encryption(msg),
            CryptoError::DecryptionFailed(msg) => VaultError::Decryption(msg),
            CryptoError::InvalidKey => VaultError::InvalidPassphrase,
            CryptoError::EntropyError => VaultError::Crypto("Entropy source error".into()),
        }
    }
}

// Implement conversion from secretrust_core::Error to VaultError
impl From<secretrust_core::error::Error> for VaultError {
    fn from(err: secretrust_core::error::Error) -> Self {
        use secretrust_core::error::Error;
        match err {
            Error::InvalidSize => VaultError::MemoryProtection("Invalid memory size".into()),
            Error::InvalidAlignment => VaultError::MemoryProtection("Invalid memory alignment".into()),
            Error::InvalidPointer => VaultError::MemoryProtection("Invalid pointer".into()),
            Error::MemoryCorruption => VaultError::MemoryCorruption,
            Error::Provider(msg) => VaultError::Provider(msg),
            Error::Nix(e) => VaultError::MemoryProtection(e.to_string()),
            Error::Io(e) => VaultError::Io(e),
            Error::NotFound(key) => VaultError::ItemNotFound,
            Error::Serialization(e) => VaultError::Serialization(e),
            Error::Crypto(e) => VaultError::from(e),
            Error::InvalidKey => VaultError::InvalidPassphrase,
            Error::Other(msg) => VaultError::Other(msg),
        }
    }
}
