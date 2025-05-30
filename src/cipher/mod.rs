mod algorithm;
pub mod api;
pub mod encryption_result;
mod nonce;

// Re-export algorithm enum
pub use self::algorithm::CipherAlgorithm;
pub use encryption_result::{DecryptionResultImpl, EncryptionResultImpl};
pub use nonce::{
    Nonce, NonceConfig, NonceError, NonceGenerator, NonceManager, NonceSecretKey, ParsedNonce,
};
