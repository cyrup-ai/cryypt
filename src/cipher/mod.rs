mod algorithm;
pub mod api;
pub mod encryption_result;

// Re-export algorithm enum
pub use self::algorithm::CipherAlgorithm;
pub use encryption_result::{EncryptionResultImpl, DecryptionResultImpl};

