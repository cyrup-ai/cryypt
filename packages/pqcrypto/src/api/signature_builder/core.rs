//! Core signature builder types and basic implementations

// Re-export builder types
pub use super::falcon::{
    FalconBuilder, FalconWithKeyPair, FalconWithMessage, FalconWithPublicKey, FalconWithSecretKey,
    FalconWithSignature,
};
pub use super::ml_dsa::{
    MlDsaBuilder, MlDsaWithKeyPair, MlDsaWithMessage, MlDsaWithPublicKey, MlDsaWithSecretKey,
    MlDsaWithSignature,
};
pub use super::sphincs::{
    SphincsBuilder, SphincsWithKeyPair, SphincsWithMessage, SphincsWithPublicKey,
    SphincsWithSecretKey, SphincsWithSignature,
};

/// Main entry point for signature operations
pub struct SignatureBuilder;

/// Signature builder with result handler for keypair operations (returns tuple)
pub struct SignatureBuilderWithHandler<F, T> {
    pub result_handler: F,
    pub _phantom: std::marker::PhantomData<T>,
}

/// Signature builder with result handler for sign operations (returns Vec<u8>)
pub struct SignatureBuilderWithSignHandler<F, T> {
    pub result_handler: F,
    pub _phantom: std::marker::PhantomData<T>,
}

/// Signature builder with result handler for verify operations (returns bool)
pub struct SignatureBuilderWithVerifyHandler<F, T> {
    pub result_handler: F,
    pub _phantom: std::marker::PhantomData<T>,
}

/// Signature builder with secret key for signing
pub struct SignatureBuilderWithSecretKey {
    pub _phantom: std::marker::PhantomData<()>,
}

/// Signature builder with public key for verification
pub struct SignatureBuilderWithPublicKey {
    pub _phantom: std::marker::PhantomData<()>,
}

impl SignatureBuilder {
    /// Add `on_result` handler - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> SignatureBuilderWithHandler<F, T>
    where
        F: FnOnce(crate::Result<(Vec<u8>, Vec<u8>)>) -> T + Send + 'static,
        T: Send + 'static,
    {
        SignatureBuilderWithHandler {
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set security level for signature operations
    #[must_use]
    pub fn with_security_level(self, _level: u16) -> Self {
        self
    }

    /// Set secret key for signing operations
    #[must_use]
    pub fn with_secret_key(self, _key: Vec<u8>) -> SignatureBuilderWithSecretKey {
        SignatureBuilderWithSecretKey {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set public key for verification operations
    #[must_use]
    pub fn with_public_key(self, _key: Vec<u8>) -> SignatureBuilderWithPublicKey {
        SignatureBuilderWithPublicKey {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set signature for verification operations
    #[must_use]
    pub fn with_signature(self, _signature: Vec<u8>) -> Self {
        self
    }
}

impl SignatureBuilderWithSecretKey {
    /// Add `on_result` handler for signing - README.md pattern
    #[allow(clippy::unused_self)] // self consumed for builder pattern state transition
    pub fn on_result<F, T>(self, handler: F) -> SignatureBuilderWithSignHandler<F, T>
    where
        F: FnOnce(crate::Result<Vec<u8>>) -> T + Send + 'static,
        T: Send + 'static,
    {
        SignatureBuilderWithSignHandler {
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl SignatureBuilderWithPublicKey {
    /// Set signature for verification operations
    pub fn with_signature(self, _signature: Vec<u8>) -> Self {
        self
    }

    /// Add `on_result` handler for verification - README.md pattern
    #[allow(clippy::unused_self)] // self consumed for builder pattern state transition
    pub fn on_result<F, T>(self, handler: F) -> SignatureBuilderWithVerifyHandler<F, T>
    where
        F: FnOnce(crate::Result<bool>) -> T + Send + 'static,
        T: Send + 'static,
    {
        SignatureBuilderWithVerifyHandler {
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }
}
