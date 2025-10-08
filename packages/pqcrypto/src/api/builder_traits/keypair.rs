//! Key pair builder traits for KEM and signature operations
//!
//! Contains traits for generating and configuring cryptographic key pairs.

use crate::{PqCryptoError, Result};
use std::future::Future;
use std::path::Path;

/// Builder that can generate a KEM key pair
pub trait KemKeyPairBuilder {
    /// The resulting type after building the KEM scheme
    type Output;
    /// The resulting type containing the public key
    type PublicKeyOutput;
    /// The resulting type containing the secret key
    type SecretKeyOutput;

    /// Generate a new key pair
    fn generate(self) -> impl Future<Output = Result<Self::Output>> + Send
    where
        Self: Sized + Send;

    /// Load key pair from bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the key pair bytes are invalid or if key loading fails.
    fn with_keypair<T: Into<Vec<u8>>>(self, public_key: T, secret_key: T) -> Result<Self::Output>
    where
        Self: Sized;

    /// Load public key from bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the public key bytes are invalid or if key loading fails.
    fn with_public_key<T: Into<Vec<u8>>>(self, public_key: T) -> Result<Self::PublicKeyOutput>
    where
        Self: Sized;

    /// Load secret key from bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key bytes are invalid or if key loading fails.
    fn with_secret_key<T: Into<Vec<u8>>>(self, secret_key: T) -> Result<Self::SecretKeyOutput>
    where
        Self: Sized;

    /// Load public key from hex
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid or if key loading fails.
    fn with_public_key_hex(self, hex: &str) -> Result<Self::PublicKeyOutput>
    where
        Self: Sized,
    {
        let bytes = hex::decode(hex)
            .map_err(|e| PqCryptoError::InvalidKey(format!("Invalid hex public key: {e}")))?;
        self.with_public_key(bytes)
    }

    /// Load secret key from hex
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid or if key loading fails.
    fn with_secret_key_hex(self, hex: &str) -> Result<Self::SecretKeyOutput>
    where
        Self: Sized,
    {
        let bytes = hex::decode(hex)
            .map_err(|e| PqCryptoError::InvalidKey(format!("Invalid hex secret key: {e}")))?;
        self.with_secret_key(bytes)
    }

    /// Load public key from base64
    ///
    /// # Errors
    ///
    /// Returns an error if the base64 string is invalid or if key loading fails.
    fn with_public_key_base64(self, base64: &str) -> Result<Self::PublicKeyOutput>
    where
        Self: Sized,
    {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|e| PqCryptoError::InvalidKey(format!("Invalid base64 public key: {e}")))?;
        self.with_public_key(bytes)
    }

    /// Load secret key from base64
    ///
    /// # Errors
    ///
    /// Returns an error if the base64 string is invalid or if key loading fails.
    fn with_secret_key_base64(self, base64: &str) -> Result<Self::SecretKeyOutput>
    where
        Self: Sized,
    {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|e| PqCryptoError::InvalidKey(format!("Invalid base64 secret key: {e}")))?;
        self.with_secret_key(bytes)
    }

    /// Load key pair from files
    fn with_keypair_files<P: AsRef<Path> + Send>(
        self,
        public_key_path: P,
        secret_key_path: P,
    ) -> impl Future<Output = Result<Self::Output>> + Send
    where
        Self: Sized + Send,
    {
        async move {
            let public_key = tokio::fs::read(public_key_path)
                .await
                .map_err(|e| PqCryptoError::Io(format!("Failed to read public key file: {e}")))?;
            let secret_key = tokio::fs::read(secret_key_path)
                .await
                .map_err(|e| PqCryptoError::Io(format!("Failed to read secret key file: {e}")))?;
            self.with_keypair(public_key, secret_key)
        }
    }
}

/// Builder that can generate a signature key pair
pub trait SignatureKeyPairBuilder {
    /// The resulting type after building the signature scheme
    type Output;
    /// The resulting type containing the public key
    type PublicKeyOutput;
    /// The resulting type containing the secret key
    type SecretKeyOutput;

    /// Generate a new key pair
    fn generate(self) -> impl Future<Output = Result<Self::Output>> + Send
    where
        Self: Sized + Send;

    /// Load key pair from bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the key pair bytes are invalid or if key loading fails.
    fn with_keypair<T: Into<Vec<u8>>>(self, public_key: T, secret_key: T) -> Result<Self::Output>
    where
        Self: Sized;

    /// Load public key from bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the public key bytes are invalid or if key loading fails.
    fn with_public_key<T: Into<Vec<u8>>>(self, public_key: T) -> Result<Self::PublicKeyOutput>
    where
        Self: Sized;

    /// Load secret key from bytes
    ///
    /// # Errors
    ///
    /// Returns an error if the secret key bytes are invalid or if key loading fails.
    fn with_secret_key<T: Into<Vec<u8>>>(self, secret_key: T) -> Result<Self::SecretKeyOutput>
    where
        Self: Sized;

    /// Load public key from hex
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid or if key loading fails.
    fn with_public_key_hex(self, hex: &str) -> Result<Self::PublicKeyOutput>
    where
        Self: Sized,
    {
        let bytes = hex::decode(hex)
            .map_err(|e| PqCryptoError::InvalidKey(format!("Invalid hex public key: {e}")))?;
        self.with_public_key(bytes)
    }

    /// Load secret key from hex
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid or if key loading fails.
    fn with_secret_key_hex(self, hex: &str) -> Result<Self::SecretKeyOutput>
    where
        Self: Sized,
    {
        let bytes = hex::decode(hex)
            .map_err(|e| PqCryptoError::InvalidKey(format!("Invalid hex secret key: {e}")))?;
        self.with_secret_key(bytes)
    }

    /// Load public key from base64
    ///
    /// # Errors
    ///
    /// Returns an error if the base64 string is invalid or if key loading fails.
    fn with_public_key_base64(self, base64: &str) -> Result<Self::PublicKeyOutput>
    where
        Self: Sized,
    {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|e| PqCryptoError::InvalidKey(format!("Invalid base64 public key: {e}")))?;
        self.with_public_key(bytes)
    }

    /// Load secret key from base64
    ///
    /// # Errors
    ///
    /// Returns an error if the base64 string is invalid or if key loading fails.
    fn with_secret_key_base64(self, base64: &str) -> Result<Self::SecretKeyOutput>
    where
        Self: Sized,
    {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|e| PqCryptoError::InvalidKey(format!("Invalid base64 secret key: {e}")))?;
        self.with_secret_key(bytes)
    }
}
