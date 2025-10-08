//! Data operation builder traits
//!
//! Contains traits for configuring cryptographic operation data (ciphertext, messages, signatures).

use crate::{PqCryptoError, Result};
use std::future::Future;
use std::path::Path;

/// Builder that can accept ciphertext for decapsulation
pub trait CiphertextBuilder {
    /// The resulting type after adding the ciphertext
    type Output;

    /// Set the ciphertext from bytes
    fn with_ciphertext<T: Into<Vec<u8>>>(self, ciphertext: T) -> Self::Output;

    /// Set the ciphertext from hex
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid.
    fn with_ciphertext_hex(self, hex: &str) -> Result<Self::Output>
    where
        Self: Sized,
    {
        let bytes = hex::decode(hex).map_err(|e| {
            PqCryptoError::InvalidEncryptedData(format!("Invalid hex ciphertext: {e}"))
        })?;
        Ok(self.with_ciphertext(bytes))
    }

    /// Set the ciphertext from base64
    ///
    /// # Errors
    ///
    /// Returns an error if the base64 string is invalid.
    fn with_ciphertext_base64(self, base64: &str) -> Result<Self::Output>
    where
        Self: Sized,
    {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|e| {
                PqCryptoError::InvalidEncryptedData(format!("Invalid base64 ciphertext: {e}"))
            })?;
        Ok(self.with_ciphertext(bytes))
    }

    /// Load ciphertext from file
    fn with_ciphertext_file<P: AsRef<Path> + Send>(
        self,
        path: P,
    ) -> impl Future<Output = Result<Self::Output>> + Send
    where
        Self: Sized + Send,
    {
        async move {
            let ciphertext = tokio::fs::read(path)
                .await
                .map_err(|e| PqCryptoError::Io(format!("Failed to read ciphertext file: {e}")))?;
            Ok(self.with_ciphertext(ciphertext))
        }
    }
}

/// Builder that can accept a message for signing
pub trait MessageBuilder {
    /// The resulting type after adding the message
    type Output;

    /// Set the message from bytes
    fn with_message<T: Into<Vec<u8>>>(self, message: T) -> Self::Output;

    /// Set the message from a string
    fn with_message_text(self, text: &str) -> Self::Output
    where
        Self: Sized,
    {
        self.with_message(text.as_bytes())
    }

    /// Set the message from hex
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid.
    fn with_message_hex(self, hex: &str) -> Result<Self::Output>
    where
        Self: Sized,
    {
        let bytes = hex::decode(hex)
            .map_err(|e| PqCryptoError::InvalidParameters(format!("Invalid hex message: {e}")))?;
        Ok(self.with_message(bytes))
    }

    /// Set the message from base64
    ///
    /// # Errors
    ///
    /// Returns an error if the base64 string is invalid.
    fn with_message_base64(self, base64: &str) -> Result<Self::Output>
    where
        Self: Sized,
    {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|e| {
                PqCryptoError::InvalidParameters(format!("Invalid base64 message: {e}"))
            })?;
        Ok(self.with_message(bytes))
    }

    /// Load message from file
    fn with_message_file<P: AsRef<Path> + Send>(
        self,
        path: P,
    ) -> impl Future<Output = Result<Self::Output>> + Send
    where
        Self: Sized + Send,
    {
        async move {
            let message = tokio::fs::read(path)
                .await
                .map_err(|e| PqCryptoError::Io(format!("Failed to read message file: {e}")))?;
            Ok(self.with_message(message))
        }
    }
}

/// Builder that can accept a signature for verification
pub trait SignatureDataBuilder {
    /// The resulting type after adding the signature
    type Output;

    /// Set the signature from bytes
    fn with_signature<T: Into<Vec<u8>>>(self, signature: T) -> Self::Output;

    /// Set the signature from hex
    ///
    /// # Errors
    ///
    /// Returns an error if the hex string is invalid.
    fn with_signature_hex(self, hex: &str) -> Result<Self::Output>
    where
        Self: Sized,
    {
        let bytes = hex::decode(hex)
            .map_err(|e| PqCryptoError::InvalidParameters(format!("Invalid hex signature: {e}")))?;
        Ok(self.with_signature(bytes))
    }

    /// Set the signature from base64
    ///
    /// # Errors
    ///
    /// Returns an error if the base64 string is invalid.
    fn with_signature_base64(self, base64: &str) -> Result<Self::Output>
    where
        Self: Sized,
    {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|e| {
                PqCryptoError::InvalidParameters(format!("Invalid base64 signature: {e}"))
            })?;
        Ok(self.with_signature(bytes))
    }

    /// Load signature from file
    fn with_signature_file<P: AsRef<Path> + Send>(
        self,
        path: P,
    ) -> impl Future<Output = Result<Self::Output>> + Send
    where
        Self: Sized + Send,
    {
        async move {
            let signature = tokio::fs::read(path)
                .await
                .map_err(|e| PqCryptoError::Io(format!("Failed to read signature file: {e}")))?;
            Ok(self.with_signature(signature))
        }
    }
}
