//! Builder traits for post-quantum cryptography operations

use crate::{CryptError, Result};
use std::future::Future;
use std::path::Path;

/// Async result type for encapsulation operations
pub trait AsyncEncapsulationResult:
    Future<Output = Result<super::super::EncapsulationResult>> + Send
{
}

impl<T> AsyncEncapsulationResult for T where
    T: Future<Output = Result<super::super::EncapsulationResult>> + Send
{
}

/// Async result type for decapsulation operations
pub trait AsyncDecapsulationResult:
    Future<Output = Result<super::super::DecapsulationResult>> + Send
{
}

impl<T> AsyncDecapsulationResult for T where
    T: Future<Output = Result<super::super::DecapsulationResult>> + Send
{
}

/// Async result type for signature operations
pub trait AsyncSignatureResult:
    Future<Output = Result<super::super::SignatureResult>> + Send
{
}

impl<T> AsyncSignatureResult for T where
    T: Future<Output = Result<super::super::SignatureResult>> + Send
{
}

/// Async result type for verification operations
pub trait AsyncVerificationResult:
    Future<Output = Result<super::super::VerificationResult>> + Send
{
}

impl<T> AsyncVerificationResult for T where
    T: Future<Output = Result<super::super::VerificationResult>> + Send
{
}

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
    fn with_keypair<T: Into<Vec<u8>>>(self, public_key: T, secret_key: T) -> Result<Self::Output>
    where
        Self: Sized;

    /// Load public key from bytes
    fn with_public_key<T: Into<Vec<u8>>>(self, public_key: T) -> Result<Self::PublicKeyOutput>
    where
        Self: Sized;

    /// Load secret key from bytes
    fn with_secret_key<T: Into<Vec<u8>>>(self, secret_key: T) -> Result<Self::SecretKeyOutput>
    where
        Self: Sized;

    /// Load public key from hex
    fn with_public_key_hex(self, hex: &str) -> Result<Self::PublicKeyOutput>
    where
        Self: Sized,
    {
        let bytes = hex::decode(hex)
            .map_err(|e| CryptError::InvalidKey(format!("Invalid hex public key: {}", e)))?;
        self.with_public_key(bytes)
    }

    /// Load secret key from hex
    fn with_secret_key_hex(self, hex: &str) -> Result<Self::SecretKeyOutput>
    where
        Self: Sized,
    {
        let bytes = hex::decode(hex)
            .map_err(|e| CryptError::InvalidKey(format!("Invalid hex secret key: {}", e)))?;
        self.with_secret_key(bytes)
    }

    /// Load public key from base64
    fn with_public_key_base64(self, base64: &str) -> Result<Self::PublicKeyOutput>
    where
        Self: Sized,
    {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|e| CryptError::InvalidKey(format!("Invalid base64 public key: {}", e)))?;
        self.with_public_key(bytes)
    }

    /// Load secret key from base64
    fn with_secret_key_base64(self, base64: &str) -> Result<Self::SecretKeyOutput>
    where
        Self: Sized,
    {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|e| CryptError::InvalidKey(format!("Invalid base64 secret key: {}", e)))?;
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
                .map_err(|e| CryptError::Io(format!("Failed to read public key file: {}", e)))?;
            let secret_key = tokio::fs::read(secret_key_path)
                .await
                .map_err(|e| CryptError::Io(format!("Failed to read secret key file: {}", e)))?;
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
    fn with_keypair<T: Into<Vec<u8>>>(self, public_key: T, secret_key: T) -> Result<Self::Output>
    where
        Self: Sized;

    /// Load public key from bytes
    fn with_public_key<T: Into<Vec<u8>>>(self, public_key: T) -> Result<Self::PublicKeyOutput>
    where
        Self: Sized;

    /// Load secret key from bytes
    fn with_secret_key<T: Into<Vec<u8>>>(self, secret_key: T) -> Result<Self::SecretKeyOutput>
    where
        Self: Sized;

    /// Load public key from hex
    fn with_public_key_hex(self, hex: &str) -> Result<Self::PublicKeyOutput>
    where
        Self: Sized,
    {
        let bytes = hex::decode(hex)
            .map_err(|e| CryptError::InvalidKey(format!("Invalid hex public key: {}", e)))?;
        self.with_public_key(bytes)
    }

    /// Load secret key from hex
    fn with_secret_key_hex(self, hex: &str) -> Result<Self::SecretKeyOutput>
    where
        Self: Sized,
    {
        let bytes = hex::decode(hex)
            .map_err(|e| CryptError::InvalidKey(format!("Invalid hex secret key: {}", e)))?;
        self.with_secret_key(bytes)
    }

    /// Load public key from base64
    fn with_public_key_base64(self, base64: &str) -> Result<Self::PublicKeyOutput>
    where
        Self: Sized,
    {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|e| CryptError::InvalidKey(format!("Invalid base64 public key: {}", e)))?;
        self.with_public_key(bytes)
    }

    /// Load secret key from base64
    fn with_secret_key_base64(self, base64: &str) -> Result<Self::SecretKeyOutput>
    where
        Self: Sized,
    {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|e| CryptError::InvalidKey(format!("Invalid base64 secret key: {}", e)))?;
        self.with_secret_key(bytes)
    }
}

/// Builder that can accept ciphertext for decapsulation
pub trait CiphertextBuilder {
    /// The resulting type after adding the ciphertext
    type Output;

    /// Set the ciphertext from bytes
    fn with_ciphertext<T: Into<Vec<u8>>>(self, ciphertext: T) -> Self::Output;

    /// Set the ciphertext from hex
    fn with_ciphertext_hex(self, hex: &str) -> Result<Self::Output>
    where
        Self: Sized,
    {
        let bytes = hex::decode(hex).map_err(|e| {
            CryptError::InvalidEncryptedData(format!("Invalid hex ciphertext: {}", e))
        })?;
        Ok(self.with_ciphertext(bytes))
    }

    /// Set the ciphertext from base64
    fn with_ciphertext_base64(self, base64: &str) -> Result<Self::Output>
    where
        Self: Sized,
    {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|e| {
                CryptError::InvalidEncryptedData(format!("Invalid base64 ciphertext: {}", e))
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
                .map_err(|e| CryptError::Io(format!("Failed to read ciphertext file: {}", e)))?;
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
    fn with_message_hex(self, hex: &str) -> Result<Self::Output>
    where
        Self: Sized,
    {
        let bytes = hex::decode(hex)
            .map_err(|e| CryptError::InvalidParameters(format!("Invalid hex message: {}", e)))?;
        Ok(self.with_message(bytes))
    }

    /// Set the message from base64
    fn with_message_base64(self, base64: &str) -> Result<Self::Output>
    where
        Self: Sized,
    {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|e| CryptError::InvalidParameters(format!("Invalid base64 message: {}", e)))?;
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
                .map_err(|e| CryptError::Io(format!("Failed to read message file: {}", e)))?;
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
    fn with_signature_hex(self, hex: &str) -> Result<Self::Output>
    where
        Self: Sized,
    {
        let bytes = hex::decode(hex)
            .map_err(|e| CryptError::InvalidParameters(format!("Invalid hex signature: {}", e)))?;
        Ok(self.with_signature(bytes))
    }

    /// Set the signature from base64
    fn with_signature_base64(self, base64: &str) -> Result<Self::Output>
    where
        Self: Sized,
    {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(base64)
            .map_err(|e| {
                CryptError::InvalidParameters(format!("Invalid base64 signature: {}", e))
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
                .map_err(|e| CryptError::Io(format!("Failed to read signature file: {}", e)))?;
            Ok(self.with_signature(signature))
        }
    }
}

/// Final stage builder that can encapsulate
pub trait EncapsulateBuilder {
    /// Perform key encapsulation operation
    fn encapsulate(self) -> impl AsyncEncapsulationResult;
}

/// Final stage builder that can decapsulate
pub trait DecapsulateBuilder {
    /// Perform key decapsulation operation
    fn decapsulate(self) -> impl AsyncDecapsulationResult;
}

/// Final stage builder that can sign
pub trait SignBuilder {
    /// Perform digital signature operation
    fn sign(self) -> impl AsyncSignatureResult;
}

/// Final stage builder that can verify
pub trait VerifyBuilder {
    /// Perform signature verification operation
    fn verify(self) -> impl AsyncVerificationResult;
}
