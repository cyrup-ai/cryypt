//! Encryption result type that implements Future for clean async interfaces

use crate::Result;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::oneshot;

/// A result wrapper that provides encoding methods
pub struct EncodableResult {
    data: Vec<u8>,
}

impl EncodableResult {
    /// Create a new encodable result
    #[must_use]
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Convert to base64 encoded string
    #[must_use]
    pub fn to_base64(self) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&self.data)
    }

    /// Convert to hex encoded string
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(&self.data)
    }

    /// Get the raw bytes
    #[must_use]
    pub fn to_bytes(self) -> Vec<u8> {
        self.data
    }

    /// Convert to UTF-8 string (for text data)
    /// Convert encrypted result to string representation
    ///
    /// # Errors
    ///
    /// Returns an error if the encrypted data cannot be converted to a valid UTF-8 string.
    pub fn to_string(self) -> crate::Result<String> {
        String::from_utf8(self.data)
            .map_err(|e| crate::CryptError::InvalidEncryptedData(format!("Invalid UTF-8: {e}")))
    }

    /// Convert to UTF-8 string, replacing invalid sequences
    #[must_use]
    pub fn to_string_lossy(self) -> String {
        String::from_utf8_lossy(&self.data).into_owned()
    }

    /// Write to file
    /// Write encrypted result to a file
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be created or written to.
    pub async fn to_file<P: AsRef<std::path::Path>>(self, path: P) -> crate::Result<()> {
        tokio::fs::write(path, &self.data)
            .await
            .map_err(|e| crate::CryptError::Internal(format!("Failed to write file: {e}")))
    }

    /// Get the length of the data
    #[must_use]
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the data is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl AsRef<[u8]> for EncodableResult {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl From<Vec<u8>> for EncodableResult {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<EncodableResult> for Vec<u8> {
    fn from(result: EncodableResult) -> Self {
        result.data
    }
}

/// Concrete implementation of an encryption operation result
pub struct EncryptionResultImpl {
    receiver: oneshot::Receiver<Result<Vec<u8>>>,
}

impl EncryptionResultImpl {
    /// Create a new `EncryptionResult` from a oneshot receiver
    pub(crate) fn new(receiver: oneshot::Receiver<Result<Vec<u8>>>) -> Self {
        Self { receiver }
    }
}

impl Future for EncryptionResultImpl {
    type Output = EncodableResult;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(Ok(data))) => Poll::Ready(EncodableResult::from(data)),
            Poll::Ready(Ok(Err(e))) => {
                log::error!("Encryption operation error: {e}");
                Poll::Ready(EncodableResult::from(Vec::new()))
            }
            Poll::Ready(Err(_)) => {
                log::error!("Encryption task dropped");
                Poll::Ready(EncodableResult::from(Vec::new()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Concrete implementation of a decryption operation result
pub struct DecryptionResultImpl {
    receiver: oneshot::Receiver<Result<Vec<u8>>>,
}

impl DecryptionResultImpl {
    /// Create a new `DecryptionResult` from a oneshot receiver
    pub(crate) fn new(receiver: oneshot::Receiver<Result<Vec<u8>>>) -> Self {
        Self { receiver }
    }
}

impl Future for DecryptionResultImpl {
    type Output = Vec<u8>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(Ok(data))) => Poll::Ready(data),
            Poll::Ready(Ok(Err(e))) => {
                log::error!("Decryption operation error: {e}");
                Poll::Ready(Vec::new())
            }
            Poll::Ready(Err(_)) => {
                log::error!("Decryption task dropped");
                Poll::Ready(Vec::new())
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
