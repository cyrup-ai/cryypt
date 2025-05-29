//! Encryption result type that implements Future for clean async interfaces

use crate::{CryptError, Result};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::oneshot;

/// Concrete implementation of an encryption operation result
pub struct EncryptionResultImpl {
    receiver: oneshot::Receiver<Result<Vec<u8>>>,
}

impl EncryptionResultImpl {
    /// Create a new EncryptionResult from a oneshot receiver
    pub(crate) fn new(receiver: oneshot::Receiver<Result<Vec<u8>>>) -> Self {
        Self { receiver }
    }

    /// Create an EncryptionResult that's already completed
    pub(crate) fn ready(result: Result<Vec<u8>>) -> Self {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(result); // Safe to ignore error since we control both ends
        Self { receiver: rx }
    }

    /// Create an EncryptionResult that yields an error
    pub(crate) fn error(error: CryptError) -> Self {
        Self::ready(Err(error))
    }
}

impl Future for EncryptionResultImpl {
    type Output = Result<Vec<u8>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(CryptError::internal("Encryption task dropped"))),
            Poll::Pending => Poll::Pending,
        }
    }
}


/// Concrete implementation of a decryption operation result
pub struct DecryptionResultImpl {
    receiver: oneshot::Receiver<Result<Vec<u8>>>,
}

impl DecryptionResultImpl {
    /// Create a new DecryptionResult from a oneshot receiver
    pub(crate) fn new(receiver: oneshot::Receiver<Result<Vec<u8>>>) -> Self {
        Self { receiver }
    }

    /// Create a DecryptionResult that's already completed
    pub(crate) fn ready(result: Result<Vec<u8>>) -> Self {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(result);
        Self { receiver: rx }
    }

    /// Create a DecryptionResult that yields an error
    pub(crate) fn error(error: CryptError) -> Self {
        Self::ready(Err(error))
    }
}

impl Future for DecryptionResultImpl {
    type Output = Result<Vec<u8>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(CryptError::internal("Decryption task dropped"))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Key derivation result that implements Future
pub struct KeyDerivationResult {
    receiver: oneshot::Receiver<Result<Vec<u8>>>,
}

impl KeyDerivationResult {
    /// Create a new KeyDerivationResult from a oneshot receiver
    pub(crate) fn new(receiver: oneshot::Receiver<Result<Vec<u8>>>) -> Self {
        Self { receiver }
    }

    /// Create a KeyDerivationResult that's already completed
    pub(crate) fn ready(result: Result<Vec<u8>>) -> Self {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(result);
        Self { receiver: rx }
    }

    /// Create a KeyDerivationResult that yields an error
    pub(crate) fn error(error: CryptError) -> Self {
        Self::ready(Err(error))
    }
}

impl Future for KeyDerivationResult {
    type Output = Result<Vec<u8>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(CryptError::internal("Key derivation task dropped"))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_encryption_result_ready() {
        let data = vec![1, 2, 3];
        let result = EncryptionResultImpl::ready(Ok(data.clone())).await.expect("Failed to get encryption result");
        assert_eq!(result, data);
    }

    #[tokio::test]
    async fn test_encryption_result_error() {
        let result = EncryptionResultImpl::error(CryptError::InvalidKey("test".into())).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_decryption_result_ready() {
        let data = vec![1, 2, 3, 4, 5];
        let result = DecryptionResultImpl::ready(Ok(data.clone())).await.expect("Failed to get decryption result");
        assert_eq!(result, data);
    }
}