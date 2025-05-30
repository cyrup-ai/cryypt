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


