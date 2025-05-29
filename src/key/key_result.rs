//! Concrete key result type

use crate::{CryptError, Result};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::oneshot;

/// Concrete key resolution result
pub struct KeyResult {
    receiver: oneshot::Receiver<Result<Vec<u8>>>,
}

impl KeyResult {
    /// Create a new KeyResult from a oneshot receiver
    pub(crate) fn new(receiver: oneshot::Receiver<Result<Vec<u8>>>) -> Self {
        Self { receiver }
    }

    /// Create a KeyResult that's already completed
    pub fn ready(result: Result<Vec<u8>>) -> Self {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(result);
        Self { receiver: rx }
    }

    /// Create a KeyResult that yields an error
    pub fn error(error: CryptError) -> Self {
        Self::ready(Err(error))
    }
}

impl Future for KeyResult {
    type Output = Result<Vec<u8>>;
    
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(CryptError::internal("Key resolution task dropped"))),
            Poll::Pending => Poll::Pending,
        }
    }
}