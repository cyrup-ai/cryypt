//! Concrete cipher result type implementing the unwrapping pattern

use crate::{CryptError, Result};
use cryypt_common::NotResult;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::oneshot;

/// Concrete cipher resolution result
pub struct CipherResult {
    receiver: oneshot::Receiver<Result<Vec<u8>>>,
}

/// Cipher result with user-defined error handler
pub struct CipherResultWithHandler<F> {
    receiver: oneshot::Receiver<Result<Vec<u8>>>,
    handler: Option<F>,
}

impl CipherResult {
    /// Create a new CipherResult from a oneshot receiver
    pub(crate) fn new(receiver: oneshot::Receiver<Result<Vec<u8>>>) -> Self {
        Self { receiver }
    }

    /// Create a CipherResult that's already completed
    pub fn ready(result: Result<Vec<u8>>) -> Self {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(result);
        Self { receiver: rx }
    }

    /// Create a CipherResult that yields an error
    pub fn error(error: CryptError) -> Self {
        Self::ready(Err(error))
    }
    
    /// Add a result handler following README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> CipherResultWithHandler<F>
    where
        F: FnOnce(Result<Vec<u8>>) -> T,
    {
        CipherResultWithHandler {
            receiver: self.receiver,
            handler: Some(handler),
        }
    }
}

impl Future for CipherResult {
    type Output = Result<Vec<u8>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(CryptError::InternalError("Cipher resolution task dropped".to_string()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<F, T> Future for CipherResultWithHandler<F>
where
    F: FnOnce(Result<Vec<u8>>) -> T + Unpin,
    T: NotResult,
{
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match Pin::new(&mut this.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => {
                // Call the user's on_result handler with the Result
                // The handler defines what happens on error and returns unwrapped value
                if let Some(handler) = this.handler.take() {
                    Poll::Ready(handler(result))
                } else {
                    // Handler was already called, this shouldn't happen
                    panic!("CipherResultWithHandler polled after completion")
                }
            }
            Poll::Ready(Err(_)) => {
                // Task dropped - this should not happen in normal operation
                if let Some(handler) = this.handler.take() {
                    Poll::Ready(handler(Err(CryptError::InternalError("Cipher resolution task dropped".to_string()))))
                } else {
                    // Handler was already called, this shouldn't happen
                    panic!("CipherResultWithHandler polled after completion")
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}