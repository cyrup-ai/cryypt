//! Concrete cipher result type implementing the unwrapping pattern

use crate::{CipherError, Result};
use cryypt_common::NotResult;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::oneshot;

/// Concrete cipher resolution result
pub struct CipherResult {
    receiver: Option<oneshot::Receiver<Result<Vec<u8>>>>,
    completed: bool,
}

/// Cipher result with user-defined error handler
pub struct CipherResultWithHandler<F> {
    receiver: oneshot::Receiver<Result<Vec<u8>>>,
    handler: Option<F>,
    completed: bool,
}

impl CipherResult {
    /// Create a `CipherResult` from a receiver (for testing)
    #[must_use]
    pub fn from_receiver(receiver: oneshot::Receiver<Result<Vec<u8>>>) -> Self {
        Self {
            receiver: Some(receiver),
            completed: false,
        }
    }

    /// Create a `CipherResult` that's already completed
    #[must_use]
    pub fn ready(result: Result<Vec<u8>>) -> Self {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(result);
        Self {
            receiver: Some(rx),
            completed: false,
        }
    }

    /// Create a `CipherResult` that yields an error
    #[must_use]
    pub fn error(error: CipherError) -> Self {
        Self::ready(Err(error))
    }

    /// Add a result handler following README.md pattern
    /// Attach a result handler to process the cipher operation result
    ///
    /// # Panics
    ///
    /// Panics if the internal receiver has already been consumed. This should not happen
    /// in normal usage as `on_result` is typically called once on a fresh `CipherResult`.
    #[must_use]
    pub fn on_result<F, T>(self, handler: F) -> CipherResultWithHandler<F>
    where
        F: FnOnce(Result<Vec<u8>>) -> T,
    {
        CipherResultWithHandler {
            receiver: self.receiver.expect("CipherResult receiver should exist"),
            handler: Some(handler),
            completed: self.completed,
        }
    }
}

impl Future for CipherResult {
    type Output = Result<Vec<u8>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // If already completed, return error indicating multiple polls
        if self.completed {
            return Poll::Ready(Err(CipherError::Internal(
                "CipherResult polled after completion".to_string(),
            )));
        }

        // If receiver has been taken, this is an invalid state
        let Some(receiver) = self.receiver.as_mut() else {
            return Poll::Ready(Err(CipherError::Internal(
                "CipherResult receiver already consumed".to_string(),
            )));
        };

        match Pin::new(receiver).poll(cx) {
            Poll::Ready(Ok(result)) => {
                self.completed = true;
                self.receiver = None; // Consume the receiver
                Poll::Ready(result)
            }
            Poll::Ready(Err(_)) => {
                self.completed = true;
                self.receiver = None; // Consume the receiver
                Poll::Ready(Err(CipherError::Internal(
                    "Cipher resolution task dropped".to_string(),
                )))
            }
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

        // If already completed, return Pending to avoid multiple completions
        if this.completed {
            return Poll::Pending;
        }

        match Pin::new(&mut this.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => {
                // Call the user's on_result handler with the Result
                // The handler defines what happens on error and returns unwrapped value
                if let Some(handler) = this.handler.take() {
                    this.completed = true;
                    Poll::Ready(handler(result))
                } else {
                    // Handler already taken - mark as completed and return Pending
                    this.completed = true;
                    Poll::Pending
                }
            }
            Poll::Ready(Err(_)) => {
                // Task dropped - this should not happen in normal operation
                if let Some(handler) = this.handler.take() {
                    this.completed = true;
                    Poll::Ready(handler(Err(CipherError::Internal(
                        "Cipher resolution task dropped".to_string(),
                    ))))
                } else {
                    // Handler already taken - mark as completed and return Pending
                    this.completed = true;
                    Poll::Pending
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
