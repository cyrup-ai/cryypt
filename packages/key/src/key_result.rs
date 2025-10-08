//! Concrete key result type

use crate::{KeyError, Result};
use cryypt_common::NotResult;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::oneshot;

/// Concrete key resolution result
pub struct KeyResult {
    receiver: oneshot::Receiver<Result<Vec<u8>>>,
}

/// Key result with user-defined error handler
pub struct KeyResultWithHandler<F> {
    receiver: oneshot::Receiver<Result<Vec<u8>>>,
    handler: Option<F>,
    completed: bool,
}

impl KeyResult {
    /// Create a new `KeyResult` from a oneshot receiver
    pub(crate) fn new(receiver: oneshot::Receiver<Result<Vec<u8>>>) -> Self {
        Self { receiver }
    }

    /// Create a `KeyResult` that's already completed
    #[must_use]
    pub fn ready(result: Result<Vec<u8>>) -> Self {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(result);
        Self { receiver: rx }
    }

    /// Create a `KeyResult` that yields an error
    #[must_use]
    pub fn error(error: KeyError) -> Self {
        Self::ready(Err(error))
    }

    /// Add a result handler following README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> KeyResultWithHandler<F>
    where
        F: FnOnce(Result<Vec<u8>>) -> T,
    {
        KeyResultWithHandler {
            receiver: self.receiver,
            handler: Some(handler),
            completed: false,
        }
    }
}

impl Future for KeyResult {
    type Output = Result<Vec<u8>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => {
                Poll::Ready(Err(KeyError::internal("Key resolution task dropped")))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<F, T> Future for KeyResultWithHandler<F>
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
                    // Handler was already called, return Pending
                    Poll::Pending
                }
            }
            Poll::Ready(Err(_)) => {
                // Task dropped - this should not happen in normal operation
                if let Some(handler) = this.handler.take() {
                    this.completed = true;
                    Poll::Ready(handler(Err(KeyError::internal(
                        "Key resolution task dropped",
                    ))))
                } else {
                    // Handler was already called, return Pending
                    Poll::Pending
                }
            }
            Poll::Pending => Poll::Pending,
        }
    }
}
