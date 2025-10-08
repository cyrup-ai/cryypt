//! Async compression result type implementing the unwrapping pattern

use crate::{CompressionError, CompressionResult, Result};
use cryypt_common::NotResult;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::oneshot;

/// Concrete async compression resolution result
pub struct AsyncCompressionResult {
    receiver: oneshot::Receiver<Result<CompressionResult>>,
}

/// Async compression result with user-defined error handler
pub struct AsyncCompressionResultWithHandler<F> {
    receiver: oneshot::Receiver<Result<CompressionResult>>,
    handler: Option<F>,
    completed: bool,
}

impl AsyncCompressionResult {
    /// Create a new `AsyncCompressionResult` from a oneshot receiver
    pub(crate) fn new(receiver: oneshot::Receiver<Result<CompressionResult>>) -> Self {
        Self { receiver }
    }

    /// Create an `AsyncCompressionResult` that's already completed
    #[must_use]
    pub fn ready(result: Result<CompressionResult>) -> Self {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(result);
        Self { receiver: rx }
    }

    /// Create an `AsyncCompressionResult` that yields an error
    #[must_use]
    pub fn error(error: CompressionError) -> Self {
        Self::ready(Err(error))
    }

    /// Add a result handler following README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> AsyncCompressionResultWithHandler<F>
    where
        F: FnOnce(Result<CompressionResult>) -> T,
    {
        AsyncCompressionResultWithHandler {
            receiver: self.receiver,
            handler: Some(handler),
            completed: false,
        }
    }
}

impl Future for AsyncCompressionResult {
    type Output = Result<CompressionResult>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(CompressionError::internal(
                "Compression resolution task dropped",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<F, T> Future for AsyncCompressionResultWithHandler<F>
where
    F: FnOnce(Result<CompressionResult>) -> T + Unpin,
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
                    Poll::Ready(handler(Err(CompressionError::internal(
                        "Compression resolution task dropped",
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
