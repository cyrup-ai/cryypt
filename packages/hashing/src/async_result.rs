//! Async hash result type implementing the unwrapping pattern

use crate::{HashError, HashResult, Result};
use cryypt_common::NotResult;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::oneshot;

/// Concrete async hash resolution result
pub struct AsyncHashResult {
    receiver: oneshot::Receiver<Result<HashResult>>,
}

/// Async hash result with user-defined error handler
pub struct AsyncHashResultWithHandler<F> {
    receiver: oneshot::Receiver<Result<HashResult>>,
    handler: Option<F>,
    completed: bool,
}

/// Async hash result with error transformation
pub struct AsyncHashResultWithError<E> {
    receiver: oneshot::Receiver<Result<HashResult>>,
    error_handler: E,
}

impl AsyncHashResult {
    /// Create a new `AsyncHashResult` from a oneshot receiver
    pub(crate) fn new(receiver: oneshot::Receiver<Result<HashResult>>) -> Self {
        Self { receiver }
    }

    /// Create an `AsyncHashResult` that's already completed
    #[must_use]
    pub fn ready(result: Result<HashResult>) -> Self {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(result);
        Self { receiver: rx }
    }

    /// Create an `AsyncHashResult` that yields an error
    #[must_use]
    pub fn error(error: HashError) -> Self {
        Self::ready(Err(error))
    }

    /// Add a result handler following README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> AsyncHashResultWithHandler<F>
    where
        F: FnOnce(Result<HashResult>) -> T,
    {
        AsyncHashResultWithHandler {
            receiver: self.receiver,
            handler: Some(handler),
            completed: false,
        }
    }
}

impl Future for AsyncHashResult {
    type Output = Result<HashResult>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => {
                Poll::Ready(Err(HashError::internal("Hash resolution task dropped")))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<F, T> Future for AsyncHashResultWithHandler<F>
where
    F: FnOnce(Result<HashResult>) -> T + Unpin,
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
                    Poll::Ready(handler(Err(HashError::internal(
                        "Hash resolution task dropped",
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

impl<E> AsyncHashResultWithError<E> {
    /// Create a new `AsyncHashResultWithError`
    pub(crate) fn new(receiver: oneshot::Receiver<Result<HashResult>>, error_handler: E) -> Self {
        Self {
            receiver,
            error_handler,
        }
    }
}

impl<E> Future for AsyncHashResultWithError<E>
where
    E: Fn(HashError) -> HashError + Unpin,
{
    type Output = Result<HashResult>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match Pin::new(&mut this.receiver).poll(cx) {
            Poll::Ready(Ok(Ok(value))) => Poll::Ready(Ok(value)),
            Poll::Ready(Ok(Err(e))) => Poll::Ready(Err((this.error_handler)(e))),
            Poll::Ready(Err(_)) => Poll::Ready(Err((this.error_handler)(HashError::internal(
                "Hash resolution task dropped",
            )))),
            Poll::Pending => Poll::Pending,
        }
    }
}
