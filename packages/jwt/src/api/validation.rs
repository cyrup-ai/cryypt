//! JWT validation and async result handling
//!
//! Contains async result wrappers and validation utilities for JWT operations.

use crate::{JwtResult, error::JwtError};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::oneshot;

/// Async JWT result type for direct operations
pub struct AsyncJwtResult<T> {
    receiver: oneshot::Receiver<JwtResult<T>>,
}

impl<T> AsyncJwtResult<T> {
    pub(crate) fn new(receiver: oneshot::Receiver<JwtResult<T>>) -> Self {
        Self { receiver }
    }
}

impl<T> Future for AsyncJwtResult<T> {
    type Output = JwtResult<T>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(JwtError::internal("Channel closed"))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Async JWT result with error handler
pub struct AsyncJwtResultWithError<T, E> {
    receiver: oneshot::Receiver<JwtResult<T>>,
    error_handler: E,
}

impl<T, E> AsyncJwtResultWithError<T, E> {
    pub(crate) fn new(receiver: oneshot::Receiver<JwtResult<T>>, error_handler: E) -> Self {
        Self {
            receiver,
            error_handler,
        }
    }
}

impl<T, E> Future for AsyncJwtResultWithError<T, E>
where
    E: Fn(JwtError) -> JwtError + Send + Sync + 'static + Unpin,
{
    type Output = JwtResult<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match Pin::new(&mut this.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => match result {
                Ok(value) => Poll::Ready(Ok(value)),
                Err(error) => {
                    let transformed_error = (this.error_handler)(error);
                    Poll::Ready(Err(transformed_error))
                }
            },
            Poll::Ready(Err(_)) => Poll::Ready(Err(JwtError::internal("Channel closed"))),
            Poll::Pending => Poll::Pending,
        }
    }
}
