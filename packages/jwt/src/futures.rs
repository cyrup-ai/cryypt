//! Concrete Future types for JWT operations.
//!
//! This module provides Future implementations that hide async complexity
//! behind channels and spawned tasks, following the project's async conventions.

use crate::{
    api::claims::Claims,
    error::{JwtError, JwtResult},
};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::sync::oneshot;

/// Future for token generation operations.
pub struct TokenGenerationFuture {
    rx: oneshot::Receiver<JwtResult<String>>,
}

impl TokenGenerationFuture {
    /// Create a new token generation future with the given receiver.
    pub(crate) fn new(rx: oneshot::Receiver<JwtResult<String>>) -> Self {
        Self { rx }
    }
}

impl Future for TokenGenerationFuture {
    type Output = JwtResult<String>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.rx).poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(JwtError::TaskJoinError)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Future for token verification operations.
pub struct TokenVerificationFuture {
    rx: oneshot::Receiver<JwtResult<Claims>>,
}

impl TokenVerificationFuture {
    /// Create a new token verification future with the given receiver.
    pub(crate) fn new(rx: oneshot::Receiver<JwtResult<Claims>>) -> Self {
        Self { rx }
    }
}

impl Future for TokenVerificationFuture {
    type Output = JwtResult<Claims>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.rx).poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(JwtError::TaskJoinError)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Future for cleanup task start operations.
pub struct CleanupStartFuture {
    rx: oneshot::Receiver<()>,
}

impl CleanupStartFuture {
    /// Create a new cleanup start future with the given receiver.
    pub(crate) fn new(rx: oneshot::Receiver<()>) -> Self {
        Self { rx }
    }
}

impl Future for CleanupStartFuture {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.rx).poll(cx) {
            Poll::Ready(_) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
        }
    }
}

