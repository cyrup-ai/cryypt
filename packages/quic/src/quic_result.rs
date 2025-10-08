//! Concrete QUIC result types implementing the unwrapping pattern

use crate::{Result, error::CryptoTransportError};
// Removed unused import: use cryypt_common::NotResult;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::oneshot;

/// Generic QUIC result for both server and client operations
pub struct QuicResult<T = crate::api::QuicServer> {
    receiver: oneshot::Receiver<Result<T>>,
}

/// QUIC result with user-defined error handler
#[allow(dead_code)]
pub struct QuicResultWithHandler<T, F> {
    receiver: oneshot::Receiver<Result<T>>,
    handler: Option<F>,
}

/// Type alias for server results (backward compatibility)
pub type QuicServerResult = QuicResult<crate::api::QuicServer>;

/// Type alias for client results
pub type QuicClientResult = QuicResult<crate::api::QuicClient>;

impl<T> QuicResult<T> {
    /// Create a new `QuicResult` from a oneshot receiver
    pub(crate) fn new(receiver: oneshot::Receiver<Result<T>>) -> Self {
        Self { receiver }
    }

    /// Create a `QuicResult` that's already completed
    pub fn ready(result: Result<T>) -> Self {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(result);
        Self { receiver: rx }
    }

    /// Create a `QuicResult` that yields an error
    #[must_use]
    pub fn error(error: CryptoTransportError) -> Self {
        Self::ready(Err(error))
    }
}

impl<T> Future for QuicResult<T> {
    type Output = Result<T>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(CryptoTransportError::Internal(
                "QUIC resolution task dropped".to_string(),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Concrete QUIC stream result (for `open_bi`)
pub struct QuicStreamResult {
    receiver: oneshot::Receiver<Result<(crate::api::QuicSend, crate::api::QuicRecv)>>,
}

impl QuicStreamResult {
    /// Create a new `QuicStreamResult` from a oneshot receiver
    pub(crate) fn new(
        receiver: oneshot::Receiver<Result<(crate::api::QuicSend, crate::api::QuicRecv)>>,
    ) -> Self {
        Self { receiver }
    }
}

impl Future for QuicStreamResult {
    type Output = Result<(crate::api::QuicSend, crate::api::QuicRecv)>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(CryptoTransportError::Internal(
                "QUIC stream task dropped".to_string(),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Concrete QUIC write result (for `write_all`)
pub struct QuicWriteResult {
    receiver: oneshot::Receiver<Result<()>>,
}

impl QuicWriteResult {
    /// Create a new `QuicWriteResult` from a oneshot receiver
    pub(crate) fn new(receiver: oneshot::Receiver<Result<()>>) -> Self {
        Self { receiver }
    }
}

impl Future for QuicWriteResult {
    type Output = Result<()>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(CryptoTransportError::Internal(
                "QUIC write task dropped".to_string(),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}
