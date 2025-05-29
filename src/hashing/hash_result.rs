//! Hash result type that implements Future for clean async interfaces

use crate::{CryptError, Result};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::oneshot;

/// Result of a hash operation that can be awaited
pub struct HashResultImpl {
    receiver: oneshot::Receiver<Result<Vec<u8>>>,
}

impl HashResultImpl {
    /// Create a new HashResultImpl from a oneshot receiver
    pub(crate) fn new(receiver: oneshot::Receiver<Result<Vec<u8>>>) -> Self {
        Self { receiver }
    }

    /// Create a HashResultImpl that's already completed
    pub(crate) fn ready(result: Result<Vec<u8>>) -> Self {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(result); // Safe to ignore error since we control both ends
        Self { receiver: rx }
    }

    /// Create a HashResultImpl that yields an error
    pub(crate) fn error(error: CryptError) -> Self {
        Self::ready(Err(error))
    }

    /// Create a HashResultImpl from a closure that computes the hash
    pub(crate) fn from_computation<F>(computation: F) -> Self
    where
        F: FnOnce() -> Result<Vec<u8>> + Send + 'static,
    {
        let (tx, rx) = oneshot::channel();
        
        tokio::spawn(async move {
            let result = tokio::task::spawn_blocking(computation)
                .await
                .unwrap_or_else(|e| Err(CryptError::internal(format!("Hash task panicked: {}", e))));
            let _ = tx.send(result);
        });
        
        Self { receiver: rx }
    }
}

impl Future for HashResultImpl {
    type Output = Result<Vec<u8>>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(result)) => Poll::Ready(result),
            Poll::Ready(Err(_)) => Poll::Ready(Err(CryptError::internal("Hash task dropped"))),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Result of a batch hash operation that can be streamed
pub struct HashStream {
    receiver: tokio_stream::wrappers::ReceiverStream<Result<Vec<u8>>>,
}

impl HashStream {
    /// Create a new HashStream from an mpsc receiver
    pub(crate) fn new(receiver: tokio::sync::mpsc::Receiver<Result<Vec<u8>>>) -> Self {
        use tokio_stream::wrappers::ReceiverStream;
        Self {
            receiver: ReceiverStream::new(receiver),
        }
    }
}

impl futures::Stream for HashStream {
    type Item = Result<Vec<u8>>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.receiver).poll_next(cx)
    }
}