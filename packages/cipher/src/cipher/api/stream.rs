//! Streaming encryption/decryption support

use crate::Result;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc;
use tokio_stream::Stream;

/// Stream of encrypted or decrypted chunks
pub struct CryptoStream {
    receiver: mpsc::Receiver<Result<Vec<u8>>>,
    handler: Option<Box<dyn Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send>>,
}

impl CryptoStream {
    /// Create a new crypto stream
    pub fn new(receiver: mpsc::Receiver<Result<Vec<u8>>>) -> Self {
        Self {
            receiver,
            handler: None,
        }
    }

    /// Apply on_chunk! handler to the stream
    pub fn on_chunk<F>(mut self, handler: F) -> Self
    where
        F: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Send + 'static,
    {
        self.handler = Some(Box::new(handler));
        self
    }
}

impl Stream for CryptoStream {
    type Item = Vec<u8>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match self.receiver.poll_recv(cx) {
            Poll::Ready(Some(result)) => {
                if let Some(handler) = &self.handler {
                    // Apply the on_chunk! handler
                    Poll::Ready(handler(result))
                } else {
                    // No handler - pass through Ok values, skip Err
                    match result {
                        Ok(chunk) => Poll::Ready(Some(chunk)),
                        Err(_) => Poll::Ready(None),
                    }
                }
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

// Implement standard async iteration
impl CryptoStream {
    /// Get the next chunk from the stream
    pub async fn next(&mut self) -> Option<Vec<u8>> {
        use tokio_stream::StreamExt;
        StreamExt::next(self).await
    }
}