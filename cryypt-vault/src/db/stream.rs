use crate::error::VaultError;
use futures::{Stream, StreamExt};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

/// A stream of database query results
pub struct QueryStream<T> {
    inner: ReceiverStream<Result<T, VaultError>>,
}

impl<T> QueryStream<T> {
    /// Create a new QueryStream
    pub fn new() -> (Self, mpsc::Sender<Result<T, VaultError>>) {
        let (tx, rx) = mpsc::channel(16);
        (
            Self {
                inner: ReceiverStream::new(rx),
            },
            tx,
        )
    }

    /// Convert into a vector by collecting all items
    pub async fn into_vec(self) -> Result<Vec<T>, VaultError> {
        let mut items = Vec::new();
        let mut stream = self;
        while let Some(result) = stream.next().await {
            items.push(result?);
        }
        Ok(items)
    }

    /// Get the first item from the stream
    pub async fn first(mut self) -> Result<Option<T>, VaultError> {
        self.next().await.transpose()
    }
}

impl<T> Stream for QueryStream<T> {
    type Item = Result<T, VaultError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(cx)
    }
}
