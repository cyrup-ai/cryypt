//! Stream trait implementation for `GzipStream`

use super::stream_core::GzipStream;
use crate::Result;
use std::pin::Pin;
use tokio_stream::Stream;

impl<C> Stream for GzipStream<C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Unpin,
{
    type Item = Vec<u8>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        match self.receiver.poll_recv(cx) {
            std::task::Poll::Ready(Some(result)) => {
                // Apply user's chunk handler
                std::task::Poll::Ready((self.handler)(result))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

// Implement standard async iteration
impl<C> GzipStream<C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Unpin,
{
    /// Get the next chunk from the stream
    pub async fn next(&mut self) -> Option<Vec<u8>> {
        use tokio_stream::StreamExt;
        StreamExt::next(self).await
    }
}
