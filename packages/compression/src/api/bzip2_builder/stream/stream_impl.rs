//! Stream trait implementation and async iteration for `Bzip2Stream`

use super::stream_core::Bzip2Stream;
use crate::Result;
use std::pin::Pin;
use tokio_stream::Stream;

impl<C> Stream for Bzip2Stream<C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Unpin,
{
    type Item = Vec<u8>;

    #[inline]
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

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        // We don't know the exact size, but we can hint based on channel
        (0, None)
    }
}

// Implement standard async iteration
impl<C> Bzip2Stream<C>
where
    C: Fn(Result<Vec<u8>>) -> Option<Vec<u8>> + Unpin,
{
    /// Get the next chunk from the stream
    #[inline]
    pub async fn next(&mut self) -> Option<Vec<u8>> {
        use tokio_stream::StreamExt;
        StreamExt::next(self).await
    }
}
