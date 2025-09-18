//! QUIC stream operations for send and receive

use cryypt_common::NotResult;
use futures::Stream;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

/// QUIC send stream
pub struct QuicSend {
    handle: Option<crate::quic_conn::QuicConnectionHandle>,
    stream_id: Option<u64>,
}

impl QuicSend {
    pub(crate) fn new_with_handle(handle: crate::quic_conn::QuicConnectionHandle, stream_id: u64) -> Self {
        Self {
            handle: Some(handle),
            stream_id: Some(stream_id),
        }
    }

    /// Create empty send stream (for error cases)
    pub fn new() -> Self {
        Self { handle: None, stream_id: None }
    }

    /// Write data with error handler - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> QuicSendWithHandler<F, T>
    where
        F: FnOnce(crate::Result<()>) -> T + Send + 'static,
        T: NotResult + Send + 'static,
    {
        QuicSendWithHandler {
            send: self,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Write data without handler - returns future
    pub fn write_all(self, data: &[u8]) -> crate::QuicWriteResult {
        let send_copy = QuicSend {
            handle: self.handle.clone(),
            stream_id: self.stream_id,
        };
        let data = data.to_vec();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = write_all_internal(&send_copy, &data);
            let _ = tx.send(result);
        });

        crate::QuicWriteResult::new(rx)
    }
}

/// Send stream with handler following cipher pattern
pub struct QuicSendWithHandler<F, T> {
    send: QuicSend,
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

impl<F, T> QuicSendWithHandler<F, T>
where
    F: FnOnce(crate::Result<()>) -> T + Send + 'static,
    T: NotResult + Send + 'static,
{
    /// Write all data - action takes data as argument per README.md
    pub async fn write_all(self, data: &[u8]) -> T {
        let send_copy = QuicSend {
            handle: self.send.handle.clone(),
            stream_id: self.send.stream_id,
        };
        let data = data.to_vec();
        let handler = self.result_handler;

        // Perform QUIC write operation
        let result = write_all_internal(&send_copy, &data);

        // Apply result handler
        handler(result)
    }
}

/// QUIC receive stream
pub struct QuicRecv {
    receiver: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
    stream_id: u64,
}

impl QuicRecv {
    /// Create empty recv stream (for error cases)
    pub fn new() -> Self {
        Self { receiver: None, stream_id: 0 }
    }

    /// Create with real connection integration
    pub(crate) fn new_with_handle(handle: crate::quic_conn::QuicConnectionHandle, stream_id: u64) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        
        let target_stream_id = stream_id;
        // Spawn task to listen for QUIC connection events and forward stream data
        tokio::spawn(async move {
            let mut event_rx = handle.subscribe_to_events();
            
            // Forward relevant stream data to the receiver
            while let Ok(event) = event_rx.recv().await {
                match event {
                    crate::quic_conn::QuicConnectionEvent::InboundStreamData(event_stream_id, data) => {
                        // Only forward data for our specific stream ID
                        if event_stream_id == target_stream_id {
                            if tx.send(data).is_err() {
                                break; // Receiver dropped
                            }
                        }
                    }
                    crate::quic_conn::QuicConnectionEvent::StreamFinished(event_stream_id) => {
                        if event_stream_id == target_stream_id {
                            // Stream finished, close the channel
                            break;
                        }
                    }
                    _ => {
                        // Ignore other events (handshake, connection closed, etc.)
                        continue;
                    }
                }
            }
        });
        
        Self { receiver: Some(rx), stream_id: target_stream_id }
    }

    /// Create empty recv stream (for error cases)
    pub fn empty() -> Self {
        Self { receiver: None, stream_id: 0 }
    }

    /// Set chunk handler for streaming - README.md pattern
    pub fn on_chunk<F>(self, handler: F) -> QuicRecvStream<F>
    where
        F: Fn(crate::Result<Vec<u8>>) -> Option<Vec<u8>> + Send + 'static,
    {
        QuicRecvStream {
            recv: self,
            handler,
        }
    }
}

/// Receive stream with chunk handler
pub struct QuicRecvStream<F> {
    recv: QuicRecv,
    handler: F,
}

impl<F> QuicRecvStream<F>
where
    F: Fn(crate::Result<Vec<u8>>) -> Option<Vec<u8>> + Send + 'static,
{
    /// Get the stream
    pub fn stream(self) -> impl Stream<Item = Vec<u8>> + Send + 'static {
        struct QuicRecvStreamAdapter<F> {
            receiver: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
            handler: F,
        }

        impl<F> Unpin for QuicRecvStreamAdapter<F> {}

        impl<F> Stream for QuicRecvStreamAdapter<F>
        where
            F: Fn(crate::Result<Vec<u8>>) -> Option<Vec<u8>> + Send + 'static,
        {
            type Item = Vec<u8>;

            fn poll_next(
                mut self: std::pin::Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Self::Item>> {
                let this = self.as_mut().get_mut();
                if let Some(ref mut rx) = this.receiver {
                    match rx.poll_recv(cx) {
                        std::task::Poll::Ready(Some(data)) => {
                            let result = Ok(data);
                            if let Some(processed) = (this.handler)(result) {
                                std::task::Poll::Ready(Some(processed))
                            } else {
                                // Handler filtered out this chunk, poll again
                                cx.waker().wake_by_ref();
                                std::task::Poll::Pending
                            }
                        }
                        std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
                        std::task::Poll::Pending => std::task::Poll::Pending,
                    }
                } else {
                    std::task::Poll::Ready(None)
                }
            }
        }

        QuicRecvStreamAdapter {
            receiver: self.recv.receiver,
            handler: self.handler,
        }
    }
}

// Internal helper functions for stream operations
pub(crate) async fn open_bi_stream_internal(
    handle: Option<crate::quic_conn::QuicConnectionHandle>,
) -> crate::Result<(QuicSend, QuicRecv)> {
    if let Some(ref handle) = handle {
        // Wait for handshake to complete
        handle.wait_for_handshake().await?;

        // Generate unique stream ID for this bidirectional pair
        let stream_id = crate::quic_conn::generate_next_stream_id();

        // Create send/recv pair with real connection integration
        Ok((
            QuicSend::new_with_handle(handle.clone(), stream_id), 
            QuicRecv::new_with_handle(handle.clone(), stream_id)
        ))
    } else {
        Err(crate::error::CryptoTransportError::Internal(
            "Client not connected".to_string(),
        ))
    }
}

fn write_all_internal(
    send: &QuicSend,
    data: &[u8],
) -> crate::Result<()> {
    if let Some(ref handle) = send.handle {
        if let Some(stream_id) = send.stream_id {
            handle.send_stream_data_with_id(stream_id, data, true)
        } else {
            handle.send_stream_data(data, true)
        }
    } else {
        Err(crate::error::CryptoTransportError::Internal(
            "Send stream not initialized".to_string(),
        ))
    }
}
