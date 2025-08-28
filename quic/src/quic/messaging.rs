//! Messaging protocol over QUIC stream

use crate::quic_conn::QuicConnectionHandle;
use std::net::SocketAddr;

/// Messaging protocol over QUIC stream
pub struct MessagingProtocol {
    addr: SocketAddr,
    handle: Option<QuicConnectionHandle>,
}

impl MessagingProtocol {
    pub(super) fn new(addr: SocketAddr, handle: Option<QuicConnectionHandle>) -> Self {
        Self { addr, handle }
    }

    /// Send a message
    pub fn send(&self, message: impl Into<String>) -> MessageBuilder {
        MessageBuilder::new(message.into(), self.addr, self.handle.clone())
    }
}

/// Builder for messaging operations
pub struct MessageBuilder {
    message: String,
    addr: SocketAddr,
    reliable: bool,
    handle: Option<QuicConnectionHandle>,
}

impl MessageBuilder {
    pub(super) fn new(message: String, addr: SocketAddr, handle: Option<QuicConnectionHandle>) -> Self {
        Self {
            message,
            addr,
            reliable: false,
            handle,
        }
    }

    /// Ensure reliable delivery
    pub fn reliable(mut self) -> Self {
        self.reliable = true;
        self
    }
}

impl std::future::Future for MessageBuilder {
    type Output = Result<(), crate::CryptoTransportError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // Log message details
        println!(
            "📤 Sending message to {} (reliable: {})",
            self.addr, self.reliable
        );
        println!("    Message: {}", self.message);

        if let Some(handle) = &self.handle {
            let handle_clone = handle.clone();
            let message = self.message.clone();

            let fut = async move {
                // Wait for handshake
                handle_clone.wait_for_handshake().await?;

                // Send the message
                let data = message.as_bytes();
                handle_clone.send_stream_data(data, true)?;

                Ok(())
            };

            // Create a pinned future and poll it
            let mut pinned = Box::pin(fut);
            pinned.as_mut().poll(cx)
        } else {
            std::task::Poll::Ready(Err(crate::CryptoTransportError::Internal(
                "No QUIC connection handle available".to_string(),
            )))
        }
    }
}