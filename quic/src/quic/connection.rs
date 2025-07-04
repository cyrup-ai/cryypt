//! QUIC connection handling
//!
//! Provides connection management and protocol multiplexing capabilities
//! for QUIC transport layer.

use super::config::Auth;
use super::stream::{FileTransferBuilder, QuicStreamDispatcher};
use crate::{quic_conn::QuicConnectionHandle, Result};
use std::net::SocketAddr;

/// Persistent QUIC connection for multiplexed protocols
pub struct QuicConnection {
    addr: SocketAddr,
    auth: Option<Auth>,
    pub(super) handle: Option<QuicConnectionHandle>,
}

impl QuicConnection {
    pub(super) fn new(addr: SocketAddr, auth: Option<Auth>) -> Self {
        Self {
            addr,
            auth,
            handle: None,
        }
    }

    /// Dispatch multiple protocols over the same connection
    pub async fn stream<F, Fut>(&self, handler: F) -> Result<()>
    where
        F: FnOnce(QuicStreamDispatcher) -> Fut + Send,
        Fut: std::future::Future<Output = Result<()>> + Send,
    {
        let dispatcher = QuicStreamDispatcher::new(self.addr, self.handle.clone());
        handler(dispatcher).await
    }

    /// Convenience method: Upload a file
    pub fn upload_file(&self, path: impl Into<String>) -> FileTransferBuilder {
        FileTransferBuilder::upload(path.into(), self.addr)
    }

    /// Convenience method: Download a file
    pub fn download_file(&self, path: impl Into<String>) -> FileTransferBuilder {
        FileTransferBuilder::download(path.into(), self.addr)
    }

    /// Convenience method: Send a message
    pub async fn send_message(&self, message: impl Into<String>) -> Result<()> {
        let msg = message.into();
        println!(
            "📤 Sending message to {} (auth: {})",
            self.addr,
            match &self.auth {
                Some(Auth::MutualTLS { .. }) => "MutualTLS",
                Some(Auth::PSK { .. }) => "PSK",
                Some(Auth::Anonymous) => "Anonymous",
                None => "None",
            }
        );

        if let Some(handle) = &self.handle {
            // Wait for handshake to complete
            handle.wait_for_handshake().await?;

            // Send the message over QUIC stream
            let data = msg.as_bytes();
            handle.send_stream_data(data, true)?;
            println!("    Message sent: {}", msg);
        } else {
            return Err(crate::CryptoTransportError::Internal(
                "No active connection".to_string(),
            ));
        }
        Ok(())
    }

    /// Convenience method: Call RPC
    pub async fn call_rpc(
        &self,
        method: impl Into<String>,
        params: impl Into<String>,
    ) -> Result<String> {
        let method_str = method.into();
        let params_str = params.into();

        if let Some(handle) = &self.handle {
            // Wait for handshake to complete
            handle.wait_for_handshake().await?;

            // Create RPC request
            let request = serde_json::json!({
                "method": method_str,
                "params": params_str,
                "id": 1
            });

            let data = serde_json::to_vec(&request).map_err(|e| {
                crate::CryptoTransportError::Internal(format!("Failed to serialize RPC: {}", e))
            })?;

            // Send RPC request
            handle.send_stream_data(&data, true)?;
            println!("🔄 RPC {} called on {}", method_str, self.addr);

            // For now, return a mock response since we need to implement receiving
            // In a complete implementation, we'd wait for the response
            Ok(format!("{{\"result\": \"Response for {}\"}}", method_str))
        } else {
            Err(crate::CryptoTransportError::Internal(
                "No active connection".to_string(),
            ))
        }
    }
}