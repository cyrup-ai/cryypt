//! QUIC connection handling
//!
//! Provides connection management and protocol multiplexing capabilities
//! for QUIC transport layer.

use super::config::Auth;
use super::file_transfer::FileTransferConfig;
use super::stream_dispatcher::QuicStreamDispatcher;
use crate::{Result, quic_conn::QuicConnectionHandle};
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{debug, info};

/// Persistent QUIC connection for multiplexed protocols
pub struct QuicConnection {
    addr: SocketAddr,
    auth: Option<Auth>,
    pub(super) handle: Option<QuicConnectionHandle>,
}

impl QuicConnection {
    #[allow(dead_code)]
    #[must_use]
    pub(super) fn new(addr: SocketAddr, auth: Option<Auth>) -> Self {
        Self {
            addr,
            auth,
            handle: None,
        }
    }

    /// Dispatch multiple protocols over the same connection
    ///
    /// # Errors
    ///
    /// Returns any error produced by the provided handler function.
    pub async fn stream<F, Fut>(&self, handler: F) -> Result<()>
    where
        F: FnOnce(QuicStreamDispatcher) -> Fut + Send,
        Fut: std::future::Future<Output = Result<()>> + Send,
    {
        let dispatcher = QuicStreamDispatcher::new(self.addr, self.handle.clone());
        handler(dispatcher).await
    }

    /// Convenience method: Upload a file
    #[must_use]
    pub fn upload_file(&self, path: impl Into<String>) -> super::file_transfer::UploadConfig {
        super::file_transfer::FileTransferConfig::upload(path.into(), self.addr)
    }

    /// Convenience method: Download a file
    #[must_use]
    pub fn download_file(&self, path: impl Into<String>) -> super::file_transfer::DownloadConfig {
        super::file_transfer::FileTransferConfig::download(path.into(), self.addr)
    }

    /// Convenience method: Send a message
    ///
    /// # Errors
    ///
    /// Returns `CryptoTransportError::Internal` if there is no active connection,
    /// or forwards errors from the underlying QUIC connection operations including
    /// handshake completion and stream data transmission.
    pub async fn send_message(&self, message: impl Into<String>) -> Result<()> {
        let msg = message.into();
        let auth_type = match &self.auth {
            Some(Auth::MutualTLS { .. }) => "MutualTLS",
            Some(Auth::PSK { .. }) => "PSK",
            Some(Auth::Anonymous) => "Anonymous",
            None => "None",
        };

        info!(
            addr = %self.addr,
            auth = auth_type,
            "Sending message"
        );

        if let Some(handle) = &self.handle {
            // Wait for handshake to complete
            handle.wait_for_handshake().await?;

            // Send the message over QUIC stream
            let data = msg.as_bytes();
            handle.send_stream_data(data, true)?;
            debug!(message = %msg, "Message sent");
        } else {
            return Err(crate::CryptoTransportError::Internal(
                "No active connection".to_string(),
            ));
        }
        Ok(())
    }

    /// Convenience method: Call RPC
    ///
    /// # Errors
    ///
    /// Returns `CryptoTransportError::Internal` for various failure conditions including:
    /// - JSON serialization failures when creating the RPC request
    /// - No active connection available
    /// - Invalid UTF-8 in the RPC response
    /// - Connection closed before receiving a response
    /// - RPC request timeout (30 seconds)
    ///
    /// Additionally forwards errors from underlying QUIC operations such as
    /// handshake completion and stream data transmission.
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
                crate::CryptoTransportError::Internal(format!("Failed to serialize RPC: {e}"))
            })?;

            // Send RPC request
            handle.send_stream_data(&data, true)?;
            info!(
                method = %method_str,
                addr = %self.addr,
                "RPC method called"
            );

            // Wait for response with timeout
            let mut event_rx = handle.subscribe_to_events();
            let timeout_duration = Duration::from_secs(30);

            let response = tokio::time::timeout(timeout_duration, async {
                while let Ok(event) = event_rx.recv().await {
                    if let crate::quic_conn::QuicConnectionEvent::InboundStreamData(_, data) = event
                    {
                        return String::from_utf8(data).map_err(|e| {
                            crate::CryptoTransportError::Internal(format!(
                                "Invalid UTF-8 in response: {e}"
                            ))
                        });
                    }
                }
                Err(crate::CryptoTransportError::Internal(
                    "Connection closed before response".to_string(),
                ))
            })
            .await;

            match response {
                Ok(Ok(response_str)) => Ok(response_str),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(crate::CryptoTransportError::Internal(
                    "RPC timeout".to_string(),
                )),
            }
        } else {
            Err(crate::CryptoTransportError::Internal(
                "No active connection".to_string(),
            ))
        }
    }
}
