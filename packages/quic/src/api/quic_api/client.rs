//! QUIC Client Builder Patterns and Implementation
//!
//! This module provides the builder pattern implementation for QUIC clients,
//! including configuration, result handlers, and connection operations.

use super::core::QuicClient;
use super::streams::{QuicClientWithHandler, QuicRecv, QuicSend};
use cryypt_common::NotResult;
use std::sync::Arc;
use tokio::sync::oneshot;

/// QUIC client builder
pub struct QuicClientBuilder {
    #[allow(dead_code)]
    server_name: Option<String>,
}

/// QUIC client builder with server name
pub struct QuicClientWithConfig {
    server_name: String,
}

/// QUIC client builder with config and result handler
pub struct QuicClientWithConfigAndHandler<F, T> {
    server_name: String,
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

impl Default for QuicClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicClientBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self { server_name: None }
    }

    /// Set server name for TLS
    #[must_use]
    pub fn with_server_name(self, name: impl Into<String>) -> QuicClientWithConfig {
        QuicClientWithConfig {
            server_name: name.into(),
        }
    }
}

impl QuicClientWithConfig {
    /// Add `on_result` handler - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> QuicClientWithConfigAndHandler<F, T>
    where
        F: FnOnce(crate::Result<QuicClient>) -> T + Send + 'static,
        T: NotResult + Send + 'static,
    {
        QuicClientWithConfigAndHandler {
            server_name: self.server_name,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Connect to server without handler - returns future
    pub fn connect<A: Into<String>>(self, addr: A) -> crate::QuicClientResult {
        let addr_str = addr.into();
        let server_name = self.server_name;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = connect_quic_client_internal(&server_name, &addr_str).await;
            let _ = tx.send(result);
        });

        crate::QuicResult::new(rx)
    }
}

impl<F, T> QuicClientWithConfigAndHandler<F, T>
where
    F: FnOnce(crate::Result<QuicClient>) -> T + Send + 'static,
    T: NotResult + Send + 'static,
{
    /// Connect to server - action takes address as argument per README.md
    pub async fn connect<A: Into<String>>(self, addr: A) -> T {
        let addr_str = addr.into();
        let server_name = self.server_name;
        let handler = self.result_handler;

        // Perform QUIC client connection
        let result = connect_quic_client_internal(&server_name, &addr_str).await;

        // Apply result handler
        handler(result)
    }
}

impl QuicClient {
    /// Open bidirectional stream with error handler - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> QuicClientWithHandler<F, T>
    where
        F: FnOnce(crate::Result<(QuicSend, QuicRecv)>) -> T + Send + 'static,
        T: NotResult + Send + 'static,
    {
        QuicClientWithHandler {
            client: self,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Open bidirectional stream without handler - returns future
    #[must_use]
    pub fn open_bi(self) -> crate::QuicStreamResult {
        let handle = self.handle.clone();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = super::streams::open_bi_stream_internal(handle).await;
            let _ = tx.send(result);
        });

        crate::QuicStreamResult::new(rx)
    }
}

// Internal helper function for client connection
async fn connect_quic_client_internal(_server_name: &str, addr: &str) -> crate::Result<QuicClient> {
    use std::net::SocketAddr;

    // Parse address
    let socket_addr = addr.parse::<SocketAddr>().map_err(|e| {
        crate::error::CryptoTransportError::Internal(format!("Invalid address {addr}: {e}"))
    })?;

    // Create client config
    let config = Arc::new(crate::builder::QuicCryptoConfig::new());

    // Connect to server
    match crate::client::connect_quic_client(
        "0.0.0.0:0", // Let OS choose port
        addr,
        config,
    )
    .await
    {
        Ok(handle) => Ok(QuicClient {
            addr: socket_addr,
            connected: true,
            handle: Some(handle),
        }),
        Err(e) => Err(e),
    }
}
