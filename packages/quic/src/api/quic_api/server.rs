//! QUIC Server Builder Patterns and Implementation
//!
//! This module provides the builder pattern implementation for QUIC servers,
//! including configuration, result handlers, and binding operations.

use super::core::QuicServer;
use cryypt_common::NotResult;
use std::sync::Arc;
use tokio::sync::oneshot;

/// QUIC server builder
pub struct QuicServerBuilder {
    cert: Option<Vec<u8>>,
    #[allow(dead_code)]
    key: Option<Vec<u8>>,
}

/// QUIC server builder with cert and key
pub struct QuicServerWithConfig {
    cert: Vec<u8>,
    key: Vec<u8>,
}

/// QUIC server builder with config and result handler
pub struct QuicServerWithConfigAndHandler<F, T> {
    cert: Vec<u8>,
    key: Vec<u8>,
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

impl Default for QuicServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl QuicServerBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self {
            cert: None,
            key: None,
        }
    }

    /// Set server certificate
    #[must_use]
    pub fn with_cert(mut self, cert: Vec<u8>) -> Self {
        self.cert = Some(cert);
        self
    }

    /// Set server private key
    #[must_use]
    pub fn with_key(self, key: Vec<u8>) -> QuicServerWithConfig {
        QuicServerWithConfig {
            cert: self.cert.unwrap_or_default(),
            key,
        }
    }
}

impl QuicServerWithConfig {
    /// Set server certificate after key
    #[must_use]
    pub fn with_cert(mut self, cert: Vec<u8>) -> Self {
        self.cert = cert;
        self
    }

    /// Add `on_result` handler - README.md pattern
    #[must_use]
    pub fn on_result<F, T>(self, handler: F) -> QuicServerWithConfigAndHandler<F, T>
    where
        F: FnOnce(crate::Result<QuicServer>) -> T + Send + 'static,
        T: NotResult + Send + 'static,
    {
        QuicServerWithConfigAndHandler {
            cert: self.cert,
            key: self.key,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Bind server without handler - returns future
    #[must_use]
    pub fn bind<A: Into<String>>(self, addr: A) -> crate::QuicResult {
        let addr_str = addr.into();
        let cert = self.cert;
        let key = self.key;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = bind_quic_server(&cert, &key, &addr_str);
            let _ = tx.send(result);
        });

        crate::QuicResult::new(rx)
    }
}

impl<F, T> QuicServerWithConfigAndHandler<F, T>
where
    F: FnOnce(crate::Result<QuicServer>) -> T + Send + 'static,
    T: NotResult + Send + 'static,
{
    /// Bind server to address - action takes address as argument per README.md
    pub fn bind<A: Into<String>>(self, addr: A) -> T {
        let addr_str = addr.into();
        let cert = self.cert;
        let key = self.key;
        let handler = self.result_handler;

        // Perform QUIC server binding
        let result = bind_quic_server(&cert, &key, &addr_str);

        // Apply result handler
        handler(result)
    }
}

// Internal helper function for server binding
fn bind_quic_server(cert: &[u8], key: &[u8], addr: &str) -> crate::Result<QuicServer> {
    use std::net::SocketAddr;

    // Parse address
    let socket_addr = addr.parse::<SocketAddr>().map_err(|e| {
        crate::error::CryptoTransportError::Internal(format!("Invalid address {addr}: {e}"))
    })?;

    // Create server config
    let mut config = crate::builder::QuicCryptoConfig::new();
    config.set_cert_chain(cert.to_vec());
    config.set_private_key(key.to_vec());

    // Create server config
    let server_config = crate::server::QuicServerConfig {
        listen_addr: addr.to_string(),
        crypto: Arc::new(config),
    };

    // Start the server in background
    let server_future = crate::server::run_quic_server(server_config);
    let handle = tokio::spawn(server_future);

    // Server is immediately bound (async bind happens in background)
    Ok(QuicServer {
        addr: socket_addr,
        bound: true,
        _handle: Some(handle),
    })
}
