//! QUIC client implementation
//!
//! Provides builder pattern for establishing QUIC client connections
//! with support for various authentication methods.

use super::config::{Auth, Transport};
use crate::builder::QuicCryptoConfig;
use crate::{client::connect_quic_client, Result};
use std::net::SocketAddr;
use std::sync::Arc;

use super::connection::QuicConnection;

/// Builder for QUIC client connections
pub struct ClientBuilder {
    transport: Transport,
    auth: Option<Auth>,
}

impl ClientBuilder {
    pub(super) fn new(transport: Transport) -> Self {
        Self {
            transport,
            auth: None,
        }
    }

    /// Set authentication configuration
    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Connect to a remote QUIC server
    pub async fn connect(self, addr: impl Into<String>) -> Result<QuicConnection> {
        let addr_str = addr.into();
        let socket_addr: SocketAddr = addr_str.parse().map_err(|e| {
            crate::CryptoTransportError::Internal(format!("Invalid address {}: {addr_str, e}"))
        })?;

        // Validate transport type
        match self.transport {
            Transport::UDP => {
                println!(
                    "🌐 Establishing QUIC over UDP connection to {}",
                    socket_addr
                );
            }
        }

        // Build crypto config based on auth
        let crypto_config = match &self.auth {
            Some(Auth::MutualTLS { cert, key }) => {
                let mut config = QuicCryptoConfig::new();
                config.set_cert_chain(cert.clone());
                config.set_private_key(key.clone());
                Arc::new(config)
            }
            Some(Auth::PSK { key: _ }) => {
                // PSK not supported in quiche, use default config
                Arc::new(QuicCryptoConfig::new())
            }
            Some(Auth::Anonymous) | None => Arc::new(QuicCryptoConfig::new()),
        };

        // Connect using the actual QUIC implementation
        let local_addr = "0.0.0.0:0"; // Let OS choose port
        let handle = connect_quic_client(local_addr, &addr_str, crypto_config).await?;

        let mut connection = QuicConnection::new(socket_addr, self.auth);
        connection.handle = Some(handle);
        Ok(connection)
    }
}