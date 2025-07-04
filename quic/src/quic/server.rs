//! QUIC server implementation
//!
//! Provides builder pattern for creating QUIC servers with stream handling
//! and connection management capabilities.

use super::config::{Auth, Transport};
use crate::Result;
use std::time::Duration;

use super::stream::QuicStream;

/// Builder for QUIC server
pub struct ServerBuilder {
    transport: Transport,
    port: Option<u16>,
    auth: Option<Auth>,
}

impl ServerBuilder {
    pub(super) fn new(transport: Transport) -> Self {
        Self {
            transport,
            port: None,
            auth: None,
        }
    }

    /// Set the port to listen on
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set authentication configuration
    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = Some(auth);
        self
    }

    /// Handle incoming streams with a custom handler
    pub fn handle_streams<F, Fut>(self, _handler: F) -> ServerListenerBuilder
    where
        F: Fn(QuicStream) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<()>> + Send + 'static,
    {
        ServerListenerBuilder {
            transport: self.transport,
            port: self.port.unwrap_or(11443),
            auth: self.auth,
        }
    }
}

/// Builder for starting server listener
pub struct ServerListenerBuilder {
    transport: Transport,
    port: u16,
    auth: Option<Auth>,
}

impl ServerListenerBuilder {
    /// Start listening for connections
    pub async fn listen(self) -> Result<()> {
        // Validate transport type
        match self.transport {
            Transport::UDP => {
                println!("🚀 QUIC server listening on UDP port {}", self.port);
            }
        }
        println!("🔐 Auth: {:?}", self.auth);

        // TODO: Implement actual QUIC server
        // Placeholder - keep server running
        tokio::time::sleep(Duration::from_secs(3600)).await;
        Ok(())
    }
}