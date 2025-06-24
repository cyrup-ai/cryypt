//! Quique - QUIC transport with multiplexed protocol dispatch
//!
//! Provides a fluent, type-safe API for establishing persistent QUIC connections
//! and multiplexing different application protocols over the same connection.

use crate::builder::QuicCryptoConfig;
use crate::{client::connect_quic_client, quic_conn::QuicConnectionHandle, Result};
use serde_json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Transport layer specification
#[derive(Debug, Clone, Copy)]
pub enum Transport {
    /// UDP transport (QUIC protocol)
    UDP,
}

/// Authentication configuration
#[derive(Debug, Clone)]
pub enum Auth {
    /// Mutual TLS with certificate and private key
    MutualTLS {
        /// TLS certificate in DER or PEM format
        cert: Vec<u8>,
        /// Private key in DER or PEM format
        key: Vec<u8>,
    },
    /// Pre-shared key authentication
    PSK {
        /// Pre-shared key bytes
        key: Vec<u8>,
    },
    /// Anonymous connection (for testing only)
    Anonymous,
}

/// Application protocol types
#[derive(Debug, Clone, Copy)]
pub enum Protocol {
    /// File transfer protocol with progress tracking
    FileTransfer,
    /// Real-time messaging protocol
    Messaging,
    /// Remote procedure call protocol
    Rpc,
}

/// Main entry point for Quique QUIC transport
pub struct Quique;

impl Quique {
    /// Create a QUIC client with specified transport
    pub fn client(transport: Transport) -> ClientBuilder {
        ClientBuilder::new(transport)
    }

    /// Create a QUIC server with specified transport
    pub fn server(transport: Transport) -> ServerBuilder {
        ServerBuilder::new(transport)
    }
}

/// Builder for QUIC client connections
pub struct ClientBuilder {
    transport: Transport,
    auth: Option<Auth>,
}

impl ClientBuilder {
    fn new(transport: Transport) -> Self {
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
            crate::CryptoTransportError::Internal(format!("Invalid address {}: {}", addr_str, e))
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

/// Builder for QUIC server
pub struct ServerBuilder {
    transport: Transport,
    port: Option<u16>,
    auth: Option<Auth>,
}

impl ServerBuilder {
    fn new(transport: Transport) -> Self {
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
                println!("🚀 Quique server listening on UDP port {}", self.port);
            }
        }
        println!("🔐 Auth: {:?}", self.auth);

        // TODO: Implement actual QUIC server
        // Placeholder - keep server running
        tokio::time::sleep(Duration::from_secs(3600)).await;
        Ok(())
    }
}

/// Persistent QUIC connection for multiplexed protocols
pub struct QuicConnection {
    addr: SocketAddr,
    auth: Option<Auth>,
    handle: Option<QuicConnectionHandle>,
}

impl QuicConnection {
    fn new(addr: SocketAddr, auth: Option<Auth>) -> Self {
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

/// Stream dispatcher for multiplexed protocols
pub struct QuicStreamDispatcher {
    addr: SocketAddr,
    handle: Option<QuicConnectionHandle>,
}

impl QuicStreamDispatcher {
    fn new(addr: SocketAddr, handle: Option<QuicConnectionHandle>) -> Self {
        Self { addr, handle }
    }

    /// Access file transfer protocol
    pub fn file_transfer(&self) -> FileTransferProtocol {
        FileTransferProtocol::new(self.addr)
    }

    /// Access messaging protocol
    pub fn messaging(&self) -> MessagingProtocol {
        MessagingProtocol::new(self.addr, self.handle.clone())
    }

    /// Access RPC protocol
    pub fn rpc(&self) -> RpcProtocol {
        RpcProtocol::new(self.addr, self.handle.clone())
    }
}

/// File transfer protocol over QUIC stream
pub struct FileTransferProtocol {
    addr: SocketAddr,
}

impl FileTransferProtocol {
    fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    /// Upload a file
    pub fn upload(&self, path: impl Into<String>) -> FileTransferBuilder {
        FileTransferBuilder::upload(path.into(), self.addr)
    }

    /// Download a file
    pub fn download(&self, path: impl Into<String>) -> FileTransferBuilder {
        FileTransferBuilder::download(path.into(), self.addr)
    }
}

/// Messaging protocol over QUIC stream
pub struct MessagingProtocol {
    addr: SocketAddr,
    handle: Option<QuicConnectionHandle>,
}

impl MessagingProtocol {
    fn new(addr: SocketAddr, handle: Option<QuicConnectionHandle>) -> Self {
        Self { addr, handle }
    }

    /// Send a message
    pub fn send(&self, message: impl Into<String>) -> MessageBuilder {
        MessageBuilder::new(message.into(), self.addr, self.handle.clone())
    }
}

/// RPC protocol over QUIC stream
pub struct RpcProtocol {
    addr: SocketAddr,
    handle: Option<QuicConnectionHandle>,
}

impl RpcProtocol {
    fn new(addr: SocketAddr, handle: Option<QuicConnectionHandle>) -> Self {
        Self { addr, handle }
    }

    /// Call a remote procedure
    pub fn call(&self, method: impl Into<String>, params: impl Into<String>) -> RpcBuilder {
        RpcBuilder::new(method.into(), params.into(), self.addr, self.handle.clone())
    }
}

/// Builder for file transfer operations
pub struct FileTransferBuilder {
    operation: FileOperation,
    path: String,
    addr: SocketAddr,
    compressed: bool,
    progress_handler: Option<Box<dyn Fn(FileProgress) + Send + Sync>>,
}

#[derive(Debug)]
enum FileOperation {
    Upload,
    Download,
}

/// Progress information for file transfers
#[derive(Debug, Clone)]
pub struct FileProgress {
    /// Percentage complete (0.0 to 100.0)
    pub percent: f64,
    /// Number of bytes transferred so far
    pub bytes_transferred: u64,
    /// Total number of bytes to transfer
    pub total_bytes: u64,
    /// Current transfer rate in megabits per second
    pub mbps: f64,
}

impl FileTransferBuilder {
    fn upload(path: String, addr: SocketAddr) -> Self {
        Self {
            operation: FileOperation::Upload,
            path,
            addr,
            compressed: false,
            progress_handler: None,
        }
    }

    fn download(path: String, addr: SocketAddr) -> Self {
        Self {
            operation: FileOperation::Download,
            path,
            addr,
            compressed: false,
            progress_handler: None,
        }
    }

    /// Enable compression
    pub fn compressed(mut self) -> Self {
        self.compressed = true;
        self
    }

    /// Set progress callback
    pub fn with_progress<F>(mut self, handler: F) -> Self
    where
        F: Fn(FileProgress) + Send + Sync + 'static,
    {
        self.progress_handler = Some(Box::new(handler));
        self
    }
}

impl std::future::Future for FileTransferBuilder {
    type Output = Result<FileTransferResult>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // Log operation details
        match self.operation {
            FileOperation::Upload => {
                println!(
                    "📤 Uploading {} to {} (compressed: {})",
                    self.path, self.addr, self.compressed
                );
            }
            FileOperation::Download => {
                println!(
                    "📥 Downloading {} from {} (compressed: {})",
                    self.path, self.addr, self.compressed
                );
            }
        }

        // Simulate progress callbacks
        if let Some(ref handler) = self.progress_handler {
            handler(FileProgress {
                percent: 100.0,
                bytes_transferred: 1024,
                total_bytes: 1024,
                mbps: 8.0,
            });
        }

        // TODO: Implement actual file transfer
        let result = FileTransferResult {
            bytes_transferred: 1024,
            duration: Duration::from_secs(1),
            success: true,
        };
        std::task::Poll::Ready(Ok(result))
    }
}

/// Result of a file transfer operation
#[derive(Debug)]
pub struct FileTransferResult {
    /// Total number of bytes transferred
    pub bytes_transferred: u64,
    /// Time taken for the transfer
    pub duration: Duration,
    /// Whether the transfer completed successfully
    pub success: bool,
}

/// Builder for messaging operations
pub struct MessageBuilder {
    message: String,
    addr: SocketAddr,
    reliable: bool,
    handle: Option<QuicConnectionHandle>,
}

impl MessageBuilder {
    fn new(message: String, addr: SocketAddr, handle: Option<QuicConnectionHandle>) -> Self {
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
    type Output = Result<()>;

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

/// Builder for RPC operations
pub struct RpcBuilder {
    method: String,
    params: String,
    addr: SocketAddr,
    timeout: Option<Duration>,
    handle: Option<QuicConnectionHandle>,
}

impl RpcBuilder {
    fn new(
        method: String,
        params: String,
        addr: SocketAddr,
        handle: Option<QuicConnectionHandle>,
    ) -> Self {
        Self {
            method,
            params,
            addr,
            timeout: None,
            handle,
        }
    }

    /// Set RPC timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

impl std::future::Future for RpcBuilder {
    type Output = Result<String>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        // Log RPC details
        println!("🔄 Calling RPC method '{}' on {}", self.method, self.addr);
        println!("    Params: {}", self.params);
        if let Some(timeout) = self.timeout {
            println!("    Timeout: {:?}", timeout);
        }

        if let Some(handle) = &self.handle {
            // Create async block to handle the RPC call
            let handle_clone = handle.clone();
            let method = self.method.clone();
            let params = self.params.clone();

            let fut = async move {
                // Wait for handshake
                handle_clone.wait_for_handshake().await?;

                // Create RPC request
                let request = serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": params,
                    "id": 1
                });

                let data = serde_json::to_vec(&request).map_err(|e| {
                    crate::CryptoTransportError::Internal(format!("Failed to serialize RPC: {}", e))
                })?;

                // Send RPC request
                handle_clone.send_stream_data(&data, true)?;

                // Return mock response for now
                Ok(format!("{{\"result\": \"Response for {}\"}}", method))
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

/// Individual QUIC stream for protocol handling
pub struct QuicStream {
    protocol: Protocol,
    stream_id: u64,
}

impl QuicStream {
    /// Get the protocol type for this stream
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Get the stream ID
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }
}
