//! QUIC stream management
//!
//! Provides stream multiplexing and protocol handling capabilities
//! for file transfer, messaging, and RPC protocols over QUIC.

use super::config::Protocol;
use crate::{quic_conn::QuicConnectionHandle, Result};
use std::net::SocketAddr;
use std::time::Duration;

/// Stream dispatcher for multiplexed protocols
pub struct QuicStreamDispatcher {
    addr: SocketAddr,
    handle: Option<QuicConnectionHandle>,
}

impl QuicStreamDispatcher {
    pub(super) fn new(addr: SocketAddr, handle: Option<QuicConnectionHandle>) -> Self {
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
    pub(super) fn upload(path: String, addr: SocketAddr) -> Self {
        Self {
            operation: FileOperation::Upload,
            path,
            addr,
            compressed: false,
            progress_handler: None,
        }
    }

    pub(super) fn download(path: String, addr: SocketAddr) -> Self {
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
    type Output = FileTransferResult;

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
        std::task::Poll::Ready(result)
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
    type Output = ();

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
    pub(super) fn new(
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
    type Output = String;

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