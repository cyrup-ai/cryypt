//! QUIC API following cryypt patterns

use cryypt_common::NotResult;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use futures::Stream;

/// Main entry point - following cryypt pattern
pub struct Quic;

impl Quic {
    /// Create a QUIC server builder
    pub fn server() -> QuicServerBuilder {
        QuicServerBuilder::new()
    }
    
    /// Create a QUIC client builder
    pub fn client() -> QuicClientBuilder {
        QuicClientBuilder::new()
    }
}

/// Direct entry point for QUIC functionality
pub fn quic() -> Quic {
    Quic
}

/// QUIC server builder
pub struct QuicServerBuilder {
    cert: Option<Vec<u8>>,
    key: Option<Vec<u8>>,
}

impl QuicServerBuilder {
    pub(crate) fn new() -> Self {
        Self {
            cert: None,
            key: None,
        }
    }
    
    /// Set server certificate
    pub fn with_cert(mut self, cert: Vec<u8>) -> Self {
        self.cert = Some(cert);
        self
    }
    
    /// Set server private key
    pub fn with_key(mut self, key: Vec<u8>) -> Self {
        self.key = Some(key);
        self
    }
    
    /// Bind to address with error handler
    pub fn on_result<F, T>(self, handler: F) -> QuicServerWithHandler<F>
    where
        F: FnOnce(Result<QuicServer, crate::error::CryptoTransportError>) -> T,
        T: NotResult,
    {
        QuicServerWithHandler {
            builder: self,
            handler,
        }
    }
}

/// Server builder with error handler
pub struct QuicServerWithHandler<F> {
    builder: QuicServerBuilder,
    handler: F,
}

impl<F, T> QuicServerWithHandler<F>
where
    F: FnOnce(Result<QuicServer, crate::error::CryptoTransportError>) -> T,
    T: NotResult,
{
    /// Bind server to address
    pub async fn bind(self, addr: impl Into<String>) -> T {
        let addr_str = addr.into();
        
        // Parse address
        let socket_addr = match addr_str.parse::<SocketAddr>() {
            Ok(addr) => addr,
            Err(e) => {
                let result = Err(crate::error::CryptoTransportError::Internal(
                    format!("Invalid address {}: {}", addr_str, e)
                ));
                return (self.handler)(result);
            }
        };
        
        // Create server config
        let mut config = crate::builder::QuicCryptoConfig::new();
        
        // Set certificate and key if provided
        if let Some(cert) = self.builder.cert {
            config.set_cert_chain(cert);
        }
        if let Some(key) = self.builder.key {
            config.set_private_key(key);
        }
        
        // Create server config
        let server_config = crate::server::QuicServerConfig {
            listen_addr: addr_str.clone(),
            crypto: Arc::new(config),
        };
        
        // Start the server in background
        let server_future = crate::server::run_quic_server(server_config);
        let handle = tokio::spawn(server_future);
        
        // Server is immediately bound (async bind happens in background)
        let result = Ok(QuicServer {
            addr: socket_addr,
            bound: true,
            _handle: Some(handle),
        });
        
        (self.handler)(result)
    }
}

/// QUIC server instance
pub struct QuicServer {
    addr: SocketAddr,
    bound: bool,
    _handle: Option<tokio::task::JoinHandle<Result<(), crate::error::CryptoTransportError>>>,
}

impl QuicServer {
    /// Create unbound server (for error cases)
    pub fn new() -> Self {
        Self {
            addr: "0.0.0.0:0".parse().unwrap(),
            bound: false,
            _handle: None,
        }
    }
    
    /// Get the server's bound address
    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }
    
    /// Check if the server is bound
    pub fn is_bound(&self) -> bool {
        self.bound
    }
}

/// QUIC client builder
pub struct QuicClientBuilder {
    server_name: Option<String>,
}

impl QuicClientBuilder {
    pub(crate) fn new() -> Self {
        Self {
            server_name: None,
        }
    }
    
    /// Set server name for TLS
    pub fn with_server_name(mut self, name: impl Into<String>) -> Self {
        self.server_name = Some(name.into());
        self
    }
    
    /// Connect with error handler
    pub fn on_result<F, T>(self, handler: F) -> QuicClientWithHandler<F>
    where
        F: FnOnce(Result<QuicClient, crate::error::CryptoTransportError>) -> T,
        T: NotResult,
    {
        QuicClientWithHandler {
            builder: self,
            handler,
        }
    }
}

/// Client builder with error handler  
pub struct QuicClientWithHandler<F> {
    #[allow(dead_code)]
    builder: QuicClientBuilder,
    handler: F,
}

impl<F, T> QuicClientWithHandler<F>
where
    F: FnOnce(Result<QuicClient, crate::error::CryptoTransportError>) -> T,
    T: NotResult,
{
    /// Connect to server
    pub async fn connect(self, addr: impl Into<String>) -> T {
        let addr_str = addr.into();
        
        // Parse address
        let socket_addr = match addr_str.parse::<SocketAddr>() {
            Ok(addr) => addr,
            Err(e) => {
                let result = Err(crate::error::CryptoTransportError::Internal(
                    format!("Invalid address {}: {}", addr_str, e)
                ));
                return (self.handler)(result);
            }
        };
        
        // Create client config
        let config = Arc::new(crate::builder::QuicCryptoConfig::new());
        
        // Connect to server
        let result = match crate::client::connect_quic_client(
            "0.0.0.0:0", // Let OS choose port
            &addr_str,
            config
        ).await {
            Ok(handle) => Ok(QuicClient {
                addr: socket_addr,
                connected: true,
                handle: Some(handle),
            }),
            Err(e) => Err(e),
        };
        
        (self.handler)(result)
    }
}

/// QUIC client instance
pub struct QuicClient {
    addr: SocketAddr,
    connected: bool,
    handle: Option<crate::quic_conn::QuicConnectionHandle>,
}

impl QuicClient {
    /// Create unconnected client (for error cases)
    pub fn new() -> Self {
        Self {
            addr: "0.0.0.0:0".parse().unwrap(),
            connected: false,
            handle: None,
        }
    }
    
    /// Get the client's remote address
    pub fn addr(&self) -> &SocketAddr {
        &self.addr
    }
    
    /// Check if the client is connected
    pub fn is_connected(&self) -> bool {
        self.connected
    }
    
    /// Open bidirectional stream with error handler
    pub fn on_result<F, T>(self, handler: F) -> QuicClientStreamHandler<F>
    where
        F: FnOnce(Result<(QuicSend, QuicRecv), crate::error::CryptoTransportError>) -> T,
        T: NotResult,
    {
        QuicClientStreamHandler {
            client: self,
            handler,
        }
    }
}

/// Client with stream handler
pub struct QuicClientStreamHandler<F> {
    client: QuicClient,
    handler: F,
}

impl<F, T> QuicClientStreamHandler<F>
where
    F: FnOnce(Result<(QuicSend, QuicRecv), crate::error::CryptoTransportError>) -> T,
    T: NotResult,
{
    /// Open bidirectional stream
    pub async fn open_bi(self) -> T {
        if let Some(ref handle) = self.client.handle {
            // Wait for handshake to complete
            if let Err(e) = handle.wait_for_handshake().await {
                let result = Err(e);
                return (self.handler)(result);
            }
            
            // Create send/recv pair
            let result = Ok((QuicSend::new_with_handle(handle.clone()), QuicRecv::new()));
            (self.handler)(result)
        } else {
            let result = Err(crate::error::CryptoTransportError::Internal(
                "Client not connected".to_string()
            ));
            (self.handler)(result)
        }
    }
}

/// QUIC send stream
pub struct QuicSend {
    handle: Option<crate::quic_conn::QuicConnectionHandle>,
}

impl QuicSend {
    fn new_with_handle(handle: crate::quic_conn::QuicConnectionHandle) -> Self {
        Self {
            handle: Some(handle),
        }
    }
    
    /// Create empty send stream (for error cases)
    pub fn new() -> Self {
        Self { handle: None }
    }
    
    /// Write data with error handler
    pub fn on_result<F, T>(self, handler: F) -> QuicSendWithHandler<F>
    where
        F: FnOnce(Result<(), crate::error::CryptoTransportError>) -> T,
        T: NotResult,
    {
        QuicSendWithHandler {
            send: self,
            handler,
        }
    }
}

/// Send stream with handler
pub struct QuicSendWithHandler<F> {
    send: QuicSend,
    handler: F,
}

impl<F, T> QuicSendWithHandler<F>
where
    F: FnOnce(Result<(), crate::error::CryptoTransportError>) -> T,
    T: NotResult,
{
    /// Write all data
    pub async fn write_all(self, data: &[u8]) -> T {
        let result = if let Some(ref handle) = self.send.handle {
            handle.send_stream_data(data, true)
        } else {
            Err(crate::error::CryptoTransportError::Internal(
                "Send stream not initialized".to_string()
            ))
        };
        (self.handler)(result)
    }
}

/// QUIC receive stream
pub struct QuicRecv {
    receiver: Option<mpsc::UnboundedReceiver<Vec<u8>>>,
}

impl QuicRecv {
    pub fn new() -> Self {
        // For now, create a dummy receiver - in real implementation
        // this would be connected to the QUIC connection's event stream
        let (_tx, rx) = mpsc::unbounded_channel();
        Self {
            receiver: Some(rx),
        }
    }
    
    /// Create empty recv stream (for error cases)
    pub fn empty() -> Self {
        Self { receiver: None }
    }
    
    /// Set chunk handler for streaming
    pub fn on_chunk<F>(self, handler: F) -> QuicRecvStream<F>
    where
        F: Fn(Result<Vec<u8>, crate::error::CryptoTransportError>) -> Option<Vec<u8>> + Send + 'static,
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
    F: Fn(Result<Vec<u8>, crate::error::CryptoTransportError>) -> Option<Vec<u8>> + Send + 'static,
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
            F: Fn(Result<Vec<u8>, crate::error::CryptoTransportError>) -> Option<Vec<u8>> + Send + 'static,
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