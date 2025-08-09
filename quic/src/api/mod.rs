//! QUIC API following cryypt patterns exactly

use cryypt_common::NotResult;
use futures::Stream;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::oneshot;

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

/// QUIC master builder for dual API entry points
pub struct QuicMasterBuilder;

impl QuicMasterBuilder {
    /// Create a QUIC server builder
    pub fn server(self) -> QuicServerBuilder {
        QuicServerBuilder::new()
    }

    /// Create a QUIC client builder
    pub fn client(self) -> QuicClientBuilder {
        QuicClientBuilder::new()
    }
}

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

impl QuicServerBuilder {
    pub fn new() -> Self {
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
    pub fn with_key(self, key: Vec<u8>) -> QuicServerWithConfig {
        QuicServerWithConfig {
            cert: self.cert.unwrap_or_default(),
            key,
        }
    }
}

impl QuicServerWithConfig {
    /// Set server certificate after key
    pub fn with_cert(mut self, cert: Vec<u8>) -> Self {
        self.cert = cert;
        self
    }

    /// Add on_result handler - README.md pattern
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
    pub fn bind<A: Into<String>>(self, addr: A) -> crate::QuicResult {
        use tokio::sync::oneshot;

        let addr_str = addr.into();
        let cert = self.cert;
        let key = self.key;

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = bind_quic_server(&cert, &key, &addr_str).await;
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
    pub async fn bind<A: Into<String>>(self, addr: A) -> T {
        let addr_str = addr.into();
        let cert = self.cert;
        let key = self.key;
        let handler = self.result_handler;

        // Perform QUIC server binding
        let result = bind_quic_server(&cert, &key, &addr_str).await;

        // Apply result handler
        handler(result)
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

impl QuicClientBuilder {
    pub fn new() -> Self {
        Self { server_name: None }
    }

    /// Set server name for TLS
    pub fn with_server_name(self, name: impl Into<String>) -> QuicClientWithConfig {
        QuicClientWithConfig {
            server_name: name.into(),
        }
    }
}

impl QuicClientWithConfig {
    /// Add on_result handler - README.md pattern
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
    pub fn open_bi(self) -> crate::QuicStreamResult {
        let handle = self.handle.clone();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = open_bi_stream_internal(handle).await;
            let _ = tx.send(result);
        });

        crate::QuicStreamResult::new(rx)
    }
}

/// Client with stream handler following cipher pattern
pub struct QuicClientWithHandler<F, T> {
    client: QuicClient,
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

impl<F, T> QuicClientWithHandler<F, T>
where
    F: FnOnce(crate::Result<(QuicSend, QuicRecv)>) -> T + Send + 'static,
    T: NotResult + Send + 'static,
{
    /// Open bidirectional stream - action per README.md
    pub async fn open_bi(self) -> T {
        let handle = self.client.handle.clone();
        let handler = self.result_handler;

        // Perform QUIC stream opening
        let result = open_bi_stream_internal(handle).await;

        // Apply result handler
        handler(result)
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

    /// Write data with error handler - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> QuicSendWithHandler<F, T>
    where
        F: FnOnce(crate::Result<()>) -> T + Send + 'static,
        T: NotResult + Send + 'static,
    {
        QuicSendWithHandler {
            send: self,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Write data without handler - returns future
    pub fn write_all(self, data: &[u8]) -> crate::QuicWriteResult {
        let handle = self.handle.clone();
        let data = data.to_vec();

        let (tx, rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = write_all_internal(handle, &data).await;
            let _ = tx.send(result);
        });

        crate::QuicWriteResult::new(rx)
    }
}

/// Send stream with handler following cipher pattern
pub struct QuicSendWithHandler<F, T> {
    send: QuicSend,
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

impl<F, T> QuicSendWithHandler<F, T>
where
    F: FnOnce(crate::Result<()>) -> T + Send + 'static,
    T: NotResult + Send + 'static,
{
    /// Write all data - action takes data as argument per README.md
    pub async fn write_all(self, data: &[u8]) -> T {
        let handle = self.send.handle.clone();
        let data = data.to_vec();
        let handler = self.result_handler;

        // Perform QUIC write operation
        let result = write_all_internal(handle, &data).await;

        // Apply result handler
        handler(result)
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
        Self { receiver: Some(rx) }
    }

    /// Create empty recv stream (for error cases)
    pub fn empty() -> Self {
        Self { receiver: None }
    }

    /// Set chunk handler for streaming - README.md pattern
    pub fn on_chunk<F>(self, handler: F) -> QuicRecvStream<F>
    where
        F: Fn(crate::Result<Vec<u8>>) -> Option<Vec<u8>> + Send + 'static,
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
    F: Fn(crate::Result<Vec<u8>>) -> Option<Vec<u8>> + Send + 'static,
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
            F: Fn(crate::Result<Vec<u8>>) -> Option<Vec<u8>> + Send + 'static,
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

// Internal helper functions following cipher pattern
async fn bind_quic_server(cert: &[u8], key: &[u8], addr: &str) -> crate::Result<QuicServer> {
    // Parse address
    let socket_addr = addr.parse::<SocketAddr>().map_err(|e| {
        crate::error::CryptoTransportError::Internal(format!("Invalid address {}: {}", addr, e))
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

async fn connect_quic_client_internal(_server_name: &str, addr: &str) -> crate::Result<QuicClient> {
    // Parse address
    let socket_addr = addr.parse::<SocketAddr>().map_err(|e| {
        crate::error::CryptoTransportError::Internal(format!("Invalid address {}: {}", addr, e))
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

async fn open_bi_stream_internal(
    handle: Option<crate::quic_conn::QuicConnectionHandle>,
) -> crate::Result<(QuicSend, QuicRecv)> {
    if let Some(ref handle) = handle {
        // Wait for handshake to complete
        handle.wait_for_handshake().await?;

        // Create send/recv pair
        Ok((QuicSend::new_with_handle(handle.clone()), QuicRecv::new()))
    } else {
        Err(crate::error::CryptoTransportError::Internal(
            "Client not connected".to_string(),
        ))
    }
}

async fn write_all_internal(
    handle: Option<crate::quic_conn::QuicConnectionHandle>,
    data: &[u8],
) -> crate::Result<()> {
    if let Some(ref handle) = handle {
        handle.send_stream_data(data, true)
    } else {
        Err(crate::error::CryptoTransportError::Internal(
            "Send stream not initialized".to_string(),
        ))
    }
}
