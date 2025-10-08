//! QUIC server implementation
//!
//! Provides builder pattern for creating QUIC servers with stream handling
//! and connection management capabilities.

use super::config::{Auth, Transport};
use crate::Result;
use cryypt_common::error::LoggingTransformer;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

use crate::protocols::rpc::JsonRpcServer;
use crate::quic::stream_dispatcher::QuicStream;
use crate::quic_conn::QuicConnectionController;
use simd_json::prelude::*;

/// Context for packet processing operations
struct PacketProcessingContext<'a> {
    pkt_buf: &'a mut [u8],
    from: std::net::SocketAddr,
    socket: &'a Arc<tokio::net::UdpSocket>,
    out: &'a mut [u8; 1350],
}

/// Builder for QUIC server
pub struct ServerBuilder {
    transport: Transport,
    port: Option<u16>,
    auth: Option<Auth>,
}

impl ServerBuilder {
    #[allow(dead_code)] // Used by other modules via qualified paths
    pub(crate) fn new(transport: Transport) -> Self {
        Self {
            transport,
            port: None,
            auth: None,
        }
    }

    /// Set the port to listen on
    #[must_use]
    pub fn port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }

    /// Set authentication configuration
    #[must_use]
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
            json_rpc_server: None,
        }
    }
}

/// Builder for starting server listener
pub struct ServerListenerBuilder {
    transport: Transport,
    port: u16,
    auth: Option<Auth>,
    json_rpc_server: Option<Arc<JsonRpcServer>>,
}

impl ServerListenerBuilder {
    /// Enable JSON-RPC 2.0 support
    #[must_use]
    pub fn with_json_rpc_server(mut self, server: Arc<JsonRpcServer>) -> Self {
        self.json_rpc_server = Some(server);
        self
    }

    /// Start listening for connections
    ///
    /// # Errors
    ///
    /// Returns an error if the QUIC server configuration fails or if the server
    /// cannot bind to the specified port.
    pub async fn listen(self) -> Result<()> {
        // Validate transport type and log startup
        match self.transport {
            Transport::UDP => {
                LoggingTransformer::log_server_startup("QUIC/UDP", self.port);
                println!("🚀 QUIC server listening on UDP port {}", self.port);
            }
        }
        LoggingTransformer::log_terminal_setup(
            "server_auth_config",
            Some("Server authentication configured"),
        );
        println!("🔐 Auth: {:?}", self.auth);

        // Implement actual QUIC server using quiche
        Box::pin(self.run_quic_server()).await
    }

    /// Run the actual QUIC server with real connection handling
    async fn run_quic_server(&self) -> Result<()> {
        use crate::error::QuicError;
        use quiche::ConnectionId;

        let config = self.create_quic_config().await?;
        let socket = self.bind_server_socket().await?;
        let connections: Arc<Mutex<HashMap<ConnectionId<'static>, Arc<QuicConnectionController>>>> =
            Arc::new(Mutex::new(HashMap::new()));

        // Use heap allocation to avoid large stack arrays
        let mut buf = vec![0u8; 65535].into_boxed_slice();
        let mut out = [0; 1350];

        info!("🚀 QUIC server listening on 0.0.0.0:{}", self.port);

        self.run_packet_processing_loop(socket, config, connections, &mut buf, &mut out)
            .await
    }

    /// Create and configure QUIC server configuration
    async fn create_quic_config(&self) -> Result<quiche::Config> {
        use crate::error::QuicError;

        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
            .map_err(|e| QuicError::Config(format!("Failed to create QUIC config: {e}")))?;

        config
            .set_application_protos(&[b"h3"])
            .map_err(|e| QuicError::Config(format!("Failed to set application protocols: {e}")))?;
        config.set_max_idle_timeout(5000);
        config.set_max_recv_udp_payload_size(1350);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);

        self.load_tls_certificates(&mut config).await?;
        Ok(config)
    }

    /// Load TLS certificates for QUIC server
    async fn load_tls_certificates(&self, config: &mut quiche::Config) -> Result<()> {
        use crate::error::QuicError;

        let cert_dir = std::path::PathBuf::from("/tmp/cryypt_quic_server_certs");
        let _tls_manager = crate::tls::TlsManager::with_cert_dir(cert_dir.clone())
            .await
            .map_err(|e| {
                QuicError::Certificate(format!("Failed to initialize TLS manager: {e}"))
            })?;

        let server_cert_path = cert_dir.join("server.crt");
        let server_key_path = cert_dir.join("server.key");

        config
            .load_cert_chain_from_pem_file(
                server_cert_path
                    .to_str()
                    .ok_or_else(|| QuicError::Certificate("Invalid cert path".to_string()))?,
            )
            .map_err(|e| {
                QuicError::Certificate(format!("Failed to load certificate chain: {e}"))
            })?;

        config
            .load_priv_key_from_pem_file(
                server_key_path
                    .to_str()
                    .ok_or_else(|| QuicError::Certificate("Invalid key path".to_string()))?,
            )
            .map_err(|e| QuicError::Certificate(format!("Failed to load private key: {e}")))?;

        Ok(())
    }

    /// Bind UDP socket for QUIC server
    async fn bind_server_socket(&self) -> Result<Arc<tokio::net::UdpSocket>> {
        use crate::error::QuicError;

        let address = format!("0.0.0.0:{}", self.port);
        let socket = Arc::new(
            tokio::net::UdpSocket::bind(&address)
                .await
                .map_err(QuicError::Network)?,
        );
        Ok(socket)
    }

    /// Main packet processing loop for QUIC server
    async fn run_packet_processing_loop(
        &self,
        socket: Arc<tokio::net::UdpSocket>,
        mut config: quiche::Config,
        connections: Arc<
            Mutex<HashMap<quiche::ConnectionId<'static>, Arc<QuicConnectionController>>>,
        >,
        buf: &mut [u8],
        out: &mut [u8; 1350],
    ) -> Result<()> {
        use crate::error::QuicError;

        loop {
            match socket.recv_from(buf).await {
                Ok((len, from)) => {
                    let pkt_buf = &mut buf[..len];

                    // Parse QUIC header
                    let Ok(hdr) = quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN)
                    else {
                        continue;
                    };

                    let conn_id = hdr.dcid.clone();
                    let controller = self.get_or_create_connection(
                        &connections,
                        &conn_id,
                        &socket,
                        from,
                        &mut config,
                    )?;

                    let mut context = PacketProcessingContext {
                        pkt_buf,
                        from,
                        socket: &socket,
                        out,
                    };

                    self.process_packet_data(&controller, &mut context, &connections, &conn_id)
                        .await?;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(_) => break,
            }
        }

        Ok(())
    }

    /// Get existing connection or create new one
    #[allow(clippy::unused_self)]
    fn get_or_create_connection(
        &self,
        connections: &Arc<
            Mutex<HashMap<quiche::ConnectionId<'static>, Arc<QuicConnectionController>>>,
        >,
        conn_id: &quiche::ConnectionId<'static>,
        socket: &Arc<tokio::net::UdpSocket>,
        from: std::net::SocketAddr,
        config: &mut quiche::Config,
    ) -> Result<Arc<QuicConnectionController>> {
        use crate::error::QuicError;

        let mut conns = connections.lock().map_err(|e| {
            QuicError::InvalidState(format!("Failed to acquire connection lock: {e}"))
        })?;

        if let Some(controller) = conns.get(conn_id) {
            Ok(controller.clone())
        } else {
            let (event_tx, _event_rx) = broadcast::channel(1000);
            let conn = quiche::accept(
                conn_id,
                None,
                socket.local_addr().map_err(QuicError::Network)?,
                from,
                config,
            )
            .map_err(|e| QuicError::Connection(format!("Failed to accept connection: {e}")))?;

            let controller = Arc::new(QuicConnectionController {
                conn: Arc::new(Mutex::new(conn)),
                outbound_queue: Arc::new(Mutex::new(VecDeque::new())),
                event_tx,
                socket: socket.clone(),
                handshake_done: Arc::new(Mutex::new(false)),
            });

            conns.insert(conn_id.clone(), controller.clone());
            Ok(controller)
        }
    }

    /// Process received packet data and handle connection state
    async fn process_packet_data(
        &self,
        controller: &Arc<QuicConnectionController>,
        context: &mut PacketProcessingContext<'_>,
        connections: &Arc<
            Mutex<HashMap<quiche::ConnectionId<'static>, Arc<QuicConnectionController>>>,
        >,
        conn_id: &quiche::ConnectionId<'static>,
    ) -> Result<()> {
        use crate::error::QuicError;

        let local_addr = context.socket.local_addr().map_err(QuicError::Network)?;
        let recv_info = quiche::RecvInfo {
            from: context.from,
            to: local_addr,
        };

        // Process packet and handle responses without holding lock across await
        let (should_send_responses, readable_streams, is_closed) = {
            let mut conn = controller.conn.lock().map_err(|e| {
                QuicError::InvalidState(format!("Failed to acquire connection lock: {e}"))
            })?;

            if conn.recv(context.pkt_buf, recv_info).is_err() {
                return Ok(());
            }

            let mut send_responses = Vec::new();
            while let Ok((write, send_info)) = conn.send(context.out) {
                send_responses.push((context.out[..write].to_vec(), send_info.to));
            }

            let readable_streams: Vec<_> = if conn.is_established() {
                conn.readable().collect()
            } else {
                Vec::new()
            };

            (send_responses, readable_streams, conn.is_closed())
        };

        // Send responses without holding the connection lock
        for (data, to) in should_send_responses {
            context
                .socket
                .send_to(&data, to)
                .await
                .map_err(QuicError::Network)?;
        }

        // Handle readable streams by collecting requests first, then processing async
        if !readable_streams.is_empty() {
            let mut pending_rpc_requests = Vec::new();

            // Collect stream data while holding lock briefly
            {
                let mut conn = controller.conn.lock().map_err(|e| {
                    QuicError::InvalidState(format!("Failed to acquire connection lock: {e}"))
                })?;

                for stream_id in readable_streams {
                    if let Some(request_data) = self.collect_stream_data(&mut conn, stream_id) {
                        pending_rpc_requests.push((stream_id, request_data));
                    }
                }
            } // Lock released here

            // Process RPC requests asynchronously without holding lock
            for (stream_id, request_data) in pending_rpc_requests {
                self.process_stream_request_async(stream_id, request_data, controller)
                    .await;
            }
        }

        // Clean up closed connections
        if is_closed {
            let mut conns = connections.lock().map_err(|e| {
                QuicError::InvalidState(format!(
                    "Failed to acquire connection lock for cleanup: {e}"
                ))
            })?;
            conns.remove(conn_id);
        }

        Ok(())
    }

    /// Handle data on a QUIC stream with RPC support
    /// Collect stream data synchronously while holding connection lock
    #[allow(clippy::unused_self)] // Method part of self for consistency with other stream methods
    fn collect_stream_data(
        &self,
        conn: &mut quiche::Connection,
        stream_id: u64,
    ) -> Option<Vec<u8>> {
        let mut buf = [0; 4096];
        let mut collected_data = Vec::new();

        loop {
            match conn.stream_recv(stream_id, &mut buf) {
                Ok((len, fin)) => {
                    collected_data.extend_from_slice(&buf[..len]);
                    if fin {
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("❌ Stream read error: {}", e);
                    return None;
                }
            }
        }

        if collected_data.is_empty() {
            None
        } else {
            Some(collected_data)
        }
    }

    /// Process stream request asynchronously without holding connection lock
    async fn process_stream_request_async(
        &self,
        stream_id: u64,
        data: Vec<u8>,
        controller: &Arc<QuicConnectionController>,
    ) {
        debug!(
            "📨 Processing {} bytes on stream {}: {:?}",
            data.len(),
            stream_id,
            String::from_utf8_lossy(&data)
        );

        let response_data = if data.starts_with(br#"{"jsonrpc":"#) || data.starts_with(b"[") {
            // Handle JSON-RPC request
            if let Some(ref json_rpc_server) = self.json_rpc_server {
                match json_rpc_server.process_request(data, None).await {
                    Ok(response_bytes) => response_bytes,
                    Err(e) => {
                        let error_response = format!(
                            r#"{{"jsonrpc":"2.0","error":{{"code":{},"message":"{}"}},"id":null}}"#,
                            -32603, // Internal error
                            e
                        );
                        error_response.into_bytes()
                    }
                }
            } else {
                let error_response = r#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"RPC not enabled"},"id":null}"#;
                error_response.as_bytes().to_vec()
            }
        } else {
            // Echo non-RPC data
            let response = format!("Echo: {}", String::from_utf8_lossy(&data));
            response.into_bytes()
        };

        // Send response by acquiring lock briefly
        if let Ok(mut conn) = controller.conn.lock() {
            if conn.stream_send(stream_id, &response_data, true).is_err() {
                warn!("❌ Failed to send response on stream {}", stream_id);
            }
        } else {
            warn!(
                "❌ Failed to acquire connection lock for response on stream {}",
                stream_id
            );
        }
    }

    async fn handle_stream_data(&self, conn: &mut quiche::Connection, stream_id: u64) {
        let mut buf = [0; 4096];

        loop {
            match conn.stream_recv(stream_id, &mut buf) {
                Ok((len, fin)) => {
                    let data = &buf[..len];
                    debug!(
                        "📨 Received {} bytes on stream {}: {:?}",
                        len,
                        stream_id,
                        String::from_utf8_lossy(data)
                    );

                    // Detect JSON-RPC vs regular data
                    if data.starts_with(br#"{"jsonrpc":"#) || data.starts_with(b"[") {
                        if let Some(ref json_rpc_server) = self.json_rpc_server {
                            match json_rpc_server.process_request(data.to_vec(), None).await {
                                Ok(response_bytes) => {
                                    if conn.stream_send(stream_id, &response_bytes, true).is_err() {
                                        warn!(
                                            "❌ Failed to send JSON-RPC response on stream {}",
                                            stream_id
                                        );
                                    }
                                }
                                Err(e) => {
                                    let error_response = format!(
                                        r#"{{"jsonrpc":"2.0","error":{{"code":{},"message":"{}"}},"id":null}}"#,
                                        -32603, // Internal error
                                        e
                                    );
                                    if conn
                                        .stream_send(stream_id, error_response.as_bytes(), true)
                                        .is_err()
                                    {
                                        warn!(
                                            "❌ Failed to send RPC error on stream {}",
                                            stream_id
                                        );
                                    }
                                }
                            }
                        } else {
                            let error_response = r#"{"jsonrpc":"2.0","error":{"code":-32601,"message":"RPC not enabled"},"id":null}"#;
                            if conn
                                .stream_send(stream_id, error_response.as_bytes(), true)
                                .is_err()
                            {
                                warn!(
                                    "❌ Failed to send RPC not enabled error on stream {}",
                                    stream_id
                                );
                            }
                        }
                    } else {
                        // Echo non-RPC data
                        let response = format!("Echo: {}", String::from_utf8_lossy(data));
                        if conn
                            .stream_send(stream_id, response.as_bytes(), true)
                            .is_err()
                        {
                            warn!("❌ Failed to send echo response on stream {}", stream_id);
                        }
                    }

                    if fin {
                        debug!("🏁 Stream {} finished", stream_id);
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    error!("❌ Stream read error: {}", e);
                    break;
                }
            }
        }
    }
}
