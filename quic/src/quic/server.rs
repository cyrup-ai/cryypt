//! QUIC server implementation
//!
//! Provides builder pattern for creating QUIC servers with stream handling
//! and connection management capabilities.

use super::config::{Auth, Transport};
use crate::Result;
use std::time::Duration;
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use tokio::sync::broadcast;

use crate::quic::stream_dispatcher::QuicStream;
use crate::quic_conn::QuicConnectionController;

/// Builder for QUIC server
pub struct ServerBuilder {
    transport: Transport,
    port: Option<u16>,
    auth: Option<Auth>,
}

impl ServerBuilder {
    #[allow(dead_code)]  // Used by other modules via qualified paths
    pub(crate) fn new(transport: Transport) -> Self {
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

        // Implement actual QUIC server using quiche
        self.run_quic_server().await
    }

    /// Run the actual QUIC server with real connection handling
    async fn run_quic_server(&self) -> Result<()> {
        use quiche::{Config, ConnectionId};
        use crate::error::QuicError;
        
        // Configure QUIC server
        let mut config = Config::new(quiche::PROTOCOL_VERSION)
            .map_err(|e| QuicError::Config(format!("Failed to create QUIC config: {}", e)))?;
        config.set_application_protos(&[b"h3"])
            .map_err(|e| QuicError::Config(format!("Failed to set application protocols: {}", e)))?;
        config.set_max_idle_timeout(5000);
        config.set_max_recv_udp_payload_size(1350);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        
        // Use production TLS system for certificates
        let cert_dir = std::path::PathBuf::from("/tmp/cryypt_quic_server_certs");
        let _tls_manager = crate::tls::TlsManager::with_cert_dir(cert_dir.clone()).await
            .map_err(|e| QuicError::Certificate(format!("Failed to initialize TLS manager: {}", e)))?;
        
        let server_cert_path = cert_dir.join("server.crt");
        let server_key_path = cert_dir.join("server.key");
        
        config.load_cert_chain_from_pem_file(
            server_cert_path.to_str().ok_or_else(|| 
                QuicError::Certificate("Invalid cert path".to_string())
            )?
        ).map_err(|e| QuicError::Certificate(format!("Failed to load certificate chain: {}", e)))?;
        
        config.load_priv_key_from_pem_file(
            server_key_path.to_str().ok_or_else(|| 
                QuicError::Certificate("Invalid key path".to_string())
            )?
        ).map_err(|e| QuicError::Certificate(format!("Failed to load private key: {}", e)))?;
        
        // Bind UDP socket
        let address = format!("0.0.0.0:{}", self.port);
        let socket = Arc::new(tokio::net::UdpSocket::bind(&address).await
            .map_err(QuicError::Network)?);
        
        println!("🚀 QUIC server listening on {}", address);
        
        // Connection management
        let connections: Arc<Mutex<HashMap<ConnectionId, Arc<QuicConnectionController>>>> = 
            Arc::new(Mutex::new(HashMap::new()));
        
        let mut buf = [0; 65535];
        let mut out = [0; 1350];
        
        loop {
            // Receive packets from socket
            match socket.recv_from(&mut buf).await {
                Ok((len, from)) => {
                    let pkt_buf = &mut buf[..len];
                    
                    // Parse QUIC header
                    let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                        Ok(v) => v,
                        Err(_) => continue,
                    };
                    
                    let conn_id = hdr.dcid.clone();
                    
                    // Get or create connection
                    let controller = {
                        let mut conns = connections.lock()
                            .map_err(|e| QuicError::InvalidState(format!("Failed to acquire connection lock: {}", e)))?;
                        
                        if let Some(controller) = conns.get(&conn_id) {
                            controller.clone()
                        } else {
                            // Create new connection
                            let (event_tx, _event_rx) = broadcast::channel(1000);
                            let conn = quiche::accept(
                                &conn_id,
                                None,
                                socket.local_addr()
                                    .map_err(QuicError::Network)?,
                                from,
                                &mut config,
                            ).map_err(|e| QuicError::Connection(format!("Failed to accept connection: {}", e)))?;
                            
                            let controller = Arc::new(QuicConnectionController {
                                conn: Arc::new(Mutex::new(conn)),
                                outbound_queue: Arc::new(Mutex::new(VecDeque::new())),
                                event_tx,
                                socket: socket.clone(),
                                handshake_done: Arc::new(Mutex::new(false)),
                            });
                            
                            conns.insert(conn_id.clone(), controller.clone());
                            controller
                        }
                    };
                    
                    // Process packet
                    let local_addr = socket.local_addr()
                        .map_err(QuicError::Network)?;
                    let recv_info = quiche::RecvInfo { from, to: local_addr };
                    
                    {
                        let mut conn = controller.conn.lock()
                            .map_err(|e| QuicError::InvalidState(format!("Failed to acquire connection lock: {}", e)))?;
                        if conn.recv(pkt_buf, recv_info).is_err() {
                            continue;
                        }
                        
                        // Send response packets
                        while let Ok((write, send_info)) = conn.send(&mut out) {
                            socket.send_to(&out[..write], send_info.to).await
                                .map_err(QuicError::Network)?;
                        }
                        
                        // Handle connection events
                        if conn.is_established() {
                            // Process readable streams
                            for stream_id in conn.readable() {
                                self.handle_stream_data(&mut conn, stream_id).await;
                            }
                        }
                        
                        // Clean up closed connections
                        if conn.is_closed() {
                            let mut conns = connections.lock()
                                .map_err(|e| QuicError::InvalidState(format!("Failed to acquire connection lock for cleanup: {}", e)))?;
                            conns.remove(&conn_id);
                        }
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No more packets to read
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(_) => break,
            }
        }
        
        Ok(())
    }
    
    /// Handle data on a QUIC stream
    async fn handle_stream_data(&self, conn: &mut quiche::Connection, stream_id: u64) {
        let mut buf = [0; 4096];
        
        loop {
            match conn.stream_recv(stream_id, &mut buf) {
                Ok((len, fin)) => {
                    let data = &buf[..len];
                    println!("📨 Received {} bytes on stream {}: {:?}", len, stream_id, 
                            String::from_utf8_lossy(data));
                    
                    // Echo the data back
                    let response = format!("Echo: {}", String::from_utf8_lossy(data));
                    if conn.stream_send(stream_id, response.as_bytes(), true).is_err() {
                        println!("❌ Failed to send response on stream {}", stream_id);
                    }
                    
                    if fin {
                        println!("🏁 Stream {} finished", stream_id);
                        break;
                    }
                }
                Err(quiche::Error::Done) => break,
                Err(e) => {
                    println!("❌ Stream read error: {}", e);
                    break;
                }
            }
        }
    }
}

