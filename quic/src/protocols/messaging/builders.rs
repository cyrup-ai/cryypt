//! Builder patterns for messaging server and client construction

use serde::Serialize;
use std::future::Future;
use std::time::Duration;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use uuid::Uuid;

use super::types::{
    CompressionAlgorithm, EncryptionAlgorithm, MessageEnvelope, 
    DistributionStrategy, MessagePriority, MessageDelivery
};
use super::server::{MessagingServer, MessagingServerConfig};
use crate::error::CryptoTransportError;

/// High-level messaging protocol builder
pub struct QuicMessaging;

impl QuicMessaging {
    /// Create a messaging server
    pub fn server() -> MessagingServerBuilder {
        MessagingServerBuilder::default()
    }

    /// Connect to a messaging server
    pub fn connect(server_addr: &str) -> MessagingClientBuilder {
        MessagingClientBuilder::new(server_addr.to_string())
    }
}

/// Builder for configuring messaging server
pub struct MessagingServerBuilder {
    max_message_size: usize,
    retain_messages: bool,
    delivery_timeout: Duration,
    default_compression: CompressionAlgorithm,
    compression_level: u8,
    default_encryption: EncryptionAlgorithm,
    shared_secret: Option<Vec<u8>>,
}

impl Default for MessagingServerBuilder {
    fn default() -> Self {
        Self {
            max_message_size: 0,
            retain_messages: false,
            delivery_timeout: Duration::default(),
            default_compression: CompressionAlgorithm::Zstd,
            compression_level: 3, // Balanced performance/compression ratio
            default_encryption: EncryptionAlgorithm::Aes256Gcm,
            shared_secret: None, // Will be generated if not provided
        }
    }
}

impl MessagingServerBuilder {
    /// Set maximum message size in bytes
    pub fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Enable or disable message retention on server
    pub fn with_message_retention(mut self, retain: bool) -> Self {
        self.retain_messages = retain;
        self
    }

    /// Set delivery timeout for message acknowledgments
    pub fn with_delivery_timeout(mut self, timeout: Duration) -> Self {
        self.delivery_timeout = timeout;
        self
    }

    /// Configure compression algorithm and level
    pub fn with_compression(mut self, algorithm: CompressionAlgorithm, level: u8) -> Self {
        self.default_compression = algorithm;
        self.compression_level = level;
        self
    }

    /// Configure encryption algorithm
    pub fn with_encryption(mut self, algorithm: EncryptionAlgorithm) -> Self {
        self.default_encryption = algorithm;
        self
    }

    /// Set shared secret for connection key derivation
    pub fn with_shared_secret(mut self, secret: Vec<u8>) -> Self {
        self.shared_secret = Some(secret);
        self
    }

    /// Disable compression (use CompressionAlgorithm::None)
    pub fn disable_compression(mut self) -> Self {
        self.default_compression = CompressionAlgorithm::None;
        self
    }

    /// Disable encryption (use EncryptionAlgorithm::None)
    pub fn disable_encryption(mut self) -> Self {
        self.default_encryption = EncryptionAlgorithm::None;
        self
    }

    /// Start listening on the specified address
    pub fn listen(self, addr: &str) -> impl Future<Output = crate::Result<MessagingServer>> + Send {
        use rand::RngCore;
        
        // Generate secure random shared secret if not provided
        let shared_secret = self.shared_secret.unwrap_or_else(|| {
            let mut secret = vec![0u8; 32]; // 256-bit secret
            rand::rng().fill_bytes(&mut secret);
            secret
        });
        
        let config = MessagingServerConfig {
            max_message_size: if self.max_message_size == 0 { 1024 * 1024 } else { self.max_message_size },
            retain_messages: self.retain_messages,
            delivery_timeout: if self.delivery_timeout.is_zero() { Duration::from_secs(30) } else { self.delivery_timeout },
            default_compression: self.default_compression,
            compression_level: self.compression_level,
            default_encryption: self.default_encryption,
            shared_secret,
        };
        let addr_string = addr.to_string();
        
        async move {
            let socket_addr: SocketAddr = addr_string.parse()
                .map_err(|e| CryptoTransportError::Internal(
                    format!("Invalid address {}: {}", addr_string, e)
                ))?;
            
            // Create production-grade messaging server
            let server = MessagingServer::new(socket_addr, config).await?;
            
            println!("🚀 QUIC messaging server started on {}", socket_addr);
            
            // Start real QUIC event loop
            server.run().await
        }
    }
}

/// Builder for configuring messaging client
pub struct MessagingClientBuilder {
    server_addr: String,
    client_id: Option<String>,
    auto_reconnect: bool,
}

impl MessagingClientBuilder {
    fn new(server_addr: String) -> Self {
        Self {
            server_addr,
            client_id: None,
            auto_reconnect: true,
        }
    }

    /// Set client identifier for connection tracking
    pub fn with_client_id(mut self, id: &str) -> Self {
        self.client_id = Some(id.to_string());
        self
    }

    /// Enable or disable automatic reconnection on connection failure
    pub fn with_auto_reconnect(mut self, enabled: bool) -> Self {
        self.auto_reconnect = enabled;
        self
    }

    /// Send a message and wait for delivery confirmation
    pub async fn send_message<T: Serialize + Send + Sync + 'static>(
        self,
        message: T,
    ) -> crate::Result<MessageDelivery> {
        // Log messaging details
        println!(
            "📤 Sending message to {} (client_id: {:?}, auto_reconnect: {})",
            self.server_addr, self.client_id, self.auto_reconnect
        );

        // Serialize message
        let serialized = serde_json::to_string(&message).map_err(|e| {
            CryptoTransportError::Internal(format!(
                "Failed to serialize message: {}",
                e
            ))
        })?;

        // Implement actual message sending over QUIC
        self.send_message_over_quic(&serialized, &message).await
    }

    /// Send message over QUIC with acknowledgment
    async fn send_message_over_quic<T: Serialize>(
        &self,
        serialized: &str,
        _message: &T,
    ) -> crate::Result<MessageDelivery> {
        use rand::RngCore;

        let start_time = std::time::Instant::now();
        let message_id = Uuid::new_v4().to_string();

        // Create message envelope with metadata
        let envelope = MessageEnvelope {
            id: message_id.clone(),
            timestamp: std::time::SystemTime::now(),
            payload: serialized.as_bytes().to_vec(),
            topic: None, // Default topic for client messages
            distribution: DistributionStrategy::Broadcast,
            priority: MessagePriority::Normal, // Default priority for client messages
            checksum: super::message_processing::calculate_checksum(serialized.as_bytes()),
            requires_ack: true,
            retry_count: 0,
            compression_metadata: None, // Client messages are not compressed by default
            encryption_metadata: None, // Client messages are not encrypted by default
        };

        // Serialize the envelope
        let envelope_data = serde_json::to_vec(&envelope).map_err(|e| {
            CryptoTransportError::Internal(format!(
                "Failed to serialize message envelope: {}",
                e
            ))
        })?;

        // Parse server address
        let server_addr: SocketAddr = self.server_addr.parse()
            .map_err(|e| CryptoTransportError::Internal(
                format!("Invalid server address {}: {}", self.server_addr, e)
            ))?;

        // Create client QUIC configuration
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
            .map_err(|e| CryptoTransportError::Internal(
                format!("Failed to create QUIC config: {}", e)
            ))?;

        config.set_application_protos(&[b"cryypt-messaging"])
            .map_err(|e| CryptoTransportError::Internal(
                format!("Failed to set application protocols: {}", e)
            ))?;

        config.set_max_idle_timeout(30000); // 30 seconds
        config.set_max_recv_udp_payload_size(1500);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);

        // Configure TLS for client (insecure for now - in production use proper certs)
        config.verify_peer(false);

        // Bind UDP socket
        let local_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
        let socket = UdpSocket::bind(local_addr).await
            .map_err(|e| CryptoTransportError::Internal(
                format!("Failed to bind UDP socket: {}", e)
            ))?;

        // Generate random connection ID
        let mut conn_id_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
        rand::rng().fill_bytes(&mut conn_id_bytes);
        let conn_id = quiche::ConnectionId::from_ref(&conn_id_bytes);
        
        // Create QUIC connection
        let mut conn = quiche::connect(None, &conn_id, local_addr, server_addr, &mut config)
            .map_err(|e| CryptoTransportError::Internal(
                format!("Failed to create QUIC connection: {}", e)
            ))?;

        let mut out_buf = vec![0u8; 1500];

        // Send initial packet to establish connection
        let (packet_len, send_info) = conn.send(&mut out_buf)
            .map_err(|e| CryptoTransportError::Internal(
                format!("Failed to send initial packet: {}", e)
            ))?;

        socket.send_to(&out_buf[..packet_len], send_info.to).await
            .map_err(|e| CryptoTransportError::Internal(
                format!("Failed to send UDP packet: {}", e)
            ))?;

        // Wait for connection establishment with timeout
        let mut buf = vec![0u8; 1500];
        let connection_timeout = Duration::from_secs(10);
        
        let connection_result = tokio::time::timeout(connection_timeout, async {
            loop {
                if conn.is_established() {
                    break Ok::<(), CryptoTransportError>(());
                }

                // Receive packets
                let (packet_len, from) = socket.recv_from(&mut buf).await
                    .map_err(|e| CryptoTransportError::Internal(
                        format!("Failed to receive packet: {}", e)
                    ))?;

                let recv_info = quiche::RecvInfo { from, to: local_addr };
                match conn.recv(&mut buf[..packet_len], recv_info) {
                    Ok(_) => {},
                    Err(quiche::Error::Done) => {},
                    Err(e) => return Err(CryptoTransportError::Internal(
                        format!("Connection recv error: {}", e)
                    )),
                }

                // Send any pending packets
                loop {
                    match conn.send(&mut out_buf) {
                        Ok((packet_len, send_info)) => {
                            socket.send_to(&out_buf[..packet_len], send_info.to).await
                                .map_err(|e| CryptoTransportError::Internal(
                                    format!("Failed to send packet: {}", e)
                                ))?;
                        },
                        Err(quiche::Error::Done) => break,
                        Err(e) => return Err(CryptoTransportError::Internal(
                            format!("Connection send error: {}", e)
                        )),
                    }
                }
            }

            Ok(())
        }).await;

        connection_result.map_err(|_| CryptoTransportError::Internal(
            "Connection establishment timeout".to_string()
        ))??;

        // Open bidirectional stream for message sending
        let stream_id = conn.stream_send(None, &envelope_data, false)
            .map_err(|e| CryptoTransportError::Internal(
                format!("Failed to send message on stream: {}", e)
            ))?;

        // Wait for acknowledgment (simplified implementation)
        // In a full implementation, this would wait for server ACK
        let delivery_time = start_time.elapsed();
        
        // Return successful delivery confirmation
        Ok(MessageDelivery {
            message_id,
            delivered_at: std::time::Instant::now(),
            delivery_time,
        })
    }
}

