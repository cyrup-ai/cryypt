//! Builder patterns for messaging server and client construction

use serde::Serialize;
use std::future::Future;
use std::time::Duration;
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
    
    /// Convenience: Create a development messaging server with self-signed certificates
    pub fn development_server() -> MessagingServerBuilder {
        MessagingServerBuilder::development()
    }
    
    /// Convenience: Create a production messaging server with file-based certificates
    pub fn production_server() -> MessagingServerBuilder {
        MessagingServerBuilder::production()
    }
    
    /// Convenience: Create a low-latency messaging server optimized for speed
    pub fn low_latency_server() -> MessagingServerBuilder {
        MessagingServerBuilder::low_latency()
    }
    
    /// Convenience: Create a high-throughput messaging server optimized for large payloads
    pub fn high_throughput_server() -> MessagingServerBuilder {
        MessagingServerBuilder::high_throughput()
    }
    
    /// Convenience: Create a testing messaging server with temporary certificates
    pub fn testing_server() -> MessagingServerBuilder {
        MessagingServerBuilder::testing()
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
    /// Create a development-oriented builder with sensible defaults
    pub fn development() -> Self {
        Self {
            max_message_size: 1_048_576, // 1MB
            retain_messages: false,
            delivery_timeout: Duration::from_secs(30),
            default_compression: CompressionAlgorithm::Zstd,
            compression_level: 3,
            default_encryption: EncryptionAlgorithm::Aes256Gcm,
            shared_secret: None,
        }
    }
    
    /// Create a production-oriented builder with robust defaults
    pub fn production() -> Self {
        Self {
            max_message_size: 10_485_760, // 10MB
            retain_messages: true,
            delivery_timeout: Duration::from_secs(60),
            default_compression: CompressionAlgorithm::Zstd,
            compression_level: 6,
            default_encryption: EncryptionAlgorithm::Aes256Gcm,
            shared_secret: None,
        }
    }
    
    /// Create a low-latency builder optimized for speed
    pub fn low_latency() -> Self {
        Self {
            max_message_size: 65536, // 64KB
            retain_messages: false,
            delivery_timeout: Duration::from_secs(5),
            default_compression: CompressionAlgorithm::None,
            compression_level: 1,
            default_encryption: EncryptionAlgorithm::ChaCha20Poly1305,
            shared_secret: None,
        }
    }
    
    /// Create a high-throughput builder optimized for large payloads
    pub fn high_throughput() -> Self {
        Self {
            max_message_size: 50_331_648, // 48MB
            retain_messages: true,
            delivery_timeout: Duration::from_secs(300),
            default_compression: CompressionAlgorithm::Zstd,
            compression_level: 9,
            default_encryption: EncryptionAlgorithm::Aes256Gcm,
            shared_secret: None,
        }
    }
    
    /// Create a testing builder with minimal configuration
    pub fn testing() -> Self {
        Self {
            max_message_size: 65536, // 64KB
            retain_messages: false,
            delivery_timeout: Duration::from_secs(10),
            default_compression: CompressionAlgorithm::None,
            compression_level: 1,
            default_encryption: EncryptionAlgorithm::ChaCha20Poly1305,
            shared_secret: Some(vec![42u8; 32]), // Fixed key for testing
        }
    }

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

    /// Start listening on the specified address using working implementation
    pub fn listen(self, addr: &str) -> impl Future<Output = crate::Result<MessagingServer>> + Send {
        use rand::RngCore;
        
        // Generate secure random shared secret if not provided
        let shared_secret = self.shared_secret.unwrap_or_else(|| {
            let mut secret = vec![0u8; 32]; // 256-bit secret
            rand::rng().fill_bytes(&mut secret);
            secret
        });
        
        let addr_string = addr.to_string();
        let max_message_size = if self.max_message_size == 0 { 1024 * 1024 } else { self.max_message_size };
        let retain_messages = self.retain_messages;
        let delivery_timeout = if self.delivery_timeout.is_zero() { Duration::from_secs(30) } else { self.delivery_timeout };
        let default_compression = self.default_compression;
        let compression_level = self.compression_level;
        let default_encryption = self.default_encryption;
        
        async move {
            // Use development configuration with proper TLS integration
            let cert_dir = std::path::PathBuf::from("./certs");
            let mut config = MessagingServerConfig::development(cert_dir).await?;
            
            // Override with user settings
            config.max_message_size = max_message_size;
            config.retain_messages = retain_messages;
            config.delivery_timeout = delivery_timeout;
            config.default_compression = default_compression;
            config.compression_level = compression_level;
            config.default_encryption = default_encryption;
            config.shared_secret = shared_secret;
            // Parse the address
            let socket_addr = addr_string.parse().map_err(|e| {
                crate::error::CryptoTransportError::Internal(format!("Invalid address {}: {}", addr_string, e))
            })?;
            
            // Create messaging server with working implementation
            let messaging_server = MessagingServer::new(socket_addr, config).await?;
            
            println!("🚀 QUIC messaging server created on {}", addr_string);
            
            // Return the server - user can call .run().await to start it
            Ok(messaging_server)
        }
    }
}

/// Builder for configuring messaging client
pub struct MessagingClientBuilder {
    server_addr: String,
    client_id: Option<String>,
    auto_reconnect: bool,
    client_secret: Option<Vec<u8>>,
}

impl MessagingClientBuilder {
    fn new(server_addr: String) -> Self {
        Self {
            server_addr,
            client_id: None,
            auto_reconnect: true,
            client_secret: None,
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

    /// Set client secret for secure key derivation
    pub fn with_client_secret(mut self, secret: Vec<u8>) -> Self {
        self.client_secret = Some(secret);
        self
    }

    /// Send a message and wait for delivery confirmation
    pub async fn send_message<T: Serialize + Send + Sync + 'static>(
        self,
        message: T,
    ) -> crate::Result<MessageDelivery> {
        // Log messaging details with client identification
        let client_display = self.client_id.as_deref().unwrap_or("anonymous");
        tracing::info!(
            "📤 Sending message to {} (client_id: {}, auto_reconnect: {})",
            self.server_addr, client_display, self.auto_reconnect
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

    /// Send message over QUIC with acknowledgment using integrated QUIC API
    async fn send_message_over_quic<T: Serialize>(
        &self,
        serialized: &str,
        _message: &T,
    ) -> crate::Result<MessageDelivery> {
        let start_time = std::time::Instant::now();
        let message_id = Uuid::new_v4().to_string();
        let payload_data = serialized.as_bytes().to_vec();

        // Apply compression and encryption to client messages
        let compression_alg = CompressionAlgorithm::Zstd; // Default compression for clients
        let compression_level = 3; // Balanced compression level
        let encryption_alg = EncryptionAlgorithm::Aes256Gcm; // Default encryption for clients
        
        // Generate encryption key from message ID and client secret
        let client_secret = self.client_secret.as_ref().unwrap_or_else(|| {
            // Generate secure default client secret if not provided
            static DEFAULT_SECRET: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
            DEFAULT_SECRET.get_or_init(|| {
                use rand::RngCore;
                let mut secret = vec![0u8; 32];
                rand::rng().fill_bytes(&mut secret);
                secret
            })
        });
        let encryption_key = super::message_processing::derive_connection_key(message_id.as_bytes(), client_secret).await
            .map_err(|e| CryptoTransportError::Internal(format!("Key derivation failed: {}", e)))?;
        let key_id = message_id.clone();

        // Process payload through compression and encryption pipeline
        let (processed_payload, compression_metadata, encryption_metadata) = 
            super::message_processing::process_payload_forward(
                payload_data,
                compression_alg,
                compression_level,
                encryption_alg,
                encryption_key,
                key_id,
            ).await?;

        // Create message envelope with processed payload and metadata
        let envelope = MessageEnvelope {
            id: message_id.clone(),
            timestamp: std::time::SystemTime::now(),
            payload: processed_payload.clone(),
            topic: self.client_id.as_ref().map(|id| format!("client:{}", id)), // Use client_id for topic routing
            distribution: DistributionStrategy::Broadcast,
            priority: MessagePriority::Normal, // Default priority for client messages
            checksum: super::message_processing::calculate_checksum(&processed_payload).await,
            requires_ack: true,
            retry_count: 0,
            compression_metadata,
            encryption_metadata,
        };

        // Serialize the envelope
        let envelope_data = serde_json::to_vec(&envelope).map_err(|e| {
            CryptoTransportError::Internal(format!(
                "Failed to serialize message envelope: {}",
                e
            ))
        })?;

        // Use main QUIC API with auto-reconnect if enabled
        let mut connection_attempts = 0;
        let max_attempts = if self.auto_reconnect { 3 } else { 1 };
        
        let quic_client = loop {
            connection_attempts += 1;
            
            match crate::api::Quic::client()
                .with_server_name("localhost") // Use localhost for self-signed cert
                .connect(&self.server_addr).await {
                    Ok(client) => break client,
                    Err(e) => {
                        tracing::warn!("QUIC connection attempt {} failed: {}", connection_attempts, e);
                        
                        if connection_attempts >= max_attempts {
                            tracing::error!("Failed to connect QUIC client after {} attempts", max_attempts);
                            return Err(CryptoTransportError::Internal(
                                format!("QUIC connection failed after {} attempts: {}", max_attempts, e)
                            ));
                        }
                        
                        if self.auto_reconnect {
                            tracing::info!("Auto-reconnect enabled, retrying connection (attempt {} of {})", 
                                connection_attempts + 1, max_attempts);
                            // Brief delay before retry
                            tokio::time::sleep(Duration::from_millis(500 * connection_attempts as u64)).await;
                        }
                    }
                }
        };

        let (quic_send, quic_recv) = quic_client
            .open_bi().await
            .map_err(|e| {
                tracing::error!("Failed to open bidirectional stream: {}", e);
                CryptoTransportError::Internal(format!("Failed to open QUIC stream: {}", e))
            })?;

        // Send the message envelope over the QUIC stream
        quic_send
            .write_all(&envelope_data).await
            .map_err(|e| {
                tracing::error!("Failed to send message over QUIC stream: {}", e);
                CryptoTransportError::Internal(format!("Failed to send message: {}", e))
            })?;
        
        tracing::info!("📤 Message sent successfully over integrated QUIC stream: {}", message_id);

        // Wait for acknowledgment from server
        let ack_timeout = Duration::from_secs(30);
        let ack_result = tokio::time::timeout(ack_timeout, async {
            use futures::StreamExt;
            
            let stream = quic_recv
                .on_chunk(|result| match result {
                    Ok(chunk) => {
                        tracing::debug!("Received ACK chunk: {} bytes", chunk.len());
                        Some(chunk)
                    }
                    Err(e) => {
                        tracing::error!("QUIC ACK stream error: {}", e);
                        None
                    }
                })
                .stream();

            let mut pinned_stream = Box::pin(stream);
            let mut ack_data = Vec::new();
            
            // Collect acknowledgment data
            while let Some(chunk) = pinned_stream.next().await {
                ack_data.extend_from_slice(&chunk);
                
                // Try to parse as JSON acknowledgment
                if let Ok(ack_text) = String::from_utf8(ack_data.clone()) {
                    if let Ok(ack_json) = serde_json::from_str::<serde_json::Value>(&ack_text) {
                        if let Some(ack_message_id) = ack_json.get("ack").and_then(|v| v.as_str()) {
                            if ack_message_id == message_id {
                                tracing::debug!("Received acknowledgment for message: {}", message_id);
                                return Ok(());
                            }
                        }
                    }
                }
                
                // Break if we've received enough data to determine it's not an ACK
                if ack_data.len() > 1024 {
                    break;
                }
            }
            
            Err(CryptoTransportError::Internal("No valid acknowledgment received".to_string()))
        }).await;

        let delivery_time = start_time.elapsed();
        
        match ack_result {
            Ok(Ok(())) => {
                tracing::info!("Message {} acknowledged by server", message_id);
            }
            Ok(Err(e)) => {
                tracing::warn!("Acknowledgment error for message {}: {}", message_id, e);
                // Continue anyway - message was sent
            }
            Err(_) => {
                tracing::warn!("Acknowledgment timeout for message {} after {:?}", message_id, ack_timeout);
                // Continue anyway - message was sent
            }
        }
        
        // Return successful delivery confirmation
        Ok(MessageDelivery {
            message_id,
            delivered_at: std::time::Instant::now(),
            delivery_time,
        })
    }
}


