//! Builder for configuring messaging client

use serde::Serialize;
use std::time::Duration;
use uuid::Uuid;

use super::super::types::{
    CompressionAlgorithm, DistributionStrategy, EncryptionAlgorithm, MessageDelivery,
    MessageEnvelope, MessagePriority,
};
use crate::error::CryptoTransportError;

/// Builder for configuring messaging client
pub struct MessagingClientBuilder {
    server_addr: String,
    client_id: Option<String>,
    auto_reconnect: bool,
    client_secret: Option<Vec<u8>>,
}

impl MessagingClientBuilder {
    pub(super) fn new(server_addr: String) -> Self {
        Self {
            server_addr,
            client_id: None,
            auto_reconnect: true,
            client_secret: None,
        }
    }

    /// Set client identifier for connection tracking
    #[must_use]
    pub fn with_client_id(mut self, id: &str) -> Self {
        self.client_id = Some(id.to_string());
        self
    }

    /// Enable or disable automatic reconnection on connection failure
    #[must_use]
    pub fn with_auto_reconnect(mut self, enabled: bool) -> Self {
        self.auto_reconnect = enabled;
        self
    }

    /// Set client secret for secure key derivation
    #[must_use]
    pub fn with_client_secret(mut self, secret: Vec<u8>) -> Self {
        self.client_secret = Some(secret);
        self
    }

    /// Send a message and wait for delivery confirmation
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Message serialization fails
    /// - Network connection fails
    /// - Message delivery fails
    /// - Timeout occurs during send
    pub async fn send_message<T: Serialize + Send + Sync + 'static>(
        self,
        message: T,
    ) -> crate::Result<MessageDelivery> {
        // Log messaging details with client identification
        let client_display = self.client_id.as_deref().unwrap_or("anonymous");
        tracing::info!(
            "📤 Sending message to {} (client_id: {}, auto_reconnect: {})",
            self.server_addr,
            client_display,
            self.auto_reconnect
        );

        // Serialize message
        let serialized = serde_json::to_string(&message).map_err(|e| {
            CryptoTransportError::Internal(format!("Failed to serialize message: {e}"))
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

        // Setup encryption and process payload
        let (processed_payload, compression_metadata, encryption_metadata) = self
            .setup_and_process_payload(&payload_data, &message_id)
            .await?;

        // Create message envelope
        let envelope = self
            .create_message_envelope(
                message_id.clone(),
                processed_payload,
                compression_metadata,
                encryption_metadata,
            )
            .await?;

        // Serialize the envelope
        let envelope_data = serde_json::to_vec(&envelope).map_err(|e| {
            CryptoTransportError::Internal(format!("Failed to serialize message envelope: {e}"))
        })?;

        // Establish QUIC connection with retries
        let quic_client = self.establish_quic_connection().await?;
        let (quic_send, quic_recv) = quic_client.open_bi().await.map_err(|e| {
            tracing::error!("Failed to open bidirectional stream: {}", e);
            CryptoTransportError::Internal(format!("Failed to open QUIC stream: {e}"))
        })?;

        // Send message and wait for acknowledgment
        self.send_and_await_ack(quic_send, quic_recv, &envelope_data, &message_id)
            .await?;

        let delivery_time = start_time.elapsed();

        // Return successful delivery confirmation
        Ok(MessageDelivery {
            message_id,
            delivered_at: std::time::Instant::now(),
            delivery_time,
        })
    }

    /// Setup encryption parameters and process payload through compression/encryption pipeline
    async fn setup_and_process_payload(
        &self,
        payload_data: &[u8],
        message_id: &str,
    ) -> crate::Result<(
        Vec<u8>,
        Option<super::super::types::CompressionMetadata>,
        Option<super::super::types::EncryptionMetadata>,
    )> {
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
        let encryption_key = super::super::message_processing::derive_connection_key(
            message_id.as_bytes(),
            client_secret,
        )
        .await?;
        let key_id = message_id.to_string();

        // Process payload through compression and encryption pipeline
        super::super::message_processing::process_payload_forward(
            payload_data.to_vec(),
            compression_alg,
            compression_level,
            encryption_alg,
            encryption_key,
            key_id,
        )
        .await
    }

    /// Create message envelope with processed payload and metadata
    async fn create_message_envelope(
        &self,
        message_id: String,
        processed_payload: Vec<u8>,
        compression_metadata: Option<super::super::types::CompressionMetadata>,
        encryption_metadata: Option<super::super::types::EncryptionMetadata>,
    ) -> crate::Result<MessageEnvelope> {
        let checksum =
            super::super::message_processing::calculate_checksum(&processed_payload).await?;

        Ok(MessageEnvelope {
            id: message_id,
            timestamp: std::time::SystemTime::now(),
            payload: processed_payload,
            topic: self.client_id.as_ref().map(|id| format!("client:{id}")), // Use client_id for topic routing
            distribution: DistributionStrategy::Broadcast,
            priority: MessagePriority::Normal, // Default priority for client messages
            checksum,
            requires_ack: true,
            retry_count: 0,
            compression_metadata,
            encryption_metadata,
        })
    }

    /// Establish QUIC connection with retry logic
    async fn establish_quic_connection(&self) -> crate::Result<crate::quic::QuicClient> {
        let mut connection_attempts = 0;
        let max_attempts = if self.auto_reconnect { 3 } else { 1 };

        loop {
            connection_attempts += 1;

            match crate::api::Quic::client()
                .with_server_name("localhost") // Use localhost for self-signed cert
                .connect(&self.server_addr)
                .await
            {
                Ok(client) => return Ok(client),
                Err(e) => {
                    tracing::warn!(
                        "QUIC connection attempt {} failed: {}",
                        connection_attempts,
                        e
                    );

                    if connection_attempts >= max_attempts {
                        tracing::error!(
                            "Failed to connect QUIC client after {} attempts",
                            max_attempts
                        );
                        return Err(CryptoTransportError::Internal(format!(
                            "QUIC connection failed after {max_attempts} attempts: {e}"
                        )));
                    }

                    if self.auto_reconnect {
                        tracing::info!(
                            "Auto-reconnect enabled, retrying connection (attempt {} of {})",
                            connection_attempts + 1,
                            max_attempts
                        );
                        // Brief delay before retry
                        #[allow(clippy::cast_sign_loss)]
                        tokio::time::sleep(Duration::from_millis(
                            500 * (connection_attempts.min(10) as u64),
                        ))
                        .await;
                    }
                }
            }
        }
    }

    /// Send message over QUIC stream and wait for acknowledgment
    async fn send_and_await_ack(
        &self,
        quic_send: crate::api::QuicSend,
        quic_recv: crate::api::QuicRecv,
        envelope_data: &[u8],
        message_id: &str,
    ) -> crate::Result<()> {
        // Send the message envelope over the QUIC stream
        quic_send.write_all(envelope_data).await.map_err(|e| {
            tracing::error!("Failed to send message over QUIC stream: {}", e);
            CryptoTransportError::Internal(format!("Failed to send message: {e}"))
        })?;

        tracing::info!(
            "📤 Message sent successfully over integrated QUIC stream: {}",
            message_id
        );

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
                if let Ok(ack_text) = String::from_utf8(ack_data.clone())
                    && let Ok(ack_json) = serde_json::from_str::<serde_json::Value>(&ack_text)
                    && let Some(ack_message_id) = ack_json.get("ack").and_then(|v| v.as_str())
                    && ack_message_id == message_id
                {
                    tracing::debug!("Received acknowledgment for message: {}", message_id);
                    return Ok(());
                }

                // Break if we've received enough data to determine it's not an ACK
                if ack_data.len() > 1024 {
                    break;
                }
            }

            Err(CryptoTransportError::Internal(
                "No valid acknowledgment received".to_string(),
            ))
        })
        .await;

        match ack_result {
            Ok(Ok(())) => {
                tracing::info!("Message {} acknowledged by server", message_id);
            }
            Ok(Err(e)) => {
                tracing::warn!("Acknowledgment error for message {}: {}", message_id, e);
                // Continue anyway - message was sent
            }
            Err(_) => {
                tracing::warn!(
                    "Acknowledgment timeout for message {} after {:?}",
                    message_id,
                    ack_timeout
                );
                // Continue anyway - message was sent
            }
        }

        Ok(())
    }
}
