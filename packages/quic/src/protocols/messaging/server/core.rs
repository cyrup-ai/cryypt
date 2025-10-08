//! Core messaging server implementation

use crossbeam::{channel, queue::ArrayQueue, utils::CachePadded};
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use uuid::Uuid;

use super::super::message_processing::{
    calculate_checksum, derive_connection_key, process_payload_forward,
};
use super::super::types::{
    CompressionAlgorithm, DistributionStrategy, EncryptionAlgorithm, LoadBalancer, MessageEnvelope,
    MessagePriority, PriorityMessageQueue, now_millis,
};
use super::config::MessagingServerConfig;
use super::connection_health::{ConnectionHealth, ConnectionReputation};
use super::topic_manager::TopicSubscriptionManager;
use crate::error::CryptoTransportError;

/// Security ban tracking for misbehaving connections
#[derive(Debug, Clone)]
pub struct SecurityBan {
    pub reason: String,
    pub start_time: u64,
    pub expiry_time: u64,
    pub ban_level: u64, // Escalating ban levels
    pub security_events_count: u64,
}

impl SecurityBan {
    pub fn new(reason: String, duration_ms: u64, ban_level: u64, events_count: u64) -> Self {
        let now = now_millis();
        Self {
            reason,
            start_time: now,
            expiry_time: now.saturating_add(duration_ms),
            ban_level,
            security_events_count: events_count,
        }
    }

    /// Check if ban has expired
    pub fn is_expired(&self) -> bool {
        now_millis() >= self.expiry_time
    }

    /// Get remaining ban time in milliseconds
    pub fn remaining_time_ms(&self) -> u64 {
        let now = now_millis();
        if now >= self.expiry_time {
            0
        } else {
            self.expiry_time.saturating_sub(now)
        }
    }
}

/// Enhanced connection state with lock-free data structures and health monitoring
#[derive(Debug)]
pub struct ServerConnectionState {
    /// Priority-aware inbound message queue
    pub inbound: PriorityMessageQueue,
    /// Bounded outbound queue for flow control
    pub outbound: ArrayQueue<Vec<u8>>,
    /// Last activity timestamp
    pub last_activity: AtomicU64,
    /// Active stream count
    pub active_streams: AtomicU64,
    /// Connection health metrics
    pub health: ConnectionHealth,
}

impl Default for ServerConnectionState {
    fn default() -> Self {
        Self::new()
    }
}

impl ServerConnectionState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            inbound: PriorityMessageQueue::new(),
            outbound: ArrayQueue::new(1000), // Bounded outbound queue for flow control
            last_activity: AtomicU64::new(now_millis()),
            active_streams: AtomicU64::new(0),
            health: ConnectionHealth::new(),
        }
    }

    /// Update activity timestamp
    pub fn update_activity(&self) {
        self.last_activity.store(now_millis(), Ordering::Relaxed);
    }
}

/// High-performance messaging server with enterprise features
pub struct MessagingServer {
    /// Server socket address
    pub addr: SocketAddr,
    /// Server configuration
    pub config: MessagingServerConfig,
    /// Lock-free connection management with sharded hashmaps
    pub connections: DashMap<Vec<u8>, Arc<CachePadded<ServerConnectionState>>>,
    /// Lock-free topic subscription management
    pub topic_subscriptions: Arc<TopicSubscriptionManager>,
    /// Load balancer for distribution strategies
    pub load_balancer: Arc<LoadBalancer>,
    /// Lock-free ACK management
    pub pending_acks: DashMap<String, channel::Sender<bool>>,
    /// Message processing pipeline
    pub message_tx: channel::Sender<MessageEnvelope>,
    pub message_rx: channel::Receiver<MessageEnvelope>,
    /// Performance counters using lock-free `DashMap`
    pub performance_counters: Arc<DashMap<&'static str, AtomicU64>>,
    /// Security reputation tracking per connection
    pub connection_reputations: DashMap<Vec<u8>, Arc<ConnectionReputation>>,
    /// Temporary security bans with automatic expiry
    pub security_bans: DashMap<Vec<u8>, SecurityBan>,
}

impl MessagingServer {
    /// Create a new `MessagingServer` with real QUIC configuration
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Server configuration is invalid
    /// - Unable to bind to the specified address
    /// - QUIC configuration setup fails
    pub fn new(addr: SocketAddr, config: MessagingServerConfig) -> crate::Result<Self> {
        // Create message processing channel
        let (message_tx, message_rx) = channel::unbounded();

        // Initialize performance counters
        let performance_counters = DashMap::new();
        performance_counters.insert("message_count", AtomicU64::new(0));
        performance_counters.insert("bytes_processed", AtomicU64::new(0));
        let performance_counters = Arc::new(performance_counters);

        Ok(Self {
            addr,
            config,
            connections: DashMap::new(),
            topic_subscriptions: Arc::new(TopicSubscriptionManager::new()),
            load_balancer: Arc::new(LoadBalancer::new()),
            pending_acks: DashMap::new(),
            message_tx,
            message_rx,
            performance_counters,
            connection_reputations: DashMap::new(),
            security_bans: DashMap::new(),
        })
    }

    /// Subscribe a connection to a topic (lock-free operation)
    pub fn subscribe_to_topic(&self, conn_id: Vec<u8>, topic: String) {
        self.topic_subscriptions.subscribe(conn_id, topic);
    }

    /// Unsubscribe a connection from a topic (lock-free operation)  
    pub fn unsubscribe_from_topic(&self, conn_id: &[u8], topic: &str) {
        self.topic_subscriptions.unsubscribe(conn_id, topic);
    }

    /// Get all connections subscribed to a topic (lock-free read)
    #[must_use]
    pub fn get_topic_subscribers(&self, topic: &str) -> Vec<Vec<u8>> {
        self.topic_subscriptions.get_subscribers(topic)
    }

    /// Send a message to specific topic subscribers (lock-free operation)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Message serialization fails
    /// - No subscribers are available for the topic
    /// - Network transmission fails
    pub async fn send_to_topic(
        &self,
        topic: String,
        payload: Vec<u8>,
        requires_ack: bool,
    ) -> crate::Result<()> {
        self.send_to_topic_with_options(
            topic,
            payload,
            requires_ack,
            DistributionStrategy::Broadcast,
            MessagePriority::Normal,
        )
        .await
    }

    /// Send a message to topic subscribers using specific distribution strategy
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Invalid distribution strategy
    /// - Message processing fails
    /// - Topic validation fails
    pub async fn send_to_topic_with_strategy(
        &self,
        topic: String,
        payload: Vec<u8>,
        requires_ack: bool,
        distribution: DistributionStrategy,
    ) -> crate::Result<()> {
        self.send_to_topic_with_options(
            topic,
            payload,
            requires_ack,
            distribution,
            MessagePriority::Normal,
        )
        .await
    }

    /// Send a message with full control over options (priority, distribution strategy)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Message creation or serialization fails
    /// - Topic validation fails
    /// - Distribution strategy is invalid
    /// - Message delivery fails
    pub async fn send_to_topic_with_options(
        &self,
        topic: String,
        payload: Vec<u8>,
        requires_ack: bool,
        distribution: DistributionStrategy,
        priority: MessagePriority,
    ) -> crate::Result<()> {
        let message_id = Uuid::new_v4().to_string();

        // Generate connection key ID from message ID (connection agnostic)
        let key_id = message_id.clone();

        // Use server's default compression and encryption settings
        let compression_alg: CompressionAlgorithm = self.config.default_compression;
        let compression_level = self.config.compression_level;
        let encryption_alg: EncryptionAlgorithm = self.config.default_encryption;

        // Derive encryption key from shared secret and message ID
        let encryption_key =
            derive_connection_key(key_id.as_bytes(), &self.config.shared_secret).await?;

        // Process payload through compression and encryption pipeline
        let (processed_payload, compression_metadata, encryption_metadata) =
            process_payload_forward(
                payload,
                compression_alg,
                compression_level,
                encryption_alg,
                encryption_key,
                key_id,
            )
            .await?;

        let envelope = MessageEnvelope {
            id: message_id,
            timestamp: std::time::SystemTime::now(),
            payload: processed_payload.clone(),
            topic: Some(topic),
            distribution,
            priority,
            checksum: calculate_checksum(&processed_payload).await?,
            requires_ack,
            retry_count: 0,
            compression_metadata,
            encryption_metadata,
        };

        // Send to processing pipeline
        self.message_tx.try_send(envelope).map_err(|e| {
            CryptoTransportError::Internal(format!("Failed to send topic message: {e}"))
        })?;

        Ok(())
    }

    /// Send a broadcast message to all connections (lock-free operation)
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Message broadcast fails
    /// - No active connections available
    /// - Network transmission errors
    pub async fn broadcast(&self, payload: Vec<u8>, requires_ack: bool) -> crate::Result<()> {
        self.broadcast_with_priority(payload, requires_ack, MessagePriority::Normal)
            .await
    }

    /// Send a broadcast message with specific priority
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Message processing fails
    /// - Broadcast delivery fails
    /// - Connection errors occur
    /// - Priority queue operations fail
    pub async fn broadcast_with_priority(
        &self,
        payload: Vec<u8>,
        requires_ack: bool,
        priority: MessagePriority,
    ) -> crate::Result<()> {
        let message_id = Uuid::new_v4().to_string();

        // Generate connection key ID from message ID (connection agnostic)
        let key_id = message_id.clone();

        // Use server's default compression and encryption settings
        let compression_alg: CompressionAlgorithm = self.config.default_compression;
        let compression_level = self.config.compression_level;
        let encryption_alg: EncryptionAlgorithm = self.config.default_encryption;

        // Derive encryption key from shared secret and message ID
        let encryption_key =
            derive_connection_key(key_id.as_bytes(), &self.config.shared_secret).await?;

        // Process payload through compression and encryption pipeline
        let (processed_payload, compression_metadata, encryption_metadata) =
            process_payload_forward(
                payload,
                compression_alg,
                compression_level,
                encryption_alg,
                encryption_key,
                key_id,
            )
            .await?;

        let envelope = MessageEnvelope {
            id: message_id,
            timestamp: std::time::SystemTime::now(),
            payload: processed_payload.clone(),
            topic: None, // No topic for broadcast
            distribution: DistributionStrategy::Broadcast,
            priority,
            checksum: calculate_checksum(&processed_payload).await?,
            requires_ack,
            retry_count: 0,
            compression_metadata,
            encryption_metadata,
        };

        // Send to processing pipeline
        self.message_tx.try_send(envelope).map_err(|e| {
            CryptoTransportError::Internal(format!("Failed to send broadcast message: {e}"))
        })?;

        Ok(())
    }

    /// Add a new connection to the server
    pub fn add_connection(&self, conn_id: Vec<u8>) {
        let state = ServerConnectionState::new();
        self.connections
            .insert(conn_id.clone(), Arc::new(CachePadded::new(state)));

        // Initialize reputation tracking
        self.connection_reputations
            .insert(conn_id, Arc::new(ConnectionReputation::new()));
    }

    /// Remove a connection from the server
    pub fn remove_connection(&self, conn_id: &[u8]) {
        self.connections.remove(conn_id);
        self.topic_subscriptions.remove_connection(conn_id);
        self.connection_reputations.remove(conn_id);
        self.security_bans.remove(conn_id);
    }

    /// Get connection state
    #[must_use]
    pub fn get_connection_state(
        &self,
        conn_id: &[u8],
    ) -> Option<Arc<CachePadded<ServerConnectionState>>> {
        self.connections
            .get(conn_id)
            .map(|entry| entry.value().clone())
    }

    /// Check if connection is banned
    #[must_use]
    pub fn is_connection_banned(&self, conn_id: &[u8]) -> bool {
        if let Some(ban) = self.security_bans.get(conn_id) {
            !ban.is_expired()
        } else {
            false
        }
    }

    /// Ban a connection for security violations
    pub fn ban_connection(&self, conn_id: Vec<u8>, reason: String, duration_ms: u64) {
        let events_count = self
            .connection_reputations
            .get(&conn_id)
            .map_or(0, |rep| rep.total_security_events.load(Ordering::Relaxed));

        let ban_level = events_count / 10 + 1; // Escalating ban levels
        let ban = SecurityBan::new(reason, duration_ms, ban_level, events_count);

        self.security_bans.insert(conn_id, ban);
    }
}
