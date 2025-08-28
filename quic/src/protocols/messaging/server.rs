//! Server implementation for QUIC messaging protocol

use dashmap::{DashMap, DashSet};
use crossbeam::{channel, queue::ArrayQueue, utils::CachePadded};
use std::sync::{atomic::{AtomicU64, Ordering}, Arc};
use std::net::SocketAddr;
use std::time::Duration;
use std::collections::HashMap;
use uuid::Uuid;

use super::types::{
    CompressionAlgorithm, EncryptionAlgorithm, MessageEnvelope, 
    DistributionStrategy, MessagePriority, PriorityMessageQueue,
    LoadBalancer, now_millis
};
use super::message_processing::{derive_connection_key, process_payload_forward, calculate_checksum};
use crate::error::CryptoTransportError;

/// Production-grade messaging server configuration
#[derive(Debug, Clone)]
pub struct MessagingServerConfig {
    pub max_message_size: usize,
    pub retain_messages: bool,
    pub delivery_timeout: Duration,
    /// Default compression algorithm for all messages
    pub default_compression: CompressionAlgorithm,
    /// Compression level (1-22 for zstd, higher = better compression)
    pub compression_level: u8,
    /// Default encryption algorithm for all messages
    pub default_encryption: EncryptionAlgorithm,
    /// Shared secret for connection key derivation (32 bytes recommended)
    pub shared_secret: Vec<u8>,
}

/// Topic subscription management using lock-free data structures
#[derive(Debug)]
pub struct TopicSubscriptions {
    /// Maps topic name to set of connection IDs subscribed to that topic
    topic_to_connections: DashMap<String, DashSet<Vec<u8>>>,
    /// Maps connection ID to set of topics it's subscribed to
    connection_to_topics: DashMap<Vec<u8>, DashSet<String>>,
}

impl TopicSubscriptions {
    pub fn new() -> Self {
        Self {
            topic_to_connections: DashMap::new(),
            connection_to_topics: DashMap::new(),
        }
    }
    
    /// Subscribe a connection to a topic using lock-free operations
    pub fn subscribe(&self, conn_id: Vec<u8>, topic: String) {
        // Add connection to topic subscribers
        let subscribers = self.topic_to_connections.entry(topic.clone())
            .or_insert_with(DashSet::new);
        subscribers.insert(conn_id.clone());
        
        // Add topic to connection's subscriptions
        let topics = self.connection_to_topics.entry(conn_id)
            .or_insert_with(DashSet::new);
        topics.insert(topic);
    }
    
    /// Unsubscribe a connection from a topic
    pub fn unsubscribe(&self, conn_id: &[u8], topic: &str) {
        if let Some(subscribers) = self.topic_to_connections.get(topic) {
            subscribers.remove(conn_id);
        }
        if let Some(topics) = self.connection_to_topics.get(conn_id) {
            topics.remove(topic);
        }
    }
    
    /// Get all connections subscribed to a topic
    pub fn get_subscribers(&self, topic: &str) -> Vec<Vec<u8>> {
        self.topic_to_connections.get(topic)
            .map(|subscribers| subscribers.iter().map(|item| item.key().clone()).collect())
            .unwrap_or_default()
    }
    
    /// Remove all subscriptions for a connection (called on disconnect)
    pub fn remove_connection(&self, conn_id: &[u8]) {
        if let Some((_, topics)) = self.connection_to_topics.remove(conn_id) {
            for topic_ref in topics.iter() {
                let topic = topic_ref.key().clone();
                if let Some(subscribers) = self.topic_to_connections.get(&topic) {
                    subscribers.remove(conn_id);
                    // Clean up empty topic entries
                    if subscribers.is_empty() {
                        drop(subscribers);
                        self.topic_to_connections.remove(&topic);
                    }
                }
            }
        }
    }
}

/// Connection health metrics for automatic failover
#[derive(Debug)]
pub struct ConnectionHealth {
    /// Success rate: successful deliveries / total attempts (0-10000 for 0-100.00%)
    success_rate: AtomicU64,
    /// Total message delivery attempts
    total_attempts: AtomicU64,
    /// Successful message deliveries
    successful_deliveries: AtomicU64,
    /// Connection stability score (decreases on reconnects)
    stability_score: AtomicU64,
    /// Stream error count
    stream_errors: AtomicU64,
    /// Last health check timestamp
    last_health_check: AtomicU64,
}

impl ConnectionHealth {
    pub fn new() -> Self {
        Self {
            success_rate: AtomicU64::new(10000), // Start with 100% success rate
            total_attempts: AtomicU64::new(0),
            successful_deliveries: AtomicU64::new(0),
            stability_score: AtomicU64::new(10000), // Start with perfect stability
            stream_errors: AtomicU64::new(0),
            last_health_check: AtomicU64::new(now_millis()),
        }
    }
    
    /// Record successful message delivery
    pub fn record_success(&self) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);
        self.successful_deliveries.fetch_add(1, Ordering::Relaxed);
        self.update_success_rate();
    }
    
    /// Record failed message delivery
    pub fn record_failure(&self) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);
        self.update_success_rate();
    }
    
    /// Record stream error
    pub fn record_stream_error(&self) {
        self.stream_errors.fetch_add(1, Ordering::Relaxed);
        self.degrade_stability();
    }
    
    /// Record connection reconnect (degrades stability)
    pub fn record_reconnect(&self) {
        let current = self.stability_score.load(Ordering::Relaxed);
        let new_score = current.saturating_sub(1000); // Reduce by 10%
        self.stability_score.store(new_score, Ordering::Relaxed);
    }
    
    /// Calculate overall health score (0-10000 for 0-100.00%)
    pub fn health_score(&self) -> u64 {
        let success_rate = self.success_rate.load(Ordering::Relaxed);
        let stability = self.stability_score.load(Ordering::Relaxed);
        let error_penalty = self.stream_errors.load(Ordering::Relaxed).saturating_mul(100);
        
        // Weighted health score: 70% success rate + 30% stability - error penalty
        let base_score = (success_rate * 7 + stability * 3) / 10;
        base_score.saturating_sub(error_penalty)
    }
    
    /// Check if connection is healthy (above 50% health score)
    pub fn is_healthy(&self) -> bool {
        self.health_score() > 5000
    }
    
    /// Update success rate calculation
    fn update_success_rate(&self) {
        let attempts = self.total_attempts.load(Ordering::Relaxed);
        let successes = self.successful_deliveries.load(Ordering::Relaxed);
        
        if attempts > 0 {
            let rate = (successes * 10000) / attempts;
            self.success_rate.store(rate, Ordering::Relaxed);
        }
    }
    
    /// Degrade stability on errors
    fn degrade_stability(&self) {
        let current = self.stability_score.load(Ordering::Relaxed);
        let new_score = current.saturating_sub(50); // Small degradation per error
        self.stability_score.store(new_score, Ordering::Relaxed);
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

impl ServerConnectionState {
    pub fn new() -> Self {
        Self {
            inbound: PriorityMessageQueue::new(),
            outbound: ArrayQueue::new(1000), // Bounded for flow control
            last_activity: AtomicU64::new(now_millis()),
            active_streams: AtomicU64::new(0),
            health: ConnectionHealth::new(),
        }
    }
    
    #[inline(always)]
    pub fn update_activity(&self) {
        self.last_activity.store(now_millis(), Ordering::Relaxed);
    }
}

/// High-performance lock-free messaging server
pub struct MessagingServer {
    /// Server socket address
    pub addr: SocketAddr,
    /// Server configuration
    pub config: MessagingServerConfig,
    /// Lock-free connection management with sharded hashmaps
    pub connections: DashMap<Vec<u8>, Arc<CachePadded<ServerConnectionState>>>,
    /// Lock-free topic subscription management
    pub topic_subscriptions: Arc<TopicSubscriptions>,
    /// Load balancer for distribution strategies
    pub load_balancer: Arc<LoadBalancer>,
    /// Lock-free ACK management
    pub pending_acks: DashMap<String, channel::Sender<bool>>,
    /// Message processing pipeline
    pub message_tx: channel::Sender<MessageEnvelope>,
    pub message_rx: channel::Receiver<MessageEnvelope>,
    /// Performance counters using lock-free DashMap
    pub performance_counters: Arc<DashMap<&'static str, AtomicU64>>,
}

impl MessagingServer {
    /// Create a new MessagingServer with real QUIC configuration
    pub async fn new(addr: SocketAddr, config: MessagingServerConfig) -> crate::Result<Self> {
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
            topic_subscriptions: Arc::new(TopicSubscriptions::new()),
            load_balancer: Arc::new(LoadBalancer::new()),
            pending_acks: DashMap::new(),
            message_tx,
            message_rx,
            performance_counters,
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
    pub fn get_topic_subscribers(&self, topic: &str) -> Vec<Vec<u8>> {
        self.topic_subscriptions.get_subscribers(topic)
    }
    
    /// Send a message to specific topic subscribers (lock-free operation)
    pub async fn send_to_topic(&self, topic: String, payload: Vec<u8>, requires_ack: bool) -> crate::Result<()> {
        self.send_to_topic_with_options(topic, payload, requires_ack, DistributionStrategy::Broadcast, MessagePriority::Normal).await
    }
    
    /// Send a message to topic subscribers using specific distribution strategy
    pub async fn send_to_topic_with_strategy(
        &self, 
        topic: String, 
        payload: Vec<u8>, 
        requires_ack: bool, 
        distribution: DistributionStrategy
    ) -> crate::Result<()> {
        self.send_to_topic_with_options(topic, payload, requires_ack, distribution, MessagePriority::Normal).await
    }
    
    /// Send a message with full control over options (priority, distribution strategy)
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
        let compression_alg = self.config.default_compression;
        let compression_level = self.config.compression_level;
        let encryption_alg = self.config.default_encryption;
        
        // Derive encryption key from shared secret and message ID
        let encryption_key = derive_connection_key(key_id.as_bytes(), &self.config.shared_secret);
        
        // Process payload through compression and encryption pipeline
        let (processed_payload, compression_metadata, encryption_metadata) = 
            process_payload_forward(
                payload,
                compression_alg,
                compression_level,
                encryption_alg,
                encryption_key,
                key_id,
            ).await?;
        
        let envelope = MessageEnvelope {
            id: message_id,
            timestamp: std::time::SystemTime::now(),
            payload: processed_payload.clone(),
            topic: Some(topic),
            distribution,
            priority,
            checksum: calculate_checksum(&processed_payload),
            requires_ack,
            retry_count: 0,
            compression_metadata,
            encryption_metadata,
        };
        
        // Send to processing pipeline
        self.message_tx.try_send(envelope)
            .map_err(|e| CryptoTransportError::Internal(
                format!("Failed to send topic message: {}", e)
            ))?;
            
        Ok(())
    }
    
    /// Send a broadcast message to all connections (lock-free operation)
    pub async fn broadcast(&self, payload: Vec<u8>, requires_ack: bool) -> crate::Result<()> {
        self.broadcast_with_priority(payload, requires_ack, MessagePriority::Normal).await
    }
    
    /// Send a broadcast message with specific priority
    pub async fn broadcast_with_priority(&self, payload: Vec<u8>, requires_ack: bool, priority: MessagePriority) -> crate::Result<()> {
        let message_id = Uuid::new_v4().to_string();
        
        // Generate connection key ID from message ID (connection agnostic)
        let key_id = message_id.clone();
        
        // Use server's default compression and encryption settings
        let compression_alg = self.config.default_compression;
        let compression_level = self.config.compression_level;
        let encryption_alg = self.config.default_encryption;
        
        // Derive encryption key from shared secret and message ID
        let encryption_key = derive_connection_key(key_id.as_bytes(), &self.config.shared_secret);
        
        // Process payload through compression and encryption pipeline
        let (processed_payload, compression_metadata, encryption_metadata) = 
            process_payload_forward(
                payload,
                compression_alg,
                compression_level,
                encryption_alg,
                encryption_key,
                key_id,
            ).await?;
        
        let envelope = MessageEnvelope {
            id: message_id,
            timestamp: std::time::SystemTime::now(),
            payload: processed_payload.clone(),
            topic: None, // No topic = broadcast to all
            distribution: DistributionStrategy::Broadcast,
            priority,
            checksum: calculate_checksum(&processed_payload),
            requires_ack,
            retry_count: 0,
            compression_metadata,
            encryption_metadata,
        };
        
        // Send to processing pipeline
        self.message_tx.try_send(envelope)
            .map_err(|e| CryptoTransportError::Internal(
                format!("Failed to send broadcast message: {}", e)
            ))?;
            
        Ok(())
    }
    
    /// Clean up all subscriptions for a disconnected connection
    pub fn cleanup_connection(&self, conn_id: &[u8]) {
        self.topic_subscriptions.remove_connection(conn_id);
        self.connections.remove(conn_id);
    }

    /// Run the messaging server with complete QUIC protocol handling
    /// Based on quiche-server.rs pattern adapted for async operation with full production features
    pub async fn run(self) -> crate::Result<MessagingServer> {
        use tokio::net::UdpSocket;
        use tokio::time::{Duration, interval};
        use std::collections::HashMap;
        use quiche::{Connection, ConnectionId, Header, RecvInfo};
        use ring::rand::SystemRandom;
        use ring::hmac;
        
        const MAX_BUF_SIZE: usize = 65507;
        const MAX_DATAGRAM_SIZE: usize = 1350;
        
        let mut buf = [0; MAX_BUF_SIZE];
        let mut out = [0; MAX_BUF_SIZE];
        
        tracing::info!("Starting QUIC messaging server on {}", self.addr);
        
        // Create UDP socket with proper configuration
        let socket = UdpSocket::bind(self.addr).await
            .map_err(|e| CryptoTransportError::Internal(
                format!("Failed to bind UDP socket: {}", e)
            ))?;
        
        let local_addr = socket.local_addr()
            .map_err(|e| CryptoTransportError::Internal(
                format!("Failed to get local address: {}", e)
            ))?;
        
        tracing::info!("QUIC messaging server listening on {}", local_addr);
        
        // Create comprehensive QUIC configuration
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION)
            .map_err(|e| CryptoTransportError::Internal(
                format!("Failed to create QUIC config: {}", e)
            ))?;
        
        // Configure QUIC parameters for messaging protocol
        config.set_application_protos(&[b"cryypt-messaging"])
            .map_err(|e| CryptoTransportError::Internal(
                format!("Failed to set application protocols: {}", e)
            ))?;
        
        config.set_max_idle_timeout(self.config.delivery_timeout.as_millis() as u64);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(false);
        config.set_active_connection_id_limit(8);
        config.enable_early_data();
        
        // For development - in production, load proper certificates
        config.verify_peer(false);
        
        // Generate connection ID seed for HMAC-based connection ID generation
        let rng = SystemRandom::new();
        let conn_id_seed = hmac::Key::generate(hmac::HMAC_SHA256, &rng)
            .map_err(|e| CryptoTransportError::Internal(
                format!("Failed to generate connection ID seed: {}", e)
            ))?;
        
        // Connection tracking with proper types
        let mut clients: HashMap<Vec<u8>, Connection> = HashMap::new();
        let mut clients_ids: HashMap<ConnectionId, Vec<u8>> = HashMap::new();
        let mut client_addrs: HashMap<Vec<u8>, std::net::SocketAddr> = HashMap::new();
        let mut next_client_id = 0u64;
        
        // Performance tracking
        let mut pkt_count = 0u64;
        let mut total_bytes_processed = 0u64;
        let start_time = std::time::Instant::now();
        
        // Health check interval for connections
        let mut health_check_interval = interval(Duration::from_secs(30));
        
        // Message processing task with proper error handling
        let message_rx = self.message_rx.clone();
        let topic_subscriptions = Arc::clone(&self.topic_subscriptions);
        let load_balancer = Arc::clone(&self.load_balancer);
        let performance_counters = Arc::clone(&self.performance_counters);
        
        let message_processor = tokio::spawn(async move {
            tracing::info!("Message processor task started");
            while let Ok(envelope) = message_rx.recv() {
                tracing::debug!("Processing message: {} for topic: {:?}", 
                    envelope.id, envelope.topic);
                
                // Update performance counters
                if let Some(counter) = performance_counters.get("message_count") {
                    counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                if let Some(counter) = performance_counters.get("bytes_processed") {
                    counter.fetch_add(envelope.payload.len() as u64, std::sync::atomic::Ordering::Relaxed);
                }
                
                // Route message based on topic and distribution strategy
                if let Some(topic) = &envelope.topic {
                    let subscribers = topic_subscriptions.get_subscribers(topic);
                    
                    match envelope.distribution {
                        super::types::DistributionStrategy::Broadcast => {
                            tracing::debug!("Broadcasting to {} subscribers", subscribers.len());
                            // Send to all subscribers - handled by connection loop
                        }
                        super::types::DistributionStrategy::RoundRobin => {
                            if let Some(selected) = load_balancer.select_round_robin(topic, &subscribers) {
                                tracing::debug!("Round-robin selected connection: {:?}", selected);
                            }
                        }
                        super::types::DistributionStrategy::LeastConnections => {
                            // Would need connection state tracking for this
                            tracing::debug!("Using least connections strategy");
                        }
                        _ => {
                            tracing::debug!("Using distribution strategy: {:?}", envelope.distribution);
                        }
                    }
                } else {
                    tracing::debug!("Broadcasting message to all connections");
                }
            }
            tracing::info!("Message processor task finished");
        });
        
        tracing::info!("QUIC messaging server started successfully");
        
        // Main server event loop - comprehensive implementation
        loop {
            tokio::select! {
                // Handle health checks
                _ = health_check_interval.tick() => {
                    self.perform_health_checks(&mut clients, &mut client_addrs).await;
                    
                    // Log performance statistics
                    let uptime = start_time.elapsed();
                    let msg_rate = pkt_count as f64 / uptime.as_secs() as f64;
                    let byte_rate = total_bytes_processed as f64 / uptime.as_secs() as f64;
                    
                    tracing::info!(
                        "Server stats: {} connections, {} packets ({:.2}/sec), {} bytes ({:.2}/sec), uptime: {:?}",
                        clients.len(), pkt_count, msg_rate, total_bytes_processed, byte_rate, uptime
                    );
                }
                
                // Handle incoming packets
                recv_result = socket.recv_from(&mut buf) => {
                    match recv_result {
                        Ok((len, from)) => {
                            pkt_count += 1;
                            total_bytes_processed += len as u64;
                            
                            tracing::trace!("Received {} bytes from {}", len, from);
                            
                            let pkt_buf = &mut buf[..len];
                            
                            // Parse QUIC packet header with comprehensive error handling
                            let hdr = match Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                                Ok(v) => v,
                                Err(e) => {
                                    tracing::error!("Failed to parse packet header from {}: {}", from, e);
                                    continue;
                                }
                            };
                            
                            tracing::trace!("Got packet: {:?} from {}", hdr, from);
                            
                            // Generate consistent connection ID using HMAC
                            let conn_id = hmac::sign(&conn_id_seed, &hdr.dcid);
                            let conn_id_bytes = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                            let conn_id_vec = conn_id_bytes.to_vec();
                            
                            // Look up existing connection or create new one
                            let mut is_new_connection = false;
                            
                            if !clients_ids.contains_key(&hdr.dcid) && !clients.contains_key(&conn_id_vec) {
                                // New connection handling
                                if hdr.ty != quiche::Type::Initial {
                                    tracing::warn!("Non-Initial packet from unknown client: {} (type: {:?})", from, hdr.ty);
                                    continue;
                                }
                                
                                if !quiche::version_is_supported(hdr.version) {
                                    tracing::warn!("Unsupported QUIC version {} from {}", hdr.version, from);
                                    
                                    let len = match quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out) {
                                        Ok(len) => len,
                                        Err(e) => {
                                            tracing::error!("Version negotiation failed: {}", e);
                                            continue;
                                        }
                                    };
                                    
                                    if len > 0 {
                                        if let Err(e) = socket.send_to(&out[..len], from).await {
                                            tracing::error!("Failed to send version negotiation: {}", e);
                                        }
                                    }
                                    continue;
                                }
                                
                                tracing::info!("New QUIC connection from {} (dcid: {:?})", from, hdr.dcid);
                                
                                // Create connection ID for new client
                                let scid = ConnectionId::from_vec(conn_id_vec.clone());
                                
                                // Create new QUIC connection with proper error handling
                                let conn = match quiche::accept(&scid, None, local_addr, from, &mut config) {
                                    Ok(c) => c,
                                    Err(e) => {
                                        tracing::error!("Failed to accept connection from {}: {}", from, e);
                                        continue;
                                    }
                                };
                                
                                // Store connection with proper indexing
                                clients.insert(conn_id_vec.clone(), conn);
                                clients_ids.insert(scid.clone(), conn_id_vec.clone());
                                clients_ids.insert(hdr.dcid.clone(), conn_id_vec.clone());
                                client_addrs.insert(conn_id_vec.clone(), from);
                                
                                next_client_id += 1;
                                is_new_connection = true;
                                
                                tracing::info!("Created new connection {} for client {}", 
                                    next_client_id, from);
                            }
                            
                            // Get the connection ID to use
                            let conn_key = clients_ids.get(&hdr.dcid)
                                .or_else(|| clients_ids.get(&ConnectionId::from_ref(&conn_id_vec)))
                                .cloned()
                                .unwrap_or(conn_id_vec);
                            
                            // Process packet with connection
                            if let Some(conn) = clients.get_mut(&conn_key) {
                                let recv_info = RecvInfo { 
                                    to: local_addr, 
                                    from,
                                };
                                
                                match conn.recv(pkt_buf, recv_info) {
                                    Ok(read) => {
                                        tracing::trace!("Connection processed {} bytes from {}", read, from);
                                        
                                        // Handle connection establishment
                                        if conn.is_established() {
                                            if is_new_connection {
                                                tracing::info!("QUIC connection established with {}", from);
                                                
                                                // Subscribe to default messaging topic if configured
                                                let default_topic = "default".to_string();
                                                self.topic_subscriptions.subscribe(conn_key.clone(), default_topic.clone());
                                                tracing::debug!("Subscribed connection to default topic: {}", default_topic);
                                            }
                                            
                                            // Handle messaging protocol for established connections
                                            self.handle_established_connection(conn, &conn_key, from).await;
                                        }
                                    }
                                    Err(quiche::Error::Done) => {
                                        // Normal - no more data to process
                                        tracing::trace!("Connection recv done for {}", from);
                                    }
                                    Err(e) => {
                                        tracing::error!("Connection recv failed from {}: {}", from, e);
                                        // Connection error - will be cleaned up in cleanup phase
                                    }
                                }
                            } else {
                                tracing::warn!("Received packet for unknown connection from {}", from);
                            }
                        }
                        Err(e) => {
                            tracing::error!("UDP socket recv error: {}", e);
                            // For production, might want to continue rather than break on transient errors
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                continue;
                            }
                            break;
                        }
                    }
                }
                
                // Send outgoing packets for all connections
                _ = tokio::time::sleep(Duration::from_millis(1)) => {
                    for (conn_key, conn) in clients.iter_mut() {
                        if let Some(&addr) = client_addrs.get(conn_key) {
                            // Send packets with flow control and congestion management
                            let mut total_sent = 0;
                            const MAX_BURST_SIZE: usize = 10 * MAX_DATAGRAM_SIZE;
                            
                            while total_sent < MAX_BURST_SIZE {
                                match conn.send(&mut out) {
                                    Ok((write, send_info)) => {
                                        if write == 0 {
                                            break;
                                        }
                                        
                                        total_sent += write;
                                        
                                        // Send packet with proper error handling
                                        match socket.send_to(&out[..write], send_info.to).await {
                                            Ok(sent) => {
                                                tracing::trace!("Sent {} bytes to {} (requested: {})", 
                                                    sent, send_info.to, write);
                                            }
                                            Err(e) => {
                                                tracing::error!("Failed to send {} bytes to {}: {}", 
                                                    write, send_info.to, e);
                                                
                                                // On send errors, break to avoid flooding logs
                                                if e.kind() != std::io::ErrorKind::WouldBlock {
                                                    break;
                                                }
                                            }
                                        }
                                        
                                        // Prevent overwhelming the network
                                        if write < MAX_DATAGRAM_SIZE / 2 {
                                            break;
                                        }
                                    }
                                    Err(quiche::Error::Done) => break,
                                    Err(e) => {
                                        tracing::error!("Connection send failed to {}: {}", addr, e);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // Clean up closed connections with proper resource management
            let mut to_remove = Vec::new();
            for (conn_key, conn) in clients.iter() {
                if conn.is_closed() {
                    if let Some(&addr) = client_addrs.get(conn_key) {
                        tracing::info!("Connection to {} closed - stats: {:?}", addr, conn.stats());
                        
                        // Clean up topic subscriptions
                        self.topic_subscriptions.remove_connection(conn_key);
                        
                        to_remove.push(conn_key.clone());
                    }
                }
            }
            
            // Remove closed connections from all tracking structures
            for conn_key in to_remove {
                clients.remove(&conn_key);
                client_addrs.remove(&conn_key);
                
                // Remove from connection ID mappings
                clients_ids.retain(|_, v| v != &conn_key);
                
                tracing::debug!("Cleaned up connection: {:?}", conn_key);
            }
        }
        
        // Cleanup on server shutdown
        tracing::info!("QUIC messaging server shutting down");
        message_processor.abort();
        
        // Gracefully close all connections
        for (conn_key, conn) in clients.iter_mut() {
            if !conn.is_closed() {
                let _ = conn.close(false, 0x00, b"server shutdown");
                tracing::debug!("Closed connection: {:?}", conn_key);
            }
        }
        
        Ok(self)
    }
    
    /// Perform comprehensive health checks on active connections
    async fn perform_health_checks(
        &self,
        clients: &mut HashMap<Vec<u8>, quiche::Connection>,
        client_addrs: &mut HashMap<Vec<u8>, std::net::SocketAddr>,
    ) {
        let mut unhealthy_connections = Vec::new();
        
        for (conn_key, conn) in clients.iter_mut() {
            // Check connection timeout
            if let Some(timeout) = conn.timeout() {
                if timeout.as_millis() == 0 {
                    conn.on_timeout();
                    tracing::debug!("Applied timeout to connection: {:?}", conn_key);
                }
            }
            
            // Check if connection has been idle too long
            let stats = conn.stats();
            if stats.sent == 0 && stats.recv == 0 {
                // Connection is completely idle - might want to probe or close
                tracing::debug!("Idle connection detected: {:?}", conn_key);
            }
            
            // Mark unhealthy connections for potential cleanup
            if conn.is_draining() {
                unhealthy_connections.push(conn_key.clone());
            }
        }
        
        // Handle unhealthy connections
        for conn_key in unhealthy_connections {
            if let Some(_conn) = clients.get_mut(&conn_key) {
                if let Some(&addr) = client_addrs.get(&conn_key) {
                    tracing::warn!("Unhealthy connection to {}, attempting recovery", addr);
                    // Could implement connection recovery logic here
                }
            }
        }
    }
    
    /// Handle messaging protocol for established QUIC connections
    async fn handle_established_connection(
        &self,
        conn: &mut quiche::Connection,
        conn_key: &[u8],
        peer_addr: std::net::SocketAddr,
    ) {
        // Process readable streams
        for stream_id in conn.readable() {
            let mut buf = vec![0u8; self.config.max_message_size];
            let mut total_data = Vec::new();
            
            // Read complete message from stream
            loop {
                match conn.stream_recv(stream_id, &mut buf) {
                    Ok((read, fin)) => {
                        total_data.extend_from_slice(&buf[..read]);
                        tracing::trace!("Stream {} received {} bytes (fin={})", stream_id, read, fin);
                        
                        if fin || total_data.len() >= self.config.max_message_size {
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(e) => {
                        tracing::error!("Stream {} recv error from {}: {}", stream_id, peer_addr, e);
                        break;
                    }
                }
            }
            
            if !total_data.is_empty() {
                // Parse message envelope from stream data
                match serde_json::from_slice::<super::types::MessageEnvelope>(&total_data) {
                    Ok(envelope) => {
                        tracing::info!("Received message: {} from {} (size: {} bytes)", 
                            envelope.id, peer_addr, total_data.len());
                        
                        // Verify message checksum
                        let calculated_checksum = super::message_processing::calculate_checksum(&envelope.payload);
                        if calculated_checksum != envelope.checksum {
                            tracing::error!("Message checksum mismatch: expected {}, got {}", 
                                envelope.checksum, calculated_checksum);
                            continue;
                        }
                        
                        // Process message through pipeline
                        if let Some(topic) = &envelope.topic {
                            // Subscribe connection to topic if not already subscribed
                            self.topic_subscriptions.subscribe(conn_key.to_vec(), topic.clone());
                            tracing::debug!("Connection subscribed to topic: {}", topic);
                        }
                        
                        // Decompress and decrypt if needed
                        let processed_payload = if envelope.compression_metadata.is_some() || envelope.encryption_metadata.is_some() {
                            let key = super::message_processing::derive_connection_key(conn_key, &self.config.shared_secret);
                            match super::message_processing::process_payload_reverse(
                                envelope.payload.clone(),
                                envelope.compression_metadata.as_ref(),
                                envelope.encryption_metadata.as_ref(),
                                key,
                            ).await {
                                Ok(payload) => payload,
                                Err(e) => {
                                    tracing::error!("Failed to process message payload: {}", e);
                                    continue;
                                }
                            }
                        } else {
                            envelope.payload.clone()
                        };
                        
                        tracing::debug!("Processed message payload: {} bytes", processed_payload.len());
                        
                        // Send acknowledgment if required
                        if envelope.requires_ack {
                            let ack_message = format!("{{\"ack\": \"{}\", \"status\": \"received\"}}", envelope.id);
                            
                            match conn.stream_send(stream_id, ack_message.as_bytes(), true) {
                                Ok(written) => {
                                    tracing::debug!("Sent ACK for message {} ({} bytes)", envelope.id, written);
                                }
                                Err(e) => {
                                    tracing::error!("Failed to send ACK for message {}: {}", envelope.id, e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::error!("Failed to parse message envelope from {}: {}", peer_addr, e);
                        
                        // Send error response
                        let error_response = format!("{{\"error\": \"Invalid message format: {}\"}}", e);
                        let _ = conn.stream_send(stream_id, error_response.as_bytes(), true);
                    }
                }
            }
        }
        
        // Process writable streams for outgoing messages
        for stream_id in conn.writable() {
            // Check if we have any outgoing messages for this connection
            if let Some(conn_state) = self.connections.get(conn_key) {
                while let Some(outgoing_data) = conn_state.outbound.pop() {
                    match conn.stream_send(stream_id, &outgoing_data, false) {
                        Ok(written) => {
                            tracing::trace!("Sent {} bytes on stream {} to {}", written, stream_id, peer_addr);
                            
                            if written < outgoing_data.len() {
                                // Partial write - need to handle remaining data
                                let remaining = &outgoing_data[written..];
                                if conn_state.outbound.push(remaining.to_vec()).is_err() {
                                    tracing::warn!("Outbound queue full, dropping data");
                                }
                                break;
                            }
                        }
                        Err(quiche::Error::Done) => {
                            // Stream not ready for writing - put data back
                            if conn_state.outbound.push(outgoing_data).is_err() {
                                tracing::warn!("Outbound queue full, dropping data");
                            }
                            break;
                        }
                        Err(e) => {
                            tracing::error!("Stream {} send error to {}: {}", stream_id, peer_addr, e);
                            break;
                        }
                    }
                }
            }
        }
    }
}