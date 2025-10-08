//! Core types and data structures for the messaging protocol

use crossbeam::{queue::SegQueue, utils::CachePadded};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

/// Get current time in milliseconds since epoch
pub fn now_millis() -> u64 {
    match SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        #[allow(clippy::cast_possible_truncation)]
        Ok(duration) => duration.as_millis() as u64,
        Err(_) => 0, // Fallback for clock issues
    }
}

/// Compression algorithm metadata for message processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionMetadata {
    /// Compression algorithm identifier (e.g., "zstd")
    pub algorithm: String,
    /// Compression level used (1-22 for zstd)
    pub level: u8,
    /// Original payload size before compression
    pub original_size: usize,
    /// Compressed payload size after compression
    pub compressed_size: usize,
    /// Number of chunks processed during streaming compression
    pub chunks: usize,
    /// Compression timestamp
    pub timestamp: SystemTime,
}

/// Encryption algorithm metadata for message processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    /// Encryption algorithm identifier (e.g., "aes-256-gcm", "chacha20-poly1305")
    pub algorithm: String,
    /// Key identifier for key derivation (derived from connection)
    pub key_id: String,
    /// Nonce/IV used for encryption (randomized per message)
    pub nonce: Vec<u8>,
    /// Number of chunks processed during streaming encryption
    pub chunks: usize,
    /// Message authentication tag for integrity verification
    pub auth_tag: Vec<u8>,
    /// Encryption timestamp
    pub timestamp: SystemTime,
}

/// Compression algorithm options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CompressionAlgorithm {
    /// Zstandard compression (recommended, high performance)
    #[default]
    Zstd,
    /// Disabled compression
    None,
}

/// Encryption algorithm options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM (recommended for most use cases)
    #[default]
    Aes256Gcm,
    /// ChaCha20-Poly1305 (recommended for mobile/low-power devices)
    ChaCha20Poly1305,
    /// Disabled encryption (not recommended for production)
    None,
}

/// Message envelope for QUIC transport
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    /// Unique message identifier
    pub id: String,
    /// Timestamp when message was created
    pub timestamp: SystemTime,
    /// Message payload data (potentially compressed and/or encrypted)
    pub payload: Vec<u8>,
    /// Topic for multi-receiver routing
    pub topic: Option<String>,
    /// Distribution strategy for this message
    #[serde(default)]
    pub distribution: DistributionStrategy,
    /// Message priority for queue processing
    #[serde(default)]
    pub priority: MessagePriority,
    /// Checksum for integrity verification
    pub checksum: u32,
    /// Whether this message requires acknowledgment
    pub requires_ack: bool,
    /// Number of retry attempts
    pub retry_count: u32,
    /// Compression metadata (if payload is compressed)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression_metadata: Option<CompressionMetadata>,
    /// Encryption metadata (if payload is encrypted)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encryption_metadata: Option<EncryptionMetadata>,
}

/// Message delivery confirmation
#[derive(Debug, Clone)]
pub struct MessageDelivery {
    pub message_id: String,
    pub delivered_at: std::time::Instant,
    pub delivery_time: Duration,
}

/// Distribution strategy for multi-receiver messaging
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub enum DistributionStrategy {
    /// Send to all subscribers (default broadcast)
    #[default]
    Broadcast,
    /// Send to all healthy subscribers only (health-aware broadcast)
    HealthyBroadcast,
    /// Send to single subscriber using round-robin load balancing
    RoundRobin,
    /// Send to subscriber with lowest connection load
    LeastConnections,
    /// Send to healthiest subscriber
    Healthiest,
    /// Send to random subscriber
    Random,
    /// Send to random healthy subscriber
    RandomHealthy,
}

/// Message priority levels for priority queue processing
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
pub enum MessagePriority {
    /// Critical priority - processed immediately  
    Critical = 0,
    /// High priority - processed before normal messages
    High = 1,
    /// Normal priority - default processing level
    #[default]
    Normal = 2,
    /// Low priority - processed when no higher priority messages exist
    Low = 3,
}

/// Connection state for load balancing and health tracking
#[derive(Debug)]
pub struct ConnectionState {
    pub active_streams: AtomicU64,
    pub last_activity: std::sync::RwLock<std::time::Instant>,
    pub health_score: AtomicU64, // 0-100, higher is healthier
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub message_count: AtomicU64,
}

impl ConnectionState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            active_streams: AtomicU64::new(0),
            last_activity: std::sync::RwLock::new(std::time::Instant::now()),
            health_score: AtomicU64::new(100), // Start with perfect health
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            message_count: AtomicU64::new(0),
        }
    }
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionState {
    pub fn increment_streams(&self) {
        self.active_streams.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_streams(&self) {
        self.active_streams.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn get_active_streams(&self) -> u64 {
        self.active_streams.load(Ordering::Relaxed)
    }

    pub fn update_activity(&self) {
        if let Ok(mut last) = self.last_activity.write() {
            *last = std::time::Instant::now();
        }
    }

    pub fn get_health_score(&self) -> u64 {
        self.health_score.load(Ordering::Relaxed)
    }

    pub fn set_health_score(&self, score: u64) {
        self.health_score.store(score.min(100), Ordering::Relaxed);
    }
}

/// Priority-aware message queue using lock-free data structures
#[derive(Debug)]
pub struct PriorityMessageQueue {
    /// Critical priority queue (highest priority)
    critical: SegQueue<MessageEnvelope>,
    /// High priority queue  
    high: SegQueue<MessageEnvelope>,
    /// Normal priority queue (default)
    normal: SegQueue<MessageEnvelope>,
    /// Low priority queue (lowest priority)
    low: SegQueue<MessageEnvelope>,
    /// Total message count across all priorities
    total_count: AtomicU64,
}

impl PriorityMessageQueue {
    #[must_use]
    pub fn new() -> Self {
        Self {
            critical: SegQueue::new(),
            high: SegQueue::new(),
            normal: SegQueue::new(),
            low: SegQueue::new(),
            total_count: AtomicU64::new(0),
        }
    }

    /// Push message to appropriate priority queue (lock-free operation)
    pub fn push(&self, message: MessageEnvelope) {
        match message.priority {
            MessagePriority::Critical => self.critical.push(message),
            MessagePriority::High => self.high.push(message),
            MessagePriority::Normal => self.normal.push(message),
            MessagePriority::Low => self.low.push(message),
        }
        self.total_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Pop highest priority message available (lock-free operation)
    pub fn pop(&self) -> Option<MessageEnvelope> {
        // Process in priority order: Critical -> High -> Normal -> Low
        if let Some(message) = self.critical.pop() {
            self.total_count.fetch_sub(1, Ordering::Relaxed);
            return Some(message);
        }

        if let Some(message) = self.high.pop() {
            self.total_count.fetch_sub(1, Ordering::Relaxed);
            return Some(message);
        }

        if let Some(message) = self.normal.pop() {
            self.total_count.fetch_sub(1, Ordering::Relaxed);
            return Some(message);
        }

        if let Some(message) = self.low.pop() {
            self.total_count.fetch_sub(1, Ordering::Relaxed);
            return Some(message);
        }

        None
    }

    /// Get total number of queued messages across all priorities
    pub fn len(&self) -> u64 {
        self.total_count.load(Ordering::Relaxed)
    }

    /// Check if all priority queues are empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get count of messages per priority level
    pub fn priority_counts(&self) -> (usize, usize, usize, usize) {
        (
            self.critical.len(),
            self.high.len(),
            self.normal.len(),
            self.low.len(),
        )
    }
}

impl Default for PriorityMessageQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Load balancer for connection-aware distribution
#[derive(Debug)]
pub struct LoadBalancer {
    round_robin_counters: DashMap<String, AtomicU64>,
}

impl LoadBalancer {
    #[must_use]
    pub fn new() -> Self {
        Self {
            round_robin_counters: DashMap::new(),
        }
    }

    /// Select single connection using round-robin for topic
    #[must_use]
    pub fn select_round_robin(&self, topic: &str, connections: &[Vec<u8>]) -> Option<Vec<u8>> {
        if connections.is_empty() {
            return None;
        }

        let counter = self
            .round_robin_counters
            .entry(topic.to_string())
            .or_insert_with(|| AtomicU64::new(0));

        #[allow(clippy::cast_possible_truncation)]
        let index = counter.fetch_add(1, Ordering::Relaxed) as usize % connections.len();
        connections.get(index).cloned()
    }

    /// Select connection with least active streams
    #[must_use]
    pub fn select_least_connections(
        &self,
        connections: &[Vec<u8>],
        conn_states: &DashMap<Vec<u8>, Arc<CachePadded<ConnectionState>>>,
    ) -> Option<Vec<u8>> {
        if connections.is_empty() {
            return None;
        }

        let mut best_conn = None;
        let mut min_streams = u64::MAX;

        for conn_id in connections {
            if let Some(state) = conn_states.get(conn_id) {
                let stream_count = state.get_active_streams();
                if stream_count < min_streams {
                    min_streams = stream_count;
                    best_conn = Some(conn_id.clone());
                }
            }
        }

        best_conn
    }

    /// Select healthiest connection
    #[must_use]
    pub fn select_healthiest(
        &self,
        connections: &[Vec<u8>],
        conn_states: &DashMap<Vec<u8>, Arc<CachePadded<ConnectionState>>>,
    ) -> Option<Vec<u8>> {
        if connections.is_empty() {
            return None;
        }

        let mut best_conn = None;
        let mut best_health = 0u64;

        for conn_id in connections {
            if let Some(state) = conn_states.get(conn_id) {
                let health = state.get_health_score();
                if health > best_health {
                    best_health = health;
                    best_conn = Some(conn_id.clone());
                }
            }
        }

        best_conn
    }

    /// Select random connection
    #[must_use]
    pub fn select_random(&self, connections: &[Vec<u8>]) -> Option<Vec<u8>> {
        use rand::Rng;

        if connections.is_empty() {
            return None;
        }

        let index = rand::rng().random_range(0..connections.len());
        connections.get(index).cloned()
    }

    /// Select random healthy connection (health > 50)
    #[must_use]
    pub fn select_random_healthy(
        &self,
        connections: &[Vec<u8>],
        conn_states: &DashMap<Vec<u8>, Arc<CachePadded<ConnectionState>>>,
    ) -> Option<Vec<u8>> {
        let healthy_connections: Vec<_> = connections
            .iter()
            .filter(|conn_id| {
                conn_states
                    .get(*conn_id)
                    .is_some_and(|state| state.get_health_score() > 50)
            })
            .collect();

        if healthy_connections.is_empty() {
            return self.select_random(connections); // Fallback to any connection
        }

        self.select_random(&healthy_connections.into_iter().cloned().collect::<Vec<_>>())
    }

    /// Filter connections to only healthy ones (health score > 50%)
    #[must_use]
    pub fn filter_healthy_connections(
        &self,
        connections: &[Vec<u8>],
        conn_states: &DashMap<Vec<u8>, Arc<CachePadded<ConnectionState>>>,
    ) -> Vec<Vec<u8>> {
        connections
            .iter()
            .filter_map(|conn_id| {
                conn_states.get(conn_id).and_then(|state| {
                    if state.get_health_score() > 50 {
                        Some(conn_id.clone())
                    } else {
                        None
                    }
                })
            })
            .collect()
    }
}

impl Default for LoadBalancer {
    fn default() -> Self {
        Self::new()
    }
}
