//! Core protocol functions and utilities for QUIC messaging

use crossbeam::utils::CachePadded;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::time::timeout;

use super::server::ServerConnectionState;
use super::types::LoadBalancer;

/// QUIC protocol constants
pub const QUIC_PROTOCOL_VERSION: u32 = quiche::PROTOCOL_VERSION;
pub const APPLICATION_PROTOCOL: &[u8] = b"cryypt-messaging";

/// Connection timeout constants
pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
pub const MAX_IDLE_TIMEOUT: u64 = 30000; // 30 seconds
pub const MAX_UDP_PAYLOAD_SIZE: usize = 1500;

/// Stream and data limits
pub const INITIAL_MAX_DATA: u64 = 10_000_000;
pub const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 1_000_000;
pub const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 1_000_000;
pub const INITIAL_MAX_STREAMS_BIDI: u64 = 100;
pub const INITIAL_MAX_STREAMS_UNI: u64 = 100;

/// Performance monitoring utilities
pub struct PerformanceMonitor {
    message_count: AtomicU64,
    bytes_processed: AtomicU64,
    connection_count: AtomicU64,
    error_count: AtomicU64,
}

impl Default for PerformanceMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl PerformanceMonitor {
    #[must_use]
    pub fn new() -> Self {
        Self {
            message_count: AtomicU64::new(0),
            bytes_processed: AtomicU64::new(0),
            connection_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        }
    }

    pub fn increment_messages(&self) {
        self.message_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_bytes_processed(&self, bytes: u64) {
        self.bytes_processed.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn increment_connections(&self) {
        self.connection_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn decrement_connections(&self) {
        self.connection_count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn increment_errors(&self) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_stats(&self) -> (u64, u64, u64, u64) {
        (
            self.message_count.load(Ordering::Relaxed),
            self.bytes_processed.load(Ordering::Relaxed),
            self.connection_count.load(Ordering::Relaxed),
            self.error_count.load(Ordering::Relaxed),
        )
    }
}

/// Connection ID utilities
#[must_use]
pub fn generate_connection_id() -> Vec<u8> {
    use rand::RngCore;
    let mut conn_id_bytes = [0u8; quiche::MAX_CONN_ID_LEN];
    rand::rng().fill_bytes(&mut conn_id_bytes);
    conn_id_bytes.to_vec()
}

/// Connection configuration utilities
///
/// # Errors
///
/// Returns an error if:
/// - QUIC configuration creation fails
/// - Invalid protocol parameters
/// - System resource limitations
pub fn create_quic_config() -> Result<quiche::Config, quiche::Error> {
    let mut config = quiche::Config::new(QUIC_PROTOCOL_VERSION)?;

    config.set_application_protos(&[APPLICATION_PROTOCOL])?;
    config.set_max_idle_timeout(MAX_IDLE_TIMEOUT);
    config.set_max_recv_udp_payload_size(MAX_UDP_PAYLOAD_SIZE);
    config.set_initial_max_data(INITIAL_MAX_DATA);
    config.set_initial_max_stream_data_bidi_local(INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);
    config.set_initial_max_stream_data_bidi_remote(INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);
    config.set_initial_max_streams_bidi(INITIAL_MAX_STREAMS_BIDI);
    config.set_initial_max_streams_uni(INITIAL_MAX_STREAMS_UNI);

    Ok(config)
}

/// Configure QUIC for client connections
///
/// # Errors
///
/// Returns an error if:
/// - Base QUIC configuration creation fails
/// - Client-specific configuration parameters are invalid
pub fn create_client_quic_config() -> Result<quiche::Config, quiche::Error> {
    let mut config = create_quic_config()?;
    config.verify_peer(true); // Enable proper client certificate validation
    Ok(config)
}

/// Health checker for connections
pub struct ConnectionHealthChecker {
    health_check_interval: Duration,
}

impl ConnectionHealthChecker {
    #[must_use]
    pub fn new(interval: Duration) -> Self {
        Self {
            health_check_interval: interval,
        }
    }

    /// Perform health check on all connections
    pub async fn health_check_connections(
        &self,
        connections: &DashMap<Vec<u8>, Arc<CachePadded<ServerConnectionState>>>,
        _load_balancer: &LoadBalancer,
    ) -> Vec<Vec<u8>> {
        let mut unhealthy_connections = Vec::new();
        let health_threshold = 5000; // 50% health score threshold

        // Wait for the configured health check interval before proceeding
        tokio::time::sleep(self.health_check_interval).await;

        for entry in connections {
            let conn_id = entry.key().clone();
            let state = entry.value();

            let health_score = state.health.health_score();

            if health_score < health_threshold {
                unhealthy_connections.push(conn_id);
            }

            // Update health check timestamp for this connection
            state.health.update_health_check();
        }

        unhealthy_connections
    }

    /// Get the configured health check interval
    #[must_use]
    pub fn get_interval(&self) -> Duration {
        self.health_check_interval
    }
}

/// Message flow control utilities
pub struct FlowController {
    max_outstanding_messages: usize,
    outstanding_count: AtomicU64,
}

impl FlowController {
    #[must_use]
    pub fn new(max_outstanding: usize) -> Self {
        Self {
            max_outstanding_messages: max_outstanding,
            outstanding_count: AtomicU64::new(0),
        }
    }

    /// Check if we can send more messages
    pub fn can_send(&self) -> bool {
        self.outstanding_count.load(Ordering::Relaxed) < self.max_outstanding_messages as u64
    }

    /// Reserve a slot for outgoing message
    pub fn reserve_slot(&self) -> bool {
        let current = self.outstanding_count.load(Ordering::Relaxed);
        if current < self.max_outstanding_messages as u64 {
            self.outstanding_count.fetch_add(1, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Release a slot when message is processed
    pub fn release_slot(&self) {
        self.outstanding_count.fetch_sub(1, Ordering::Relaxed);
    }

    /// Get current outstanding message count
    pub fn outstanding_count(&self) -> u64 {
        self.outstanding_count.load(Ordering::Relaxed)
    }
}

/// Retry logic utilities
pub struct RetryManager {
    max_retries: u32,
    base_delay: Duration,
    max_delay: Duration,
}

impl RetryManager {
    #[must_use]
    pub fn new(max_retries: u32, base_delay: Duration, max_delay: Duration) -> Self {
        Self {
            max_retries,
            base_delay,
            max_delay,
        }
    }

    /// Calculate exponential backoff delay
    #[must_use]
    pub fn calculate_delay(&self, attempt: u32) -> Duration {
        let delay_ms = self.base_delay.as_millis() * (2u128.pow(attempt.min(10)));
        let clamped_delay_ms = delay_ms.min(self.max_delay.as_millis());
        Duration::from_millis(u64::try_from(clamped_delay_ms).unwrap_or(u64::MAX))
    }

    /// Check if we should retry
    #[must_use]
    pub fn should_retry(&self, attempt: u32) -> bool {
        attempt < self.max_retries
    }

    /// Execute with retry logic
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - All retry attempts fail
    /// - Operation times out
    /// - Operation returns an unrecoverable error
    pub async fn retry_with_backoff<F, T, E>(&self, mut operation: F) -> Result<T, E>
    where
        F: FnMut() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<T, E>> + Send>>,
        E: std::fmt::Debug,
        T: std::fmt::Debug,
    {
        let mut attempt = 0;

        loop {
            match timeout(Duration::from_secs(30), operation()).await {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(e)) => {
                    if self.should_retry(attempt) {
                        let delay = self.calculate_delay(attempt);
                        tracing::warn!(
                            "Operation failed (attempt {}), retrying in {:?}: {:?}",
                            attempt + 1,
                            delay,
                            e
                        );
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                    } else {
                        tracing::error!(
                            "Operation failed after {} attempts: {:?}",
                            self.max_retries,
                            e
                        );
                        return Err(e);
                    }
                }
                Err(_) => {
                    if self.should_retry(attempt) {
                        let delay = self.calculate_delay(attempt);
                        tracing::warn!(
                            "Operation timed out (attempt {}), retrying in {:?}",
                            attempt + 1,
                            delay
                        );
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                    } else {
                        tracing::error!("Operation timed out after {} attempts", self.max_retries);
                        match operation().await {
                            Ok(success) => {
                                // Operation succeeded after timeout - this is unexpected but we should return success
                                tracing::warn!(
                                    "Operation succeeded unexpectedly after timeout and max retries"
                                );
                                return Ok(success);
                            }
                            Err(actual_error) => {
                                // This is the "actual error" we wanted to return
                                tracing::error!(
                                    "Operation failed after {} attempts: {:?}",
                                    self.max_retries,
                                    actual_error
                                );
                                return Err(actual_error);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Message validation utilities
pub struct MessageValidator {
    max_message_size: usize,
    max_topic_length: usize,
}

impl MessageValidator {
    #[must_use]
    pub fn new(max_message_size: usize, max_topic_length: usize) -> Self {
        Self {
            max_message_size,
            max_topic_length,
        }
    }

    /// Validate message size
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Message payload exceeds maximum allowed size
    pub fn validate_message_size(&self, payload: &[u8]) -> Result<(), String> {
        if payload.len() > self.max_message_size {
            Err(format!(
                "Message size {} exceeds maximum {}",
                payload.len(),
                self.max_message_size
            ))
        } else {
            Ok(())
        }
    }

    /// Validate topic name
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Topic name is empty
    /// - Topic name is too long
    /// - Topic name contains invalid characters
    pub fn validate_topic(&self, topic: &str) -> Result<(), String> {
        if topic.is_empty() {
            return Err("Topic cannot be empty".to_string());
        }

        if topic.len() > self.max_topic_length {
            return Err(format!(
                "Topic length {} exceeds maximum {}",
                topic.len(),
                self.max_topic_length
            ));
        }

        // Check for invalid characters
        if topic.contains('\0') || topic.contains('\n') || topic.contains('\r') {
            return Err("Topic contains invalid characters".to_string());
        }

        Ok(())
    }
}

/// Metrics collection utilities
pub struct MetricsCollector {
    start_time: std::time::Instant,
    performance_monitor: Arc<PerformanceMonitor>,
}

impl MetricsCollector {
    pub fn new(performance_monitor: Arc<PerformanceMonitor>) -> Self {
        Self {
            start_time: std::time::Instant::now(),
            performance_monitor,
        }
    }

    /// Get uptime in seconds
    #[must_use]
    pub fn uptime_seconds(&self) -> u64 {
        self.start_time.elapsed().as_secs()
    }

    /// Get formatted metrics report
    #[must_use]
    pub fn get_metrics_report(&self) -> String {
        let (messages, bytes, connections, errors) = self.performance_monitor.get_stats();
        let uptime = self.uptime_seconds();

        format!(
            "QUIC Messaging Server Metrics:\n\
             - Uptime: {}s\n\
             - Messages processed: {}\n\
             - Bytes processed: {}\n\
             - Active connections: {}\n\
             - Error count: {}\n\
             - Messages/sec: {:.2}\n\
             - Bytes/sec: {:.2}",
            uptime,
            messages,
            bytes,
            connections,
            errors,
            if uptime > 0 {
                #[allow(clippy::cast_possible_truncation)]
                let messages_clamped = messages.min(u64::from(u32::MAX)) as u32;
                #[allow(clippy::cast_possible_truncation)]
                let uptime_clamped = uptime.min(u64::from(u32::MAX)) as u32;
                f64::from(messages_clamped) / f64::from(uptime_clamped)
            } else {
                0.0
            },
            if uptime > 0 {
                #[allow(clippy::cast_possible_truncation)]
                let bytes_clamped = bytes.min(u64::from(u32::MAX)) as u32;
                #[allow(clippy::cast_possible_truncation)]
                let uptime_clamped = uptime.min(u64::from(u32::MAX)) as u32;
                f64::from(bytes_clamped) / f64::from(uptime_clamped)
            } else {
                0.0
            }
        )
    }
}
