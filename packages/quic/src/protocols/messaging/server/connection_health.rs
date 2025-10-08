//! Connection health monitoring and metrics

use super::super::types::now_millis;
use std::sync::atomic::{AtomicU64, Ordering};

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

impl Default for ConnectionHealth {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionHealth {
    #[must_use]
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

    /// Update health check timestamp
    pub fn update_health_check(&self) {
        self.last_health_check
            .store(now_millis(), Ordering::Relaxed);
    }

    /// Get last health check timestamp
    pub fn last_health_check_time(&self) -> u64 {
        self.last_health_check.load(Ordering::Relaxed)
    }

    /// Check if health check is overdue (more than 60 seconds old)
    pub fn is_health_check_overdue(&self) -> bool {
        let current_time = now_millis();
        let last_check = self.last_health_check.load(Ordering::Relaxed);
        current_time.saturating_sub(last_check) > 60000 // 60 seconds
    }

    /// Calculate overall health score (0-10000 for 0-100.00%)
    pub fn health_score(&self) -> u64 {
        let success_rate = self.success_rate.load(Ordering::Relaxed);
        let stability = self.stability_score.load(Ordering::Relaxed);
        let error_penalty = self
            .stream_errors
            .load(Ordering::Relaxed)
            .saturating_mul(100);

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

/// Security reputation tracking for connections
#[derive(Debug)]
pub struct ConnectionReputation {
    /// Number of checksum validation failures
    pub checksum_failures: AtomicU64,
    /// Number of authentication failures
    pub auth_failures: AtomicU64,
    /// Number of protocol violations
    pub protocol_violations: AtomicU64,
    /// Last security violation timestamp
    pub last_violation_time: AtomicU64,
    /// Connection first seen timestamp
    pub first_seen_time: AtomicU64,
    /// Total security events count
    pub total_security_events: AtomicU64,
    /// Reputation score (0-10000, higher is better)
    pub reputation_score: AtomicU64,
}

impl Default for ConnectionReputation {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionReputation {
    #[must_use]
    pub fn new() -> Self {
        Self {
            checksum_failures: AtomicU64::new(0),
            auth_failures: AtomicU64::new(0),
            protocol_violations: AtomicU64::new(0),
            last_violation_time: AtomicU64::new(0),
            first_seen_time: AtomicU64::new(now_millis()),
            total_security_events: AtomicU64::new(0),
            reputation_score: AtomicU64::new(10000), // Start with perfect reputation
        }
    }

    /// Record a checksum validation failure
    pub fn record_checksum_failure(&self) {
        self.checksum_failures.fetch_add(1, Ordering::Relaxed);
        self.record_security_event();
    }

    /// Record an authentication failure
    pub fn record_auth_failure(&self) {
        self.auth_failures.fetch_add(1, Ordering::Relaxed);
        self.record_security_event();
    }

    /// Record a protocol violation
    pub fn record_protocol_violation(&self) {
        self.protocol_violations.fetch_add(1, Ordering::Relaxed);
        self.record_security_event();
    }

    /// Record a general security event and update reputation
    fn record_security_event(&self) {
        self.total_security_events.fetch_add(1, Ordering::Relaxed);
        self.last_violation_time
            .store(now_millis(), Ordering::Relaxed);
        self.update_reputation_score();
    }

    /// Update reputation score based on security events
    fn update_reputation_score(&self) {
        let events = self.total_security_events.load(Ordering::Relaxed);
        let base_score = 10000u64;

        // Each security event reduces reputation by 200 points (2%)
        let penalty = events.saturating_mul(200);
        let new_score = base_score.saturating_sub(penalty);

        self.reputation_score.store(new_score, Ordering::Relaxed);
    }

    /// Check if connection has acceptable reputation (above 70%)
    pub fn is_reputable(&self) -> bool {
        self.reputation_score.load(Ordering::Relaxed) > 7000
    }

    /// Get current reputation score (0-10000)
    pub fn get_reputation_score(&self) -> u64 {
        self.reputation_score.load(Ordering::Relaxed)
    }
}
