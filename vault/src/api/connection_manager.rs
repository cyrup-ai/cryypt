//! Production-ready connection state management

use std::sync::Arc;
use tokio::sync::RwLock;

/// Production-ready connection state management
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionState {
    Idle,
    Connecting,
    Connected,
    Disconnecting,
    Disconnected,
    Error,
}

pub struct ConnectionManager {
    state: Arc<RwLock<ConnectionState>>,
    last_activity: Arc<RwLock<std::time::Instant>>,
    timeout_duration: std::time::Duration,
}

impl ConnectionManager {
    /// Create new connection manager
    pub fn new(timeout_duration: std::time::Duration) -> Self {
        Self {
            state: Arc::new(RwLock::new(ConnectionState::Idle)),
            last_activity: Arc::new(RwLock::new(std::time::Instant::now())),
            timeout_duration,
        }
    }

    /// Update connection state
    pub async fn set_state(&self, new_state: ConnectionState) {
        let mut state = self.state.write().await;
        *state = new_state;

        // Update activity timestamp
        let mut activity = self.last_activity.write().await;
        *activity = std::time::Instant::now();
    }

    /// Get current connection state
    pub async fn get_state(&self) -> ConnectionState {
        *self.state.read().await
    }

    /// Check if connection has timed out
    pub async fn is_timed_out(&self) -> bool {
        let last_activity = *self.last_activity.read().await;
        std::time::Instant::now().duration_since(last_activity) > self.timeout_duration
    }

    /// Update activity timestamp
    pub async fn update_activity(&self) {
        let mut activity = self.last_activity.write().await;
        *activity = std::time::Instant::now();
    }

    /// Check if connection is active
    pub async fn is_active(&self) -> bool {
        matches!(self.get_state().await, ConnectionState::Connected)
    }
}
