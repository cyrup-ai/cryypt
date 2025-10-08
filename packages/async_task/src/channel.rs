//! Channel-based async coordination patterns

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

/// Error types for channel operations
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("Channel closed")]
    Closed,
    #[error("Send failed: {0}")]
    SendFailed(String),
    #[error("Receive failed: {0}")]
    ReceiveFailed(String),
    #[error("Channel not found: {0}")]
    NotFound(String),
}

/// Async channel wrapper that provides proper async coordination
pub struct AsyncChannel<T> {
    sender: mpsc::UnboundedSender<T>,
    receiver: Arc<RwLock<Option<mpsc::UnboundedReceiver<T>>>>,
}

impl<T> Default for AsyncChannel<T>
where
    T: Send + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T> AsyncChannel<T>
where
    T: Send + 'static,
{
    /// Create a new async channel
    #[must_use]
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        Self {
            sender,
            receiver: Arc::new(RwLock::new(Some(receiver))),
        }
    }

    /// Send a message asynchronously
    ///
    /// # Errors
    ///
    /// Returns `ChannelError::SendFailed` if the channel is closed or the send operation fails.
    pub fn send(&self, message: T) -> Result<(), ChannelError> {
        self.sender
            .send(message)
            .map_err(|e| ChannelError::SendFailed(e.to_string()))
    }

    /// Receive a message asynchronously
    ///
    /// # Errors
    ///
    /// Returns `ChannelError::Closed` if the channel is closed or no more messages are available.
    pub async fn recv(&self) -> Result<Option<T>, ChannelError> {
        let mut receiver_guard = self.receiver.write().await;
        if let Some(ref mut receiver) = receiver_guard.as_mut() {
            receiver.recv().await.map(Some).ok_or(ChannelError::Closed)
        } else {
            Err(ChannelError::Closed)
        }
    }

    /// Close the channel
    pub async fn close(&self) {
        let mut receiver_guard = self.receiver.write().await;
        *receiver_guard = None;
    }
}

/// Channel registry for managing multiple named channels
pub struct ChannelRegistry<T> {
    channels: Arc<RwLock<HashMap<String, AsyncChannel<T>>>>,
}

impl<T> ChannelRegistry<T>
where
    T: Send + 'static,
{
    #[must_use]
    pub fn new() -> Self {
        Self {
            channels: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Register a new channel
    pub async fn register(&self, name: String) -> AsyncChannel<T> {
        let channel = AsyncChannel::new();
        let mut channels = self.channels.write().await;
        let channel_clone = channel.clone();
        channels.insert(name, channel);
        channel_clone
    }

    /// Get a channel by name
    ///
    /// # Errors
    ///
    /// Returns `ChannelError::NotFound` if no channel with the given name exists.
    pub async fn get(&self, name: &str) -> Result<AsyncChannel<T>, ChannelError> {
        let channels = self.channels.read().await;
        channels
            .get(name)
            .cloned()
            .ok_or_else(|| ChannelError::NotFound(name.to_string()))
    }

    /// Remove a channel
    ///
    /// # Errors
    ///
    /// Returns `ChannelError::NotFound` if no channel with the given name exists.
    pub async fn remove(&self, name: &str) -> Result<(), ChannelError> {
        let mut channels = self.channels.write().await;
        channels
            .remove(name)
            .ok_or_else(|| ChannelError::NotFound(name.to_string()))?;
        Ok(())
    }
}

impl<T> Clone for AsyncChannel<T> {
    fn clone(&self) -> Self {
        Self {
            sender: self.sender.clone(),
            receiver: Arc::clone(&self.receiver),
        }
    }
}

impl<T> Default for ChannelRegistry<T>
where
    T: Send + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}
