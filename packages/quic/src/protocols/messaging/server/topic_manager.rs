//! Topic subscription management for messaging server

use dashmap::{DashMap, DashSet};

/// Topic subscription management using lock-free data structures
#[derive(Debug)]
pub struct TopicSubscriptionManager {
    /// Maps topic name to set of connection IDs subscribed to that topic
    topic_to_connections: DashMap<String, DashSet<Vec<u8>>>,
    /// Maps connection ID to set of topics it's subscribed to
    connection_to_topics: DashMap<Vec<u8>, DashSet<String>>,
}

impl Default for TopicSubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TopicSubscriptionManager {
    #[must_use]
    pub fn new() -> Self {
        Self {
            topic_to_connections: DashMap::new(),
            connection_to_topics: DashMap::new(),
        }
    }

    /// Subscribe a connection to a topic using lock-free operations
    pub fn subscribe(&self, conn_id: Vec<u8>, topic: String) {
        // Add connection to topic subscribers
        let subscribers = self.topic_to_connections.entry(topic.clone()).or_default();
        subscribers.insert(conn_id.clone());

        // Add topic to connection's subscriptions
        let topics = self.connection_to_topics.entry(conn_id).or_default();
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
    #[must_use]
    pub fn get_subscribers(&self, topic: &str) -> Vec<Vec<u8>> {
        self.topic_to_connections
            .get(topic)
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
