//! Messaging server implementation with modular architecture
//!
//! This module implements a production-grade QUIC messaging server with:
//! - Configuration management
//! - Topic subscription management  
//! - Connection health monitoring
//! - Core server functionality
//!
//! Decomposed for maintainability and single responsibility principle.

pub mod config;
pub mod topic_manager; 
pub mod connection_health;
pub mod core;

// Re-export all public types and functions for convenience
pub use config::{MessagingServerConfig, CertificateConfig};
pub use topic_manager::TopicSubscriptionManager;
pub use connection_health::{ConnectionHealth, ConnectionReputation};
pub use core::{MessagingServer, ServerConnectionState, SecurityBan};

// Alias for backward compatibility with existing imports
pub use topic_manager::TopicSubscriptionManager as TopicSubscriptions;