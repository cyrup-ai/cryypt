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
pub mod connection_health;
pub mod core;
pub mod topic_manager;

// Re-export all public types and functions for convenience
pub use config::MessagingServerConfig;
pub use connection_health::ConnectionHealth;
pub use core::{MessagingServer, ServerConnectionState};

// Alias for backward compatibility with existing imports
pub use topic_manager::TopicSubscriptionManager as TopicSubscriptions;
