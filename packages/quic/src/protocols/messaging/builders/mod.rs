//! Builder patterns for messaging server and client construction
//!
//! This module provides builder patterns for constructing messaging servers and clients
//! with comprehensive configuration options and convenience presets.
//!
//! The module is decomposed into focused, single-responsibility components:
//! - `api`: High-level convenience API for creating servers and clients
//! - `server_builder`: Server builder with configuration presets and construction logic
//! - `client_builder`: Client builder with connection and messaging functionality

pub mod api;
pub mod client_builder;
pub mod server_builder;

// Re-export main types for backward compatibility
pub use api::QuicMessaging;
pub use client_builder::MessagingClientBuilder;
pub use server_builder::MessagingServerBuilder;
