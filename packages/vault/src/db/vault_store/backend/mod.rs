//! Modular backend implementation for vault operations
//!
//! This module provides a decomposed, production-ready backend implementation
//! following single responsibility principles with focused submodules.

// Import all implementation modules
pub mod auth;
pub mod crypto;
pub mod key_utils;
pub mod operations;
pub mod passphrase;
pub mod provider;
pub mod schema;

// Re-export key types and functions for backward compatibility
// Note: These re-exports are currently unused but kept for API compatibility
