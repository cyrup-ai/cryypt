//! Common infrastructure and utilities for the cryypt project
//!
//! This crate provides shared functionality used across all cryypt crates including:
//! - Error handling with context propagation
//! - Metrics and telemetry
//! - Resource pooling
//! - Security audit logging
//! - Memory safety utilities

pub mod error;

pub use error::*;