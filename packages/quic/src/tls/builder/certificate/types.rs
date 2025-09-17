//! Common types for certificate operations
//!
//! This module contains shared types used by both certificate validation and generation:
//! - Input source types for loading certificates from different sources
//! - Common data structures for certificate operations

use std::path::PathBuf;

/// Input source for certificate data
#[derive(Debug, Clone)]
pub enum InputSource {
    /// Load certificate from file path
    File(PathBuf),
    /// Load certificate from PEM string
    String(String),
    /// Load certificate from raw bytes
    Bytes(Vec<u8>),
}
