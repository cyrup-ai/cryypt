//! Message processing pipeline with compression and encryption
//!
//! This module provides a complete message processing pipeline decomposed into
//! focused, single-responsibility components for maintainability and clarity.
//!
//! The module is decomposed into the following components:
//! - `crypto_utils`: Checksum calculation and key derivation functions
//! - `compression_pipeline`: Streaming compression and decompression
//! - `encryption_pipeline`: Streaming encryption and decryption
//! - `combined_pipelines`: High-level combined processing workflows

pub mod crypto_utils;
pub mod compression_pipeline;
pub mod encryption_pipeline;
pub mod combined_pipelines;

// Re-export key functions for backward compatibility
pub use crypto_utils::{
    calculate_checksum, 
    calculate_checksum_64, 
    calculate_authenticated_checksum, 
    verify_authenticated_checksum, 
    derive_connection_key
};
pub use compression_pipeline::{compress_payload_stream, decompress_payload_stream};
pub use encryption_pipeline::{encrypt_payload_stream, decrypt_payload_stream};
pub use combined_pipelines::{process_payload_forward, process_payload_reverse};