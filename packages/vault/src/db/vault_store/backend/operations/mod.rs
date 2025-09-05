//! Modular CRUD operations for vault entries
//!
//! This module organizes vault operations into focused, single-responsibility modules:
//! - `basic`: Core CRUD operations (put, get, delete)
//! - `ttl`: Time-to-live and expiry management
//! - `reencryption`: Cryptographic key rotation and passphrase management
//! - `cleanup`: Maintenance operations and expired entry cleanup
//! - `backup`: Backup creation, restoration, and key rotation operations
//! - `search`: Search and listing operations
//! - `advanced`: Advanced operations like put_if_absent and put_all
//!
//! Each module contains `impl LocalVaultProvider` blocks that extend the provider with
//! their respective functionality. No standalone public APIs are exported.

// Import all operation modules
pub mod basic;
pub mod ttl;
pub mod reencryption;
pub mod cleanup;
pub mod backup;
pub mod search;
pub mod advanced;