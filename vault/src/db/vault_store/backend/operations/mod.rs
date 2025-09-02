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
//! Each module maintains complete functionality while following the single responsibility principle.
//! All public APIs are re-exported to maintain backward compatibility.

// Import all operation modules
pub mod basic;
pub mod ttl;
pub mod reencryption;
pub mod cleanup;
pub mod backup;
pub mod search;
pub mod advanced;

// Re-export all public APIs for backward compatibility
// This ensures that existing code using LocalVaultProvider methods continues to work unchanged

// Basic CRUD operations
pub use basic::*;

// TTL and expiry operations
pub use ttl::*;

// Re-encryption and key rotation operations
pub use reencryption::*;

// Cleanup and maintenance operations
pub use cleanup::*;

// Backup and restore operations
pub use backup::*;

// Search and listing operations
pub use search::*;

// Advanced operations
pub use advanced::*;