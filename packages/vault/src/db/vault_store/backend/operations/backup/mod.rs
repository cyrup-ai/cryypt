//! Backup and restore operations module
//!
//! This module provides comprehensive backup, restore, and key rotation capabilities
//! decomposed into focused, single-responsibility modules:
//!
//! - `backup_operations`: Backup creation and restoration operations
//! - `debug_export`: Debug export functionality for unencrypted data inspection
//! - `key_rotation`: Encryption key rotation and re-encryption operations
//! - `salt_management`: Salt generation and file management utilities
//! - `rotation_testing`: Key rotation testing and validation operations

pub mod backup_operations;
pub mod debug_export;
pub mod key_rotation;
pub mod rotation_testing;
pub mod salt_management;

// Re-export all functionality for backward compatibility
// Note: Individual module imports are handled implicitly through impl blocks
