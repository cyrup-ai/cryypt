//! Core CRUD operations for vault entries
//!
//! Contains database operations for storing, retrieving, and managing vault entries.

pub mod advanced;
pub mod crud;
pub mod namespace;
pub mod search;

// Re-export all operations through the modules
// The implementations are directly on LocalVaultProvider in each module
