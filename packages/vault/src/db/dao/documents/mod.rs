//! Document operations implementation
//!
//! Provides SurrealDB implementation of the GenericDao trait
//! with CRUD operations and streaming support.

pub mod core;
pub mod crud_operations;
pub mod queries;
pub mod relationships;

// Re-export the main struct and trait implementation
pub use core::SurrealDbDao;
