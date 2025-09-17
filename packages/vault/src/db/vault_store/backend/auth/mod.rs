//! Authentication and session management for vault operations
//!
//! Contains JWT token validation, passphrase verification, and session state management.

pub mod lock;
pub mod passphrase;
pub mod session;
pub mod unlock;

// Re-export key types
pub use session::AuthState;
