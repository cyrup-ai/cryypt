//! Error handling with context propagation
//!
//! Provides a comprehensive error handling system with:
//! - Error chaining and context preservation
//! - Backtrace capture and display
//! - Structured error types with thiserror
//! - Context attachment for debugging

pub mod constructors;
pub mod display;
pub mod extensions;
pub mod logging;
pub mod macros;
pub mod types;

// Re-export all public types and traits
pub use extensions::{OptionExt, ResultExt};
pub use logging::LoggingTransformer;
pub use types::{Error, ErrorKind, Result};

// Tests moved to tests/ directory per CLAUDE.md rule
// "NEVER put tests in src/** files. Tests belong in tests/* directories"
