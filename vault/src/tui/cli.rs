//! CLI module entry point
//! 
//! This module has been refactored into a directory structure for better organization.
//! All functionality is now available through the cli module.

pub mod cli;

// Re-export everything from the cli module for backward compatibility
pub use cli::{commands::*, process_command};