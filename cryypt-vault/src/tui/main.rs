//! TUI main entry point
//!
//! Re-exports from the main module structure.

// Re-export everything from the main module
mod main;
pub use main::*;

/// Application entry point wrapper
fn main() -> Result<(), Box<dyn std::error::Error>> {
    main::main()
}