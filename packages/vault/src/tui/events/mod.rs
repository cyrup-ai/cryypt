//! TUI event handling module
//!
//! This module provides decomposed event handling for the vault TUI interface,
//! organized by functional responsibility.

pub mod event_loop;
pub mod input_mode;
pub mod normal_mode;
pub mod terminal_setup;

use crate::core::Vault;
use cryypt_common::error::LoggingTransformer;
use event_loop::run_event_loop;
use terminal_setup::{cleanup_terminal, setup_terminal_and_vault};

/// Main entry point for running the TUI - Production implementation
pub async fn run_tui(vault: Vault) -> Result<(), Box<dyn std::error::Error>> {
    // Setup terminal and initialize vault with passphrase prompt
    let (terminal, app) = setup_terminal_and_vault(vault).await?;

    // Run the main event loop - this consumes the terminal
    let result = run_event_loop(terminal, app).await;

    // Cleanup terminal state - create new terminal instance for cleanup
    let cleanup_result = || -> Result<(), Box<dyn std::error::Error>> {
        use ratatui::{Terminal, backend::CrosstermBackend};
        use std::io;

        let stdout = io::stdout();
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        cleanup_terminal(terminal)?;
        Ok(())
    }();

    // Log cleanup errors but don't fail the main operation
    if let Err(cleanup_err) = cleanup_result {
        LoggingTransformer::log_cleanup_warning("terminal", &*cleanup_err);
        // Try minimal fallback cleanup
        use crossterm::terminal::disable_raw_mode;
        let _ = disable_raw_mode();
    }

    result
}
