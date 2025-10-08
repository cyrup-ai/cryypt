//! Main entry point for cryypt vault CLI application

use cryypt_common::error::LoggingTransformer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize structured logging
    LoggingTransformer::init();

    cryypt_vault::tui::run()
}
