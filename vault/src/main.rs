//! Main entry point for cryypt vault CLI application

fn main() -> Result<(), Box<dyn std::error::Error>> {
    cryypt_vault::tui::run()
}