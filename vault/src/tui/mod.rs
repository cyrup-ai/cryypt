pub mod app;
pub mod aws_interface;
pub mod cli;
pub mod events;
pub mod pass_interface;
pub mod tabs;
pub mod types;
pub mod ui;

pub use crate::core::Vault;
use cryypt_common::error::LoggingTransformer;
use log::{error, warn, info};
pub use cli::{Cli, Commands};
pub use events::run_tui;

// Entry point for the TUI application
#[tokio::main]
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    use crate::LocalVaultProvider;
    use crate::core::Vault;
    use clap::Parser;
    use cli::Cli;
    use std::path::PathBuf;

    // Parse command line arguments
    let cli = Cli::parse();

    // Create vault
    let vault = {
        // Initialize basic vault
        let vault = Vault::new();

        // Get default config
        let mut config = crate::config::VaultConfig::default();

        // Override with command line options if provided
        if let Some(vault_path) = cli.vault_path {
            config.vault_path = vault_path;
        }

        if let Some(salt_path) = cli.salt_path {
            config.salt_path = salt_path;
        }

        // Expand home directory if needed (e.g., "~/path" -> "/home/user/path")
        if let Ok(expanded_vault_path) = shellexpand::full(&config.vault_path.to_string_lossy()) {
            config.vault_path = PathBuf::from(expanded_vault_path.to_string());
        }

        if let Ok(expanded_salt_path) = shellexpand::full(&config.salt_path.to_string_lossy()) {
            config.salt_path = PathBuf::from(expanded_salt_path.to_string());
        }

        // Create the vault provider
        // LocalVaultProvider has its own encryption setup

        // Ensure parent directories exist
        if let Some(parent) = config.vault_path.parent()
            && !parent.exists() {
                let _ = std::fs::create_dir_all(parent);

                // Set appropriate permissions on Unix systems
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Ok(metadata) = std::fs::metadata(parent) {
                        let mut perms = metadata.permissions();
                        perms.set_mode(0o700); // rwx------ (only owner can access)
                        let _ = std::fs::set_permissions(parent, perms);
                    }
                }
            }

        if let Some(parent) = config.salt_path.parent()
            && !parent.exists() {
                let _ = std::fs::create_dir_all(parent);
            }

        // Create provider with config
        let provider = LocalVaultProvider::new(config).await?;

        // Register provider
        vault.register_operation(provider).await;

        vault
    };

    // Use match option pattern to run TUI mode by default
    if let Some(command) = cli.command.clone() {
        // Check if we need to save before executing the command
        let should_save = cli.save || matches!(command, Commands::Save {});

        // Execute CLI command
        let result = cli::process_command(&vault, command, cli.json).await;

        // If save flag is true or the command is Save, explicitly save data to disk
        if should_save {
            // Save vault data by temporarily locking it (which triggers a save)
            let passphrase = std::env::var("CYSEC_PASSPHRASE").ok();

            if let Err(e) = async {
                vault.lock().await?;
                if let Some(pass) = &passphrase {
                    vault.unlock(pass).await?;
                }
                Ok::<_, Box<dyn std::error::Error>>(())
            }.await {
                LoggingTransformer::log_vault_operation("save", "batch_operation", false);
                error!("Error during save operation: {}", e);
                eprintln!("Error during save operation: {}", e);
            }
        }

        result?;
    } else {
        // Default to TUI mode
        if cli.json {
            // JSON mode with no command makes no sense, log and print error message
            LoggingTransformer::log_terminal_setup("invalid_json_flag", Some("JSON flag used without command"));
            warn!("JSON flag used without command");
            eprintln!("Error: --json flag requires a command");
            std::process::exit(1);
        }
        run_tui(vault).await?;
    }

    Ok(())
}
