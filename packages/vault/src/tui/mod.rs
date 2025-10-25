pub mod app;
pub mod aws_interface;
pub mod cli;
pub mod events;
pub mod pass_interface;
pub mod tabs;
pub mod types;
pub mod ui;

pub use crate::core::Vault;
pub use cli::{Cli, Commands};
use cryypt_common::error::LoggingTransformer;
pub use events::run_tui;
use log::{error, warn};

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

    // Clone vault_path before any operations to avoid borrow checker issues
    let global_vault_path = cli.vault_path.clone();

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

        // salt_path removed - salt now stored encrypted in SurrealDB

        // Expand home directory if needed (e.g., "~/path" -> "/home/user/path")
        if let Ok(expanded_vault_path) = shellexpand::full(&config.vault_path.to_string_lossy()) {
            config.vault_path = PathBuf::from(expanded_vault_path.to_string());
        }

        // salt_path expansion removed - salt now stored encrypted in SurrealDB

        // Create the vault provider
        // LocalVaultProvider has its own encryption setup

        // Ensure parent directories exist
        if let Some(parent) = config.vault_path.parent()
            && !parent.exists()
        {
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

        // salt_path directory creation removed - salt now stored encrypted in SurrealDB

        // Create provider with config
        let provider = LocalVaultProvider::new(config).await?;

        // Attempt to restore existing JWT session if available
        // This enables cross-command session persistence without re-authentication
        if let Ok(Some(jwt_token)) = provider.restore_jwt_session().await {
            log::info!("CLI_INIT: Found existing JWT session, restoring session state");

            // Populate in-memory JWT session state
            if let Err(e) = provider.populate_session_state(jwt_token).await {
                log::warn!("CLI_INIT: Failed to populate session state: {}", e);
                // Continue without session - user will need to authenticate
            } else {
                log::info!("CLI_INIT: JWT session state restored successfully");
            }
        } else {
            log::debug!("CLI_INIT: No existing JWT session found, will require authentication");
        }

        // Register provider
        vault.register_operation(provider).await;

        vault
    };

    // Use match option pattern to run TUI mode by default
    if let Some(command) = cli.command.clone() {
        // Set up JWT token in environment if provided via --jwt flag
        if let Some(jwt_token) = &cli.jwt {
            // SAFETY: Setting environment variables is safe in this context
            // as we're setting a value provided by the user via command line
            unsafe {
                std::env::set_var("VAULT_JWT", jwt_token);
            }
        }

        // Check if we need to save before executing the command
        let should_save = cli.save || matches!(command, Commands::Save {});

        // Execute CLI command
        let result = cli::process_command(
            &vault,
            command,
            global_vault_path,
            cli.passphrase.as_deref(),
            cli.rsa_key_path,
            cli.json,
        )
        .await;

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
            }
            .await
            {
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
            LoggingTransformer::log_terminal_setup(
                "invalid_json_flag",
                Some("JSON flag used without command"),
            );
            warn!("JSON flag used without command");
            eprintln!("Error: --json flag requires a command");
            std::process::exit(1);
        }
        run_tui(vault).await?;
    }

    Ok(())
}
