//! Terminal setup and initialization for TUI

use super::super::app::App;
use crate::core::Vault;
use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use cryypt_common::error::LoggingTransformer;
use dialoguer::{Password, theme::ColorfulTheme};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io;
use zeroize::Zeroizing;

pub async fn setup_terminal_and_vault(
    vault: Vault,
) -> Result<(Terminal<CrosstermBackend<io::Stdout>>, App), Box<dyn std::error::Error>> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let mut app = App::new(vault).await;

    // If the vault is locked, first prompt for passphrase
    if app.state.is_vault_locked {
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        )?;

        // Check if this is a new vault or existing one
        let is_new_vault = app.vault.is_new_vault().await;

        if is_new_vault {
            LoggingTransformer::log_terminal_setup(
                "new_vault_creation",
                Some("Displaying password requirements"),
            );
            println!("Welcome! Creating a new secure vault.");
            println!();
            println!("Password Requirements:");
            println!("• Minimum length: 12 characters");
            println!("• Must contain uppercase and lowercase letters");
            println!("• Must contain numbers");
            println!("• Must contain special characters");
            println!("• Should not contain easily guessable information");
            println!();

            let passphrase = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Create vault passphrase")
                .interact()?;

            app.state.passphrase = Zeroizing::new(passphrase.clone());

            // For new vaults, confirm the passphrase
            let confirm = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Confirm vault passphrase")
                .interact()?;

            if passphrase != confirm {
                LoggingTransformer::log_auth_event("passphrase_mismatch", None, false);
                eprintln!("Passphrases do not match!");
                return Err("Passphrases do not match".into());
            }
        } else {
            LoggingTransformer::log_terminal_setup(
                "vault_unlock_prompt",
                Some("Prompting for existing vault passphrase"),
            );
            println!("Secure Vault - Enter passphrase to unlock");
            println!();

            let passphrase = Password::with_theme(&ColorfulTheme::default())
                .with_prompt("Enter vault passphrase")
                .interact()?;

            app.state.passphrase = Zeroizing::new(passphrase);
        }

        // Try to unlock and handle errors properly
        if let Err(err) = app.unlock().await {
            LoggingTransformer::log_auth_event("vault_unlock_failed", None, false);
            eprintln!("Failed to unlock vault: {}", err);
            return Err(Box::new(err));
        }

        enable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            EnterAlternateScreen,
            EnableMouseCapture
        )?;
    }

    // Load initial items
    app.reload_items().await;

    Ok((terminal, app))
}

pub fn cleanup_terminal(
    mut terminal: Terminal<CrosstermBackend<io::Stdout>>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}
