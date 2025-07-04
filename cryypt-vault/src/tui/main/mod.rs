//! TUI main entry point and core functionality
//!
//! Contains the main function and core application initialization logic.

extern crate cryypt_vault;

use atty;
use clap::CommandFactory;
use clap_complete::Shell;
use cryypt_vault::logging;
use cryypt_vault::tui;
use cryypt_vault::tui::cli::Cli;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

// Declare submodules
pub mod app;
pub mod events;
pub mod ui;
pub mod commands;

// Re-export key types from submodules
pub use app::*;
pub use events::*;
pub use ui::*;
pub use commands::*;

// Set the application name
const APP_NAME: &str = "cysec";
// Alias name for easier command access
const APP_ALIAS: &str = "secret";

/// Detect current shell and get its type
fn detect_current_shell() -> Option<Shell> {
    // Try to get shell from SHELL environment variable
    if let Ok(shell_path) = std::env::var("SHELL") {
        let shell_name = Path::new(&shell_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");

        return match shell_name {
            "bash" => Some(Shell::Bash),
            "zsh" => Some(Shell::Zsh),
            "fish" => Some(Shell::Fish),
            "elvish" => Some(Shell::Elvish),
            "pwsh" | "powershell" => Some(Shell::PowerShell),
            _ => None,
        };
    }

    // Check for PowerShell on Windows
    #[cfg(windows)]
    {
        if std::env::var("PSModulePath").is_ok() {
            return Some(Shell::PowerShell);
        }
    }

    None
}

/// Get the appropriate completion directory for a shell
fn get_completion_dir(shell: Shell) -> Option<PathBuf> {
    let home = shellexpand::tilde("~").to_string();

    match shell {
        Shell::Bash => {
            // Try standard bash completion directories
            let dirs = [
                format!("{}/.local/share/bash-completion/completions", home),
                format!("{}/.bash_completion.d", home),
            ];

            for dir in dirs {
                let path = PathBuf::from(&dir);
                if path.exists() || fs::create_dir_all(&path).is_ok() {
                    return Some(path);
                }
            }

            // Create default dir if none exists
            let default = PathBuf::from(format!("{}/.bash_completion.d", home));
            if fs::create_dir_all(&default).is_ok() {
                return Some(default);
            }
        }
        Shell::Zsh => {
            // Common zsh completion locations
            let dirs = [
                format!("{}/.zsh/completion", home),
                format!("{}/.zsh/completions", home),
            ];

            for dir in dirs {
                let path = PathBuf::from(&dir);
                if path.exists() || fs::create_dir_all(&path).is_ok() {
                    return Some(path);
                }
            }

            // Create default dir if none exists
            let default = PathBuf::from(format!("{}/.zsh/completion", home));
            if fs::create_dir_all(&default).is_ok() {
                return Some(default);
            }
        }
        Shell::Fish => {
            // Fish completions directory
            let path = PathBuf::from(format!("{}/.config/fish/completions", home));
            if path.exists() || fs::create_dir_all(&path).is_ok() {
                return Some(path);
            }
        }
        Shell::PowerShell => {
            // PowerShell completions directory
            let path = PathBuf::from(format!("{}/.local/share/powershell/completions", home));
            if path.exists() || fs::create_dir_all(&path).is_ok() {
                return Some(path);
            }
        }
        Shell::Elvish => {
            // Elvish completions directory
            let path = PathBuf::from(format!("{}/.elvish/lib", home));
            if path.exists() || fs::create_dir_all(&path).is_ok() {
                return Some(path);
            }
        }
        _ => {}
    }

    None
}

/// Check if completions are already installed for the current shell
fn check_completions(shell: Shell) -> bool {
    let completion_dir = match get_completion_dir(shell) {
        Some(dir) => dir,
        None => return false,
    };

    // Check for completions file based on shell type
    let filename = match shell {
        Shell::Bash => "cysec",
        Shell::Zsh => "_cysec",
        Shell::Fish => "cysec.fish",
        Shell::PowerShell => "cysec.ps1",
        Shell::Elvish => "cysec.elv",
        _ => return false,
    };

    let completion_file = completion_dir.join(filename);
    completion_file.exists()
}

/// Install completions for the given shell
fn install_completions(shell: Shell) -> Result<(), String> {
    let completion_dir = match get_completion_dir(shell) {
        Some(dir) => dir,
        None => {
            return Err(format!(
                "Failed to find or create completions directory for {:?}",
                shell
            ));
        }
    };

    // Create directory if it doesn't exist
    if !completion_dir.exists() {
        fs::create_dir_all(&completion_dir).map_err(|e| {
            format!(
                "Failed to create completions directory {}: {}",
                completion_dir.display(),
                e
            )
        })?;
    }

    // Generate completion script
    let app = Cli::command();
    let filename = match shell {
        Shell::Bash => "cysec",
        Shell::Zsh => "_cysec",
        Shell::Fish => "cysec.fish",
        Shell::PowerShell => "cysec.ps1",
        Shell::Elvish => "cysec.elv",
        _ => {
            return Err(format!("Unsupported shell: {:?}", shell));
        }
    };

    let completion_file = completion_dir.join(filename);
    let mut file = File::create(&completion_file).map_err(|e| {
        format!(
            "Failed to create completions file {}: {}",
            completion_file.display(),
            e
        )
    })?;

    clap_complete::generate(shell, &mut app.clone(), APP_NAME, &mut file);

    // For Zsh, we may need to update fpath or source the file
    if shell == Shell::Zsh {
        eprintln!("To activate Zsh completions, add the following to your .zshrc:");
        eprintln!("fpath=(\"{}\" $fpath)", completion_dir.display());
        eprintln!("autoload -U compinit && compinit");
    }

    Ok(())
}

/// Main entry point for the application
///
/// This function automatically checks for shell completions whenever any command is run,
/// and offers to install them if not present.
pub fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logger
    if let Err(e) = logging::init_logger() {
        eprintln!("Failed to initialize logger: {}", e);
    }

    // Get command line arguments
    let args: Vec<String> = std::env::args().collect();

    // Skip completion check for help and version commands
    let skip_completion = args.len() > 1
        && matches!(
            args[1].as_str(),
            "help" | "--help" | "-h" | "-V" | "--version"
        );

    // Check for completions and handle installation if needed
    if !skip_completion {
        if let Some(shell) = detect_current_shell() {
            if !check_completions(shell) {
                // Completions aren't installed - offer to install them
                println!();
                println!(
                    "Shell completions for cysec are not installed for your current shell ({:?}).",
                    shell
                );
                println!("Would you like to install them now? [y/N]");

                // Check if we're running in an interactive terminal
                if atty::is(atty::Stream::Stdin) {
                    let mut response = String::new();
                    if io::stdin().read_line(&mut response).is_ok()
                        && response.trim().to_lowercase() == "y"
                    {
                        // User wants to install completions
                        match install_completions(shell) {
                            Ok(_) => {
                                println!("Successfully installed completions for {:?}", shell);

                                // Shell-specific activation instructions
                                handle_shell_activation(shell);
                            }
                            Err(e) => {
                                eprintln!("Failed to install completions: {}", e);
                            }
                        }
                    }
                } else {
                    // Non-interactive mode - just show a message
                    println!("Run 'cysec' in an interactive terminal to install completions.");
                }
                println!(); // Extra line for visual separation
            }
        }
    }

    // Run the application - all logic is delegated to tui module
    tui::run()
}

/// Handle shell-specific activation instructions and alias creation
fn handle_shell_activation(shell: Shell) {
    match shell {
        Shell::Bash => handle_bash_activation(),
        Shell::Zsh => handle_zsh_activation(),
        Shell::Fish => handle_fish_activation(),
        Shell::PowerShell => handle_powershell_activation(),
        Shell::Elvish => handle_elvish_activation(),
        _ => {}
    }
}

/// Handle bash shell activation and alias creation
fn handle_bash_activation() {
    println!("To activate the completions, run:");
    if let Some(dir) = get_completion_dir(Shell::Bash) {
        let file_path = dir.join(APP_NAME);
        println!("  source {}", file_path.display());
        println!("Or restart your terminal.");

        // Create alias in bash
        if let Some(home_dir) = dirs::home_dir() {
            let bash_aliases = home_dir.join(".bash_aliases");
            let bashrc = home_dir.join(".bashrc");

            // Write to .bash_aliases if it exists, otherwise try .bashrc
            let target_file = if bash_aliases.exists() {
                bash_aliases
            } else {
                bashrc
            };

            // Check if file exists and we can append to it
            if target_file.exists() {
                println!(
                    "Would you like to create a '{}' alias for the '{}' command? [y/N]",
                    APP_ALIAS, APP_NAME
                );

                let mut response = String::new();
                if io::stdin().read_line(&mut response).is_ok()
                    && response.trim().to_lowercase() == "y"
                {
                    if let Ok(mut file) =
                        std::fs::OpenOptions::new()
                            .append(true)
                            .open(&target_file)
                    {
                        if let Err(e) = writeln!(
                            file,
                            "\n# {} command alias\nalias {}='{}'",
                            APP_NAME, APP_ALIAS, APP_NAME
                        ) {
                            eprintln!(
                                "Failed to write alias: {}",
                                e
                            );
                        } else {
                            println!(
                                "Added '{}' alias to {}",
                                APP_ALIAS,
                                target_file.display()
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Handle zsh shell activation and alias creation  
fn handle_zsh_activation() {
    if let Some(dir) = get_completion_dir(Shell::Zsh) {
        let file_path = dir.join("_cysec");
        println!(
            "To activate the completions in Zsh, add to your .zshrc:"
        );
        println!("  fpath=(\"{}\" $fpath)", dir.display());
        println!("  autoload -U compinit && compinit");

        // Create alias in zsh
        if let Some(home_dir) = dirs::home_dir() {
            let zshrc = home_dir.join(".zshrc");

            if zshrc.exists() {
                println!(
                    "Would you like to create a '{}' alias for the '{}' command? [y/N]",
                    APP_ALIAS, APP_NAME
                );

                let mut response = String::new();
                if io::stdin().read_line(&mut response).is_ok()
                    && response.trim().to_lowercase() == "y"
                {
                    if let Ok(mut file) =
                        std::fs::OpenOptions::new()
                            .append(true)
                            .open(&zshrc)
                    {
                        if let Err(e) = writeln!(
                            file,
                            "\n# {} command alias\nalias {}='{}'",
                            APP_NAME, APP_ALIAS, APP_NAME
                        ) {
                            eprintln!(
                                "Failed to write alias: {}",
                                e
                            );
                        } else {
                            println!(
                                "Added '{}' alias to {}",
                                APP_ALIAS,
                                zshrc.display()
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Handle fish shell activation and alias creation
fn handle_fish_activation() {
    if let Some(dir) = get_completion_dir(Shell::Fish) {
        let file_path = dir.join("cysec.fish");
        println!(
            "To activate the completions in Fish, restart your shell or run:"
        );
        println!("  source {}", file_path.display());

        // Create alias in fish
        if let Some(home_dir) = dirs::home_dir() {
            let fish_config_dir = home_dir.join(".config/fish");
            let fish_aliases = fish_config_dir.join("config.fish");

            if fish_aliases.exists() {
                println!(
                    "Would you like to create a '{}' alias for the '{}' command? [y/N]",
                    APP_ALIAS, APP_NAME
                );

                let mut response = String::new();
                if io::stdin().read_line(&mut response).is_ok()
                    && response.trim().to_lowercase() == "y"
                {
                    if let Ok(mut file) =
                        std::fs::OpenOptions::new()
                            .append(true)
                            .open(&fish_aliases)
                    {
                        if let Err(e) = writeln!(
                            file,
                            "\n# {} command alias\nalias {} '{}'",
                            APP_NAME, APP_ALIAS, APP_NAME
                        ) {
                            eprintln!(
                                "Failed to write alias: {}",
                                e
                            );
                        } else {
                            println!(
                                "Added '{}' alias to {}",
                                APP_ALIAS,
                                fish_aliases.display()
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Handle PowerShell activation and alias creation
fn handle_powershell_activation() {
    if let Some(dir) = get_completion_dir(Shell::PowerShell) {
        let file_path = dir.join(format!("{}.ps1", APP_NAME));
        println!(
            "To activate the completions in PowerShell, run:"
        );
        println!("  . {}", file_path.display());

        // Create alias in PowerShell
        let powershell_profile = dirs::document_dir()
            .map(|d| d.join("WindowsPowerShell/Microsoft.PowerShell_profile.ps1"));

        if let Some(profile_path) = powershell_profile {
            println!(
                "Would you like to create a '{}' alias for the '{}' command? [y/N]",
                APP_ALIAS, APP_NAME
            );

            let mut response = String::new();
            if io::stdin().read_line(&mut response).is_ok()
                && response.trim().to_lowercase() == "y"
            {
                // Create parent directory if it doesn't exist
                if let Some(parent) = profile_path.parent() {
                    if !parent.exists() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                }

                let file_result = if profile_path.exists() {
                    std::fs::OpenOptions::new()
                        .append(true)
                        .open(&profile_path)
                } else {
                    std::fs::File::create(&profile_path)
                };

                if let Ok(mut file) = file_result {
                    if let Err(e) = writeln!(
                        file,
                        "\n# {} command alias\nfunction {} {{ & {} @args }}",
                        APP_NAME, APP_ALIAS, APP_NAME
                    ) {
                        eprintln!(
                            "Failed to write alias: {}",
                            e
                        );
                    } else {
                        println!(
                            "Added '{}' alias to {}",
                            APP_ALIAS,
                            profile_path.display()
                        );
                    }
                }
            }
        }
    }
}

/// Handle Elvish shell activation and alias creation
fn handle_elvish_activation() {
    if let Some(dir) = get_completion_dir(Shell::Elvish) {
        let file_path = dir.join(format!("{}.elv", APP_NAME));
        println!(
            "To activate the completions in Elvish, add to your rc.elv:"
        );
        println!("  use {}", file_path.display());

        // Create alias in Elvish
        if let Some(home_dir) = dirs::home_dir() {
            let elvish_rc = home_dir.join(".elvish/rc.elv");

            if elvish_rc.exists() {
                println!(
                    "Would you like to create a '{}' alias for the '{}' command? [y/N]",
                    APP_ALIAS, APP_NAME
                );

                let mut response = String::new();
                if io::stdin().read_line(&mut response).is_ok()
                    && response.trim().to_lowercase() == "y"
                {
                    if let Ok(mut file) =
                        std::fs::OpenOptions::new()
                            .append(true)
                            .open(&elvish_rc)
                    {
                        if let Err(e) = writeln!(
                            file,
                            "\n# {} command alias\nfn {} [@args]{{ {} @args }}",
                            APP_NAME, APP_ALIAS, APP_NAME
                        ) {
                            eprintln!(
                                "Failed to write alias: {}",
                                e
                            );
                        } else {
                            println!(
                                "Added '{}' alias to {}",
                                APP_ALIAS,
                                elvish_rc.display()
                            );
                        }
                    }
                }
            }
        }
    }
}