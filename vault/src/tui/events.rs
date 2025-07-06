use std::io;
use std::time::Duration;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use dialoguer::{Password, theme::ColorfulTheme};
use ratatui::{
    backend::CrosstermBackend,
    Terminal,
};
use crate::core::Vault;
use zeroize::Zeroizing;
use super::app::App;
use super::types::{AppMode, AppTab, InputField};
use super::ui::ui;
use crate::logging::log_security_event;

pub async fn run_tui(vault: Vault) -> Result<(), Box<dyn std::error::Error>> {
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
        execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
        
        println!("Secure Vault - Password Requirements:");
        println!("• Minimum length: 12 characters");
        println!("• Must contain uppercase and lowercase letters");
        println!("• Must contain numbers");
        println!("• Must contain special characters");
        println!("• Should not contain easily guessable information");
        println!("");
        
        let passphrase = Password::with_theme(&ColorfulTheme::default())
            .with_prompt("Enter vault passphrase")
            .interact()?;
        
        app.state.passphrase = Zeroizing::new(passphrase);
        
        // Try to unlock and handle errors properly
        if let Err(err) = app.unlock().await {
            eprintln!("Failed to unlock vault: {}", err);
            return Err(Box::new(err));
        }
        
        enable_raw_mode()?;
        execute!(terminal.backend_mut(), EnterAlternateScreen, EnableMouseCapture)?;
    }

    // Load initial items
    app.reload_items().await;

    let tick_rate = Duration::from_millis(250);
    let mut last_tick = std::time::Instant::now();

    // Main loop
    loop {
        terminal.draw(|f| {
            ui::<CrosstermBackend<std::io::Stdout>>(f, &mut app)
        })?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));
            
        // Check for session timeout
        let timeout_duration = Duration::from_secs(300); // 5 minutes
        if !app.state.is_vault_locked && app.state.last_activity.elapsed() > timeout_duration {
            app.lock().await.ok();
            app.state.error_message = Some("Session timed out due to inactivity".to_string());
            log_security_event("SESSION_TIMEOUT", "Session timed out due to inactivity", true);
        }

        if crossterm::event::poll(timeout)? {
            // Update last activity timestamp on any event
            app.state.last_activity = std::time::Instant::now();
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match &app.mode {
                        AppMode::Normal => match key.code {
                            // Single key exit commands
                            KeyCode::Char('q') => break,
                            KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => break,
                            KeyCode::Char('d') if key.modifiers.contains(event::KeyModifiers::CONTROL) => break,
                            
                            // Search-based commands (activate search mode to check for :q or /quit)
                            KeyCode::Char(':') => {
                                app.state.search_pattern = ":".to_string();
                                app.mode = AppMode::Input(InputField::Search);
                            },
                            KeyCode::Char('/') => {
                                app.state.search_pattern = "/".to_string();
                                app.mode = AppMode::Input(InputField::Search);
                            },
                            KeyCode::Tab => {
                                app.active_tab = match app.active_tab {
                                    AppTab::Keys => AppTab::Search,
                                    AppTab::Search => AppTab::Add,
                                    AppTab::Add => AppTab::Settings,
                                    AppTab::Settings => AppTab::Pass,
                                    AppTab::Pass => AppTab::AwsSecrets,
                                    AppTab::AwsSecrets => AppTab::Help,
                                    AppTab::Help => AppTab::Keys,
                                }
                            }
                            KeyCode::Char('1') => app.active_tab = AppTab::Keys,
                            KeyCode::Char('2') => app.active_tab = AppTab::Search,
                            KeyCode::Char('3') => app.active_tab = AppTab::Add,
                            KeyCode::Char('4') => app.active_tab = AppTab::Settings,
                            KeyCode::Char('5') => app.active_tab = AppTab::Pass,
                            KeyCode::Char('6') => app.active_tab = AppTab::AwsSecrets,
                            KeyCode::Char('7') => app.active_tab = AppTab::Help,
                            KeyCode::Char('s') => {
                                if app.active_tab == AppTab::Search {
                                    app.mode = AppMode::Input(InputField::Search);
                                }
                            }
                            KeyCode::Char('k') => {
                                if app.active_tab == AppTab::Add {
                                    app.mode = AppMode::Input(InputField::NewKey);
                                }
                            }
                            KeyCode::Char('v') => {
                                if app.active_tab == AppTab::Add {
                                    app.mode = AppMode::Input(InputField::NewValue);
                                }
                            }
                            KeyCode::Char('a') => {
                                if app.active_tab == AppTab::Add {
                                    // Use async block directly instead of spawning
                                    app.add_entry().await;
                                }
                            }
                            KeyCode::Char('u') => {
                                if !app.state.is_vault_locked {
                                    // Use async block directly instead of spawning
                                    app.lock().await.ok();
                                } else {
                                    app.mode = AppMode::Input(InputField::Passphrase);
                                }
                            }
                            KeyCode::Char('p') => {
                                if app.active_tab == AppTab::Settings {
                                    app.mode = AppMode::Input(InputField::NewPassphrase);
                                }
                            }
                            KeyCode::Char('c') => {
                                if app.active_tab == AppTab::Settings {
                                    app.mode = AppMode::Input(InputField::ConfirmPassphrase);
                                }
                            }
                            KeyCode::Char('d') => {
                                if app.active_tab == AppTab::Keys || app.active_tab == AppTab::Search {
                                    // Use async block directly instead of spawning
                                    app.delete_selected().await;
                                }
                            }
                            KeyCode::Up => {
                                if app.state.selected_index > 0 {
                                    app.state.selected_index -= 1;
                                }
                            }
                            KeyCode::Down => {
                                let max_index = match app.active_tab {
                                    AppTab::Keys => app.state.vault_items.len(),
                                    AppTab::Search => app.state.search_results.len(),
                                    _ => 0,
                                };
                                if max_index > 0 && app.state.selected_index < max_index - 1 {
                                    app.state.selected_index += 1;
                                }
                            }
                            _ => {}
                        },
                        AppMode::Input(field) => match key.code {
                            KeyCode::Esc => {
                                app.mode = AppMode::Normal;
                            }
                            KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => break,
                            KeyCode::Char('d') if key.modifiers.contains(event::KeyModifiers::CONTROL) => break,
                            KeyCode::Enter => {
                                match field {
                                    InputField::Search => {
                                        // Check for command inputs
                                        if app.state.search_pattern == ":q" || app.state.search_pattern == "/quit" {
                                            break;
                                        }
                                        
                                        // Set mode to normal before executing the search
                                        app.mode = AppMode::Normal;
                                        // Execute the search directly without spawning a task
                                        app.search().await;
                                    }
                                    InputField::Passphrase => {
                                        // Set mode to normal before executing unlock
                                        app.mode = AppMode::Normal;
                                        // Directly call unlock rather than spawning a task
                                        app.unlock().await.ok();
                                    }
                                    InputField::NewPassphrase | InputField::ConfirmPassphrase => {
                                        if app.state.new_passphrase == app.state.confirm_passphrase {
                                            // Set mode to normal before changing passphrase
                                            app.mode = AppMode::Normal;
                                            // Call directly instead of spawning
                                            app.change_passphrase().await;
                                        }
                                    }
                                    _ => {}
                                }
                                app.mode = AppMode::Normal;
                            }
                            KeyCode::Char(c) => {
                                // Check for command input
                                match field {
                                    InputField::Search if app.state.search_pattern.starts_with(":") => {
                                        app.state.search_pattern.push(c);
                                        // Immediately process :q command
                                        if c == 'q' && app.state.search_pattern == ":q" {
                                            break;
                                        }
                                    },
                                    InputField::Search if app.state.search_pattern.starts_with("/") => {
                                        app.state.search_pattern.push(c);
                                        // Check for /quit command
                                        if app.state.search_pattern == "/quit" {
                                            break;
                                        }
                                    },
                                    InputField::Search => app.state.search_pattern.push(c),
                                    InputField::NewKey => app.state.new_key.push(c),
                                    InputField::NewValue => app.state.new_value.push(c),
                                    InputField::Passphrase => app.state.passphrase.push(c),
                                    InputField::NewPassphrase => app.state.new_passphrase.push(c),
                                    InputField::ConfirmPassphrase => app.state.confirm_passphrase.push(c),
                                    InputField::PassStore => app.state.pass.store_path.push(c),
                                    InputField::AwsProfile => app.state.aws.profile.push(c),
                                    InputField::AwsRegion => app.state.aws.region.push(c),
                                    InputField::AwsSearchPattern => app.state.aws.search_pattern.push(c),
                                }
                            }
                            KeyCode::Backspace => {
                                match field {
                                    InputField::Search => { app.state.search_pattern.pop(); }
                                    InputField::NewKey => { app.state.new_key.pop(); }
                                    InputField::NewValue => { app.state.new_value.pop(); }
                                    InputField::Passphrase => { app.state.passphrase.pop(); }
                                    InputField::NewPassphrase => { app.state.new_passphrase.pop(); }
                                    InputField::ConfirmPassphrase => { app.state.confirm_passphrase.pop(); }
                                    InputField::PassStore => { app.state.pass.store_path.pop(); }
                                    InputField::AwsProfile => { app.state.aws.profile.pop(); }
                                    InputField::AwsRegion => { app.state.aws.region.pop(); }
                                    InputField::AwsSearchPattern => { app.state.aws.search_pattern.pop(); }
                                }
                            }
                            _ => {}
                        },
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            last_tick = std::time::Instant::now();
            
            // Clear messages after some time
            app.state.success_message = None;
        }
    }

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
