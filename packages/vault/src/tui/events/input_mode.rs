//! Input mode key handling for TUI

use super::super::app::App;
use super::super::types::{AppMode, InputField};
use crossterm::event::{self, KeyCode};

pub async fn handle_input_mode_key(
    app: &mut App,
    field: &InputField,
    key_code: KeyCode,
    modifiers: event::KeyModifiers,
) -> bool {
    match key_code {
        KeyCode::Esc => {
            app.mode = AppMode::Normal;
        }
        KeyCode::Char('c') if modifiers.contains(event::KeyModifiers::CONTROL) => return true,
        KeyCode::Char('d') if modifiers.contains(event::KeyModifiers::CONTROL) => return true,
        KeyCode::Enter => {
            match field {
                InputField::Search => {
                    // Check for command inputs
                    if app.state.search_pattern == ":q" || app.state.search_pattern == "/quit" {
                        return true;
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
            handle_character_input(app, field, c);
            // Check for immediate exit commands
            if matches!(field, InputField::Search)
                && ((app.state.search_pattern.starts_with(":")
                    && c == 'q'
                    && app.state.search_pattern == ":q")
                    || app.state.search_pattern == "/quit")
            {
                return true;
            }
        }
        KeyCode::Backspace => {
            handle_backspace(app, field);
        }
        _ => {}
    }
    false
}

fn handle_character_input(app: &mut App, field: &InputField, c: char) {
    match field {
        InputField::Search if app.state.search_pattern.starts_with(":") => {
            app.state.search_pattern.push(c);
        }
        InputField::Search if app.state.search_pattern.starts_with("/") => {
            app.state.search_pattern.push(c);
        }
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

fn handle_backspace(app: &mut App, field: &InputField) {
    match field {
        InputField::Search => {
            app.state.search_pattern.pop();
        }
        InputField::NewKey => {
            app.state.new_key.pop();
        }
        InputField::NewValue => {
            app.state.new_value.pop();
        }
        InputField::Passphrase => {
            app.state.passphrase.pop();
        }
        InputField::NewPassphrase => {
            app.state.new_passphrase.pop();
        }
        InputField::ConfirmPassphrase => {
            app.state.confirm_passphrase.pop();
        }
        InputField::PassStore => {
            app.state.pass.store_path.pop();
        }
        InputField::AwsProfile => {
            app.state.aws.profile.pop();
        }
        InputField::AwsRegion => {
            app.state.aws.region.pop();
        }
        InputField::AwsSearchPattern => {
            app.state.aws.search_pattern.pop();
        }
    }
}
