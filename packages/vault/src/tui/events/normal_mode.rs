//! Normal mode key handling for TUI

use super::super::app::App;
use super::super::types::{AppMode, AppTab, InputField};
use crossterm::event::{self, KeyCode};

pub async fn handle_normal_mode_key(
    app: &mut App,
    key_code: KeyCode,
    modifiers: event::KeyModifiers,
) -> bool {
    match key_code {
        // Single key exit commands
        KeyCode::Char('q') => return true,
        KeyCode::Char('c') if modifiers.contains(event::KeyModifiers::CONTROL) => return true,
        KeyCode::Char('d') if modifiers.contains(event::KeyModifiers::CONTROL) => return true,

        // Search-based commands (activate search mode to check for :q or /quit)
        KeyCode::Char(':') => {
            app.state.search_pattern = ":".to_string();
            app.mode = AppMode::Input(InputField::Search);
        }
        KeyCode::Char('/') => {
            app.state.search_pattern = "/".to_string();
            app.mode = AppMode::Input(InputField::Search);
        }
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
                app.add_entry().await;
            }
        }
        KeyCode::Char('u') => {
            if !app.state.is_vault_locked {
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
    }
    false
}
