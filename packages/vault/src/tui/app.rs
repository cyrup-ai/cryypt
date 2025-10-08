use super::types::{AppMode, AppState, AppTab};
use crate::core::Vault;
use crate::error::VaultError;
use crate::logging::log_security_event;
use tokio_stream::StreamExt;
use zeroize::Zeroizing;

pub struct App {
    pub active_tab: AppTab,
    pub mode: AppMode,
    pub state: AppState,
    pub vault: Vault,
}

impl App {
    pub async fn new(vault: Vault) -> App {
        App {
            active_tab: AppTab::Keys,
            mode: AppMode::Normal,
            state: AppState {
                is_vault_locked: vault.is_locked().await,
                ..Default::default()
            },
            vault,
        }
    }

    pub async fn unlock(&mut self) -> Result<(), VaultError> {
        self.state.error_message = None;

        // Rate limiting for failed unlock attempts
        let now = std::time::Instant::now();
        if self.state.failed_unlock_attempts >= 5 {
            let cooldown = std::time::Duration::from_secs(30);
            if now.duration_since(self.state.last_unlock_attempt) < cooldown {
                let remaining = cooldown - now.duration_since(self.state.last_unlock_attempt);
                self.state.error_message = Some(format!(
                    "Too many failed attempts. Try again in {} seconds",
                    remaining.as_secs()
                ));
                log_security_event(
                    "TUI_UNLOCK",
                    "Rate limited: too many failed attempts",
                    false,
                );
                return Err(VaultError::TooManyAttempts(remaining));
            } else {
                // Reset counter after cooldown period
                self.state.failed_unlock_attempts = 0;
            }
        }

        self.state.last_unlock_attempt = now;

        // Attempt to unlock the vault
        match self.vault.unlock(self.state.passphrase.as_str()).await {
            Ok(_) => {
                self.state.is_vault_locked = false;
                self.state.success_message = Some("Vault unlocked successfully".to_string());
                // Clear passphrase from memory
                self.state.passphrase = Zeroizing::new(String::new());
                self.state.failed_unlock_attempts = 0;
                self.reload_items().await;
                // Reset last activity timestamp
                self.state.last_activity = std::time::Instant::now();
                log_security_event("TUI_UNLOCK", "Vault unlocked via TUI", true);
                Ok(())
            }
            Err(err) => {
                self.state.failed_unlock_attempts += 1;
                self.state.error_message = Some(format!("Failed to unlock vault: {err}"));
                log_security_event(
                    "TUI_UNLOCK",
                    &format!("Failed to unlock vault: {err}"),
                    false,
                );
                Err(err)
            }
        }
    }

    pub async fn lock(&mut self) -> Result<(), VaultError> {
        self.state.error_message = None;
        match self.vault.lock().await {
            Ok(_) => {
                self.state.is_vault_locked = true;
                self.state.vault_items.clear();
                self.state.success_message = Some("Vault locked successfully".to_string());
                log_security_event("TUI_LOCK", "Vault locked via TUI", true);
                Ok(())
            }
            Err(err) => {
                self.state.error_message = Some(format!("Failed to lock vault: {err}"));
                log_security_event("TUI_LOCK", &format!("Failed to lock vault: {err}"), false);
                Err(err)
            }
        }
    }

    pub async fn reload_items(&mut self) {
        if self.state.is_vault_locked {
            self.state.error_message = Some("Failed to load items: Vault locked".to_string());
            return;
        }

        let stream_result = self.vault.find(".*").await;
        let mut stream = match stream_result {
            Ok(s) => s,
            Err(err) => {
                self.state.error_message = Some(format!("Failed to start search: {err}"));
                return;
            }
        };
        let mut items = Vec::new();

        while let Some(result) = stream.next().await {
            match result {
                Ok(item) => items.push(item),
                Err(err) => {
                    self.state.error_message = Some(format!("Failed to load items: {err}"));
                    return;
                }
            }
        }

        self.state.vault_items = items;
    }

    pub async fn search(&mut self) {
        if self.state.is_vault_locked {
            return;
        }

        if self.state.search_pattern.is_empty() {
            self.state.search_results = self.state.vault_items.clone();
            return;
        }

        let stream_result = self.vault.find(&self.state.search_pattern).await;
        let mut stream = match stream_result {
            Ok(s) => s,
            Err(err) => {
                self.state.error_message = Some(format!("Failed to start search: {err}"));
                return;
            }
        };
        let mut items = Vec::new();

        while let Some(result) = stream.next().await {
            match result {
                Ok(item) => items.push(item),
                Err(err) => {
                    self.state.error_message = Some(format!("Failed to search: {err}"));
                    return;
                }
            }
        }

        self.state.search_results = items;
    }

    pub async fn add_entry(&mut self) {
        if self.state.is_vault_locked {
            self.state.error_message = Some("Vault is locked".to_string());
            return;
        }

        if self.state.new_key.is_empty() {
            self.state.error_message = Some("Key cannot be empty".to_string());
            return;
        }

        self.state.error_message = None;
        let key_str = self.state.new_key.as_str();
        let value_str = self.state.new_value.as_str();

        match self.vault.put(key_str, value_str).await {
            Ok(_) => {
                self.state.success_message = Some(format!("Added entry for key '{}'", key_str));
                log_security_event(
                    "ADD_ENTRY",
                    &format!("Added entry for key '{}'", key_str),
                    true,
                );
                self.state.new_key = Zeroizing::new(String::new());
                self.state.new_value = Zeroizing::new(String::new());
                self.reload_items().await;
            }
            Err(err) => {
                self.state.error_message = Some(format!("Failed to add entry: {err}"));
                log_security_event("ADD_ENTRY", &format!("Failed to add entry: {err}"), false);
            }
        }
    }

    pub async fn delete_selected(&mut self) {
        if self.state.is_vault_locked {
            return;
        }

        let items = match self.active_tab {
            AppTab::Keys => &self.state.vault_items,
            AppTab::Search => &self.state.search_results,
            _ => return,
        };

        if self.state.selected_index >= items.len() {
            return;
        }

        let (key, _) = &items[self.state.selected_index];

        self.state.error_message = None;
        match self.vault.delete(key).await {
            Ok(_) => {
                self.state.success_message = Some(format!("Deleted entry for key '{}'", key));
                log_security_event(
                    "DELETE_ENTRY",
                    &format!("Deleted entry for key '{}'", key),
                    true,
                );
                // Store the current items first to avoid borrow issues
                let was_empty = self.state.vault_items.is_empty();
                self.reload_items().await;
                // Adjust selected index but don't go below 0
                if self.state.selected_index > 0 && !was_empty {
                    self.state.selected_index -= 1;
                }
            }
            Err(err) => {
                self.state.error_message = Some(format!("Failed to delete entry: {err}"));
                log_security_event(
                    "DELETE_ENTRY",
                    &format!("Failed to delete entry: {err}"),
                    false,
                );
            }
        }
    }

    pub async fn change_passphrase(&mut self) {
        if self.state.is_vault_locked {
            self.state.error_message = Some("Vault is locked".to_string());
            return;
        }

        if *self.state.new_passphrase != *self.state.confirm_passphrase {
            self.state.error_message = Some("Passphrases don't match".to_string());
            return;
        }

        if self.state.new_passphrase.len() < 12 {
            self.state.error_message =
                Some("Passphrase must be at least 12 characters".to_string());
            return;
        }

        // Use the vault's change_passphrase method
        match self
            .vault
            .change_passphrase(
                self.state.passphrase.as_str(),
                self.state.new_passphrase.as_str(),
            )
            .await
        {
            Ok(_) => {
                self.state.success_message = Some("Passphrase changed successfully".to_string());
                self.state.new_passphrase = Zeroizing::new(String::new());
                self.state.confirm_passphrase = Zeroizing::new(String::new());
                log_security_event("PASSPHRASE_CHANGE", "Passphrase changed successfully", true);
            }
            Err(err) => {
                self.state.error_message = Some(format!("Failed to change passphrase: {err}"));
                log_security_event(
                    "PASSPHRASE_CHANGE",
                    &format!("Failed to change passphrase: {err}"),
                    false,
                );
            }
        }
    }

    /// Create a PassInterface for password operations
    pub async fn create_pass_interface(
        &self,
    ) -> Result<crate::tui::pass_interface::PassInterface, VaultError> {
        use std::path::PathBuf;

        // Use the pass store path from app state, or create a default one
        let pass_store_path = if self.state.pass.store_path.is_empty() {
            // Create default pass store path in the same directory as the vault
            let mut default_path = PathBuf::from("~/.password-store");
            if let Ok(home) = std::env::var("HOME") {
                default_path = PathBuf::from(home).join(".password-store");
            }
            default_path
        } else {
            PathBuf::from(&self.state.pass.store_path)
        };

        crate::tui::pass_interface::PassInterface::from_path(pass_store_path).await
    }
}
