//! Vault operations for CLI commands - decomposed modules

// Re-export all functions from sibling modules
pub use super::crud_operations::{handle_delete, handle_get, handle_put, handle_save};
pub use super::passphrase_operations::handle_change_passphrase;
pub use super::query_operations::{handle_find, handle_list};
pub use super::unlock_operations::ensure_unlocked;
