//! CRUD operations for vault CLI commands

pub mod delete;
pub mod get;
pub mod put;
pub mod save;

// Re-export all handlers for easy access
pub use delete::handle_delete;
pub use get::handle_get;
pub use put::handle_put;
pub use save::handle_save;
