//! Authentication operations for vault CLI

//! This module provides JWT-based authentication commands for secure vault access.

pub mod login;
pub mod logout;

pub use login::handle_login;
pub use logout::handle_logout;
