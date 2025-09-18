//! Authentication operations for vault CLI
//!
//! This module provides JWT-based authentication commands for secure vault access.

pub mod login;

pub use login::{handle_login, handle_logout};