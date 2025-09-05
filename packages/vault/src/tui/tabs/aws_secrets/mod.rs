//! AWS Secrets Manager tab rendering modules

pub mod create_form;
pub mod help_text;
pub mod list_view;
pub mod main_render;
pub mod search;
pub mod update_form;
pub mod view_mode;

// Re-export main render function for easy access
pub use main_render::render_aws_secrets_tab;
