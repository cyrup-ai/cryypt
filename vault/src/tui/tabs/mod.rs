pub mod add;
pub mod aws_secrets;
pub mod help;
pub mod keys;
pub mod pass;
pub mod search;
pub mod settings;

pub use add::render_add_tab;
pub use aws_secrets::render_aws_secrets_tab;
pub use help::render_help_tab;
pub use keys::render_keys_tab;
pub use pass::render_pass_tab;
pub use search::render_search_tab;
pub use settings::render_settings_tab;
