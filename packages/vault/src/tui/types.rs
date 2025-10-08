use crate::aws_interface::{AwsSecretManager, SecretSummary};
use crate::core::VaultValue;
use crate::pass_interface::PassInterface;
use std::fmt;
use std::time::Instant;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppTab {
    Keys = 0,
    Search = 1,
    Add = 2,
    Settings = 3,
    Pass = 4,
    AwsSecrets = 5,
    Help = 6,
}

impl fmt::Display for AppTab {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppTab::Keys => write!(f, "Keys"),
            AppTab::Search => write!(f, "Search"),
            AppTab::Add => write!(f, "Add"),
            AppTab::Settings => write!(f, "Settings"),
            AppTab::Pass => write!(f, "Pass"),
            AppTab::AwsSecrets => write!(f, "AWS"),
            AppTab::Help => write!(f, "Help"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputField {
    Search,
    NewKey,
    NewValue,
    Passphrase,
    NewPassphrase,
    ConfirmPassphrase,
    PassStore,
    AwsProfile,
    AwsRegion,
    AwsSearchPattern,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppMode {
    Normal,
    Input(InputField),
}

#[derive(Debug)]
pub struct AppState {
    pub is_vault_locked: bool,
    pub vault_items: Vec<(String, VaultValue)>,
    pub search_pattern: String,
    pub search_results: Vec<(String, VaultValue)>,
    pub selected_index: usize,
    pub new_key: Zeroizing<String>,
    pub new_value: Zeroizing<String>,
    pub passphrase: Zeroizing<String>,
    pub new_passphrase: Zeroizing<String>,
    pub confirm_passphrase: Zeroizing<String>,
    pub error_message: Option<String>,
    pub success_message: Option<String>,
    pub last_activity: Instant,
    pub failed_unlock_attempts: usize,
    pub last_unlock_attempt: Instant,
    pub argon2_memory_cost: u32,
    pub argon2_time_cost: u32,
    pub argon2_parallelism: u32,

    // Pass password manager state
    pub pass: PassState,

    // AWS Secrets Manager state
    pub aws: AwsSecretsManagerState,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            is_vault_locked: true,
            vault_items: Vec::new(),
            search_pattern: String::new(),
            search_results: Vec::new(),
            selected_index: 0,
            new_key: Zeroizing::new(String::new()),
            new_value: Zeroizing::new(String::new()),
            passphrase: Zeroizing::new(String::new()),
            new_passphrase: Zeroizing::new(String::new()),
            confirm_passphrase: Zeroizing::new(String::new()),
            error_message: None,
            success_message: None,
            last_activity: Instant::now(),
            failed_unlock_attempts: 0,
            last_unlock_attempt: Instant::now(),
            argon2_memory_cost: 16384,
            argon2_time_cost: 3,
            argon2_parallelism: 4,

            // Pass password manager state
            pass: PassState::default(),

            // AWS Secrets Manager state
            aws: AwsSecretsManagerState::default(),
        }
    }
}

// Pass password store state enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PassStateMode {
    #[default]
    List,
    View,
    Search,
}

// AWS Secrets Manager state enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AwsSecretsStateMode {
    #[default]
    List,
    View,
    Search,
    Create,
    Update,
}

// Pass password store state
#[derive(Debug, Default)]
pub struct PassState {
    pub mode: PassStateMode,
    pub store_path: String,
    pub entries: Vec<String>,
    pub selected_index: usize,
    pub content: Option<Zeroizing<String>>,
    pub search_query: String,
    pub search_results: Vec<String>,
    pub status_message: String,
    pub interface: Option<PassInterface>,
}

// AWS Secrets Manager state
#[derive(Debug, Default)]
pub struct AwsSecretsManagerState {
    pub mode: AwsSecretsStateMode,
    pub profile: String,
    pub region: String,
    pub client: Option<AwsSecretManager>,
    pub secrets: Vec<SecretSummary>,
    pub selected_index: usize,
    pub current_secret: String,
    pub search_query: String,
    pub search_results: Vec<SecretSummary>,
    pub status_message: String,
    pub create_field_index: usize,
    pub new_secret_name: String,
    pub new_secret_value: String,
    pub new_secret_description: String,
    pub update_secret_value: String,
    pub search_pattern: String,
}

// Zeroizing<String> handles memory clearing automatically
