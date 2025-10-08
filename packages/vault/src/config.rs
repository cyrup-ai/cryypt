use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::warn;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultConfig {
    pub vault_path: PathBuf,
    // salt_path removed - salt now stored encrypted in SurrealDB
    #[serde(default = "default_memory_cost")]
    pub argon2_memory_cost: u32,
    #[serde(default = "default_time_cost")]
    pub argon2_time_cost: u32,
    #[serde(default = "default_parallelism")]
    pub argon2_parallelism: u32,
    /// TTL cleanup interval in seconds (0 disables cleanup)
    #[serde(default = "default_ttl_cleanup_interval")]
    pub ttl_cleanup_interval_seconds: u64,
    /// Keychain configuration for PQCrypto keys
    #[serde(default)]
    pub keychain_config: KeychainConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeychainConfig {
    pub app_name: String,     // "vault"
    pub pq_namespace: String, // "pq_armor"
    pub auto_generate: bool,  // true - generate PQ keys on first use
}

impl Default for KeychainConfig {
    fn default() -> Self {
        Self {
            app_name: "vault".to_string(),
            pq_namespace: "pq_armor".to_string(),
            auto_generate: true,
        }
    }
}

fn default_memory_cost() -> u32 {
    64 * 1024 // 64 MB
}

fn default_time_cost() -> u32 {
    3
}

fn default_parallelism() -> u32 {
    4
}

fn default_ttl_cleanup_interval() -> u64 {
    3600 // 1 hour in seconds
}

impl Default for VaultConfig {
    fn default() -> Self {
        // Use proper OS-specific config directory
        let config_dir = match dirs::config_dir() {
            Some(mut dir) => {
                dir.push("cryypt");
                dir
            }
            None => {
                // Fallback to current directory if config dir unavailable
                warn!("Could not determine OS config directory, using ./cryypt");
                PathBuf::from("./cryypt")
            }
        };

        // Create the directory if it doesn't exist
        if !config_dir.exists()
            && let Err(e) = std::fs::create_dir_all(&config_dir)
        {
            warn!(
                path = %config_dir.display(),
                error = %e,
                "Failed to create config directory"
            );
        }

        // Set appropriate permissions on Unix systems
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&config_dir) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o700); // rwx------ (only owner can access)
                let _ = std::fs::set_permissions(&config_dir, perms);
            }
        }

        Self {
            vault_path: config_dir.join("vault.db"),
            // salt_path removed - salt now stored encrypted in SurrealDB
            argon2_memory_cost: default_memory_cost(),
            argon2_time_cost: default_time_cost(),
            argon2_parallelism: default_parallelism(),
            ttl_cleanup_interval_seconds: default_ttl_cleanup_interval(),
            keychain_config: KeychainConfig::default(),
        }
    }
}
