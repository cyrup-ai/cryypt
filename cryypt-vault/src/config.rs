use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    pub vault_path: PathBuf,
    pub salt_path: PathBuf,
    #[serde(default = "default_memory_cost")]
    pub argon2_memory_cost: u32,
    #[serde(default = "default_time_cost")]
    pub argon2_time_cost: u32,
    #[serde(default = "default_parallelism")]
    pub argon2_parallelism: u32,
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

impl Default for VaultConfig {
    fn default() -> Self {
        // Use XDG_DATA_HOME or ~/.local/share for data storage
        // This follows the XDG Base Directory Specification
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| {
                let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("~"));
                home.join(".local/share")
            })
            .join("cysec");
        
        // Create the directory if it doesn't exist
        if !data_dir.exists() {
            if let Err(e) = std::fs::create_dir_all(&data_dir) {
                eprintln!("Warning: Failed to create data directory: {}", e);
            }
        }
        
        // Set appropriate permissions on Unix systems
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(metadata) = std::fs::metadata(&data_dir) {
                let mut perms = metadata.permissions();
                perms.set_mode(0o700); // rwx------ (only owner can access)
                let _ = std::fs::set_permissions(&data_dir, perms);
            }
        }
        
        Self {
            vault_path: data_dir.join("cysec.db"),
            salt_path: data_dir.join("cysec.salt"),
            argon2_memory_cost: default_memory_cost(),
            argon2_time_cost: default_time_cost(),
            argon2_parallelism: default_parallelism(),
        }
    }
}
