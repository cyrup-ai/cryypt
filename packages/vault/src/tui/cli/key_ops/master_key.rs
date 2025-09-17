//! Master key derivation utilities for vault operations

use crate::core::Vault;
use cryypt_key::api::key_generator::derive::{KdfAlgorithm, KdfConfig, KeyDerivation};

use rpassword::read_password;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure wrapper for master key material with automatic memory cleanup
#[derive(ZeroizeOnDrop)]
struct SecureMasterKey {
    key: [u8; 32],
}

impl SecureMasterKey {
    fn new(key: [u8; 32]) -> Self {
        Self { key }
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

/// Generate secure salt for master key derivation
/// Uses cryptographically secure random number generator
fn generate_secure_salt() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut salt = vec![0u8; 32];
    fastrand::fill(&mut salt);
    Ok(salt)
}

/// Get default vault configuration directory
/// Uses system-appropriate location for vault configuration
fn get_vault_config_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut config_dir = if let Ok(xdg_config) = std::env::var("XDG_CONFIG_HOME") {
        PathBuf::from(xdg_config)
    } else if let Ok(home) = std::env::var("HOME") {
        let mut home_path = PathBuf::from(home);
        home_path.push(".config");
        home_path
    } else {
        return Err("Unable to determine configuration directory".into());
    };

    config_dir.push("cryypt");
    config_dir.push("vault");

    // Ensure directory exists
    fs::create_dir_all(&config_dir)?;

    Ok(config_dir)
}

/// Store salt securely to vault configuration directory
/// Creates vault-specific salt file with proper permissions
fn store_vault_salt(salt: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut salt_path = get_vault_config_dir()?;
    salt_path.push(".cryypt_salt");

    fs::write(&salt_path, salt)?;

    // Set restrictive permissions (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = std::fs::Permissions::from_mode(0o600); // Owner read/write only
        fs::set_permissions(&salt_path, permissions)?;
    }

    Ok(())
}

/// Retrieve stored salt from vault configuration directory
/// Returns existing salt or generates new one if not found
fn retrieve_vault_salt() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut salt_path = get_vault_config_dir()?;
    salt_path.push(".cryypt_salt");

    if salt_path.exists() {
        let salt = fs::read(&salt_path)?;
        if salt.len() == 32 {
            return Ok(salt);
        }
        // Invalid salt file, regenerate
    }

    // Generate new salt and store it
    let salt = generate_secure_salt()?;
    store_vault_salt(&salt)?;
    Ok(salt)
}

/// Prompt user for secure passphrase input
/// Uses rpassword for secure terminal input without echo
fn prompt_for_passphrase() -> Result<String, Box<dyn std::error::Error>> {
    print!("Enter vault master passphrase: ");
    io::stdout().flush()?; // Ensure prompt appears before password input

    let passphrase = read_password()?;

    if passphrase.is_empty() {
        return Err("Passphrase cannot be empty".into());
    }

    if passphrase.len() < 8 {
        return Err("Passphrase must be at least 8 characters".into());
    }

    Ok(passphrase)
}

/// Derive a secure master key from vault passphrase
/// Uses Argon2id with production-strength parameters and secure salt generation
pub async fn derive_master_key_from_vault(
    _vault: &Vault,
    passphrase_option: Option<&str>,
) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    // Retrieve or generate cryptographically secure salt
    let salt = retrieve_vault_salt()?;

    // Get passphrase from parameter or prompt user
    let mut passphrase = match passphrase_option {
        Some(pass) => pass.to_string(),
        None => prompt_for_passphrase()?,
    };

    // Use high-security KDF configuration for master key derivation
    let config = KdfConfig {
        algorithm: KdfAlgorithm::Argon2id,
        iterations: 3,      // Time cost for Argon2id
        memory_cost: 65536, // 64MB memory cost
        parallelism: 4,     // 4-way parallelism
        salt_size: 32,
        output_size: 32,
    };

    // Derive key using secure passphrase and salt
    let kdf = KeyDerivation::new(config).with_salt(salt);
    let derived_key = kdf
        .derive_key(passphrase.as_bytes())
        .map_err(|e| format!("Master key derivation failed: {e}"))?;

    // Securely clear passphrase from memory
    passphrase.zeroize();

    // Convert to fixed-size array with secure memory handling
    let mut master_key_bytes = [0u8; 32];
    master_key_bytes.copy_from_slice(&derived_key[..32]);

    let secure_key = SecureMasterKey::new(master_key_bytes);
    let result = *secure_key.as_bytes();

    // SecureMasterKey automatically zeroizes on drop
    Ok(result)
}
