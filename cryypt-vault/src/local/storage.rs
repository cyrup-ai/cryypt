use rand::Rng;
use std::fs;
use std::path::Path;
use std::io::{Seek, SeekFrom, Write};

use crate::config::VaultConfig;
use crate::error::{VaultError, VaultResult};

pub fn ensure_salt_file(config: &VaultConfig) -> VaultResult<()> {
    // Ensure salt file exists with proper permissions
    if !Path::new(&config.salt_path).exists() {
        let mut salt = [0u8; 16];
        rand::rng().fill(&mut salt);
        fs::write(&config.salt_path, &salt).map_err(VaultError::Io)?;

        // Set appropriate file permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&config.salt_path)
                .map_err(VaultError::Io)?
                .permissions();
            perms.set_mode(0o600); // Read/write for owner only
            fs::set_permissions(&config.salt_path, perms).map_err(VaultError::Io)?;
        }
    }
    Ok(())
}

pub fn read_salt(config: &VaultConfig) -> VaultResult<Vec<u8>> {
    let salt = fs::read(&config.salt_path).map_err(VaultError::Io)?;
    
    // Validate salt length
    if salt.len() < 16 {
        return Err(VaultError::KeyDerivation("Salt too short".into()));
    }
    
    Ok(salt)
}

pub fn read_vault_data(config: &VaultConfig) -> VaultResult<Vec<u8>> {
    if Path::new(&config.vault_path).exists() {
        let encrypted_data = fs::read(&config.vault_path).map_err(VaultError::Io)?;
        
        // Set appropriate file permissions for vault file
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&config.vault_path)
                .map_err(VaultError::Io)?
                .permissions();
            perms.set_mode(0o600); // Read/write for owner only
            fs::set_permissions(&config.vault_path, perms).map_err(VaultError::Io)?;
        }
        
        Ok(encrypted_data)
    } else {
        Ok(Vec::new()) // Return empty vec if no vault file exists yet
    }
}

pub fn write_vault_data(config: &VaultConfig, encrypted_data: Vec<u8>) -> VaultResult<()> {
    // If file exists, securely overwrite it
    if Path::new(&config.vault_path).exists() {
        secure_overwrite(&config.vault_path).map_err(VaultError::Io)?;
    }

    fs::write(&config.vault_path, encrypted_data).map_err(VaultError::Io)?;

    // Set appropriate file permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&config.vault_path)
            .map_err(VaultError::Io)?
            .permissions();
        perms.set_mode(0o600); // Read/write for owner only
        fs::set_permissions(&config.vault_path, perms).map_err(VaultError::Io)?;
    }

    Ok(())
}

fn secure_overwrite(path: &Path) -> std::io::Result<()> {
    let metadata = fs::metadata(path)?;
    let file_size = metadata.len();

    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;

    // Overwrite with zeros
    let zeros = vec![0u8; 4096];
    let mut remaining = file_size;

    while remaining > 0 {
        let to_write = std::cmp::min(remaining, 4096);
        file.write_all(&zeros[..to_write as usize])?;
        remaining -= to_write;
    }

    file.flush()?;
    file.seek(SeekFrom::Start(0))?;

    // Overwrite with ones
    let ones = vec![0xFFu8; 4096];
    let mut remaining = file_size;

    while remaining > 0 {
        let to_write = std::cmp::min(remaining, 4096);
        file.write_all(&ones[..to_write as usize])?;
        remaining -= to_write;
    }

    file.flush()?;
    file.sync_all()?;
    Ok(())
}