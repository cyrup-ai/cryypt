use std::path::{Path, PathBuf};

/// Represents the current state of a vault
#[derive(Debug, Clone)]
pub enum VaultState {
    /// Vault is locked (only .vault file exists)
    Locked {
        vault_file: PathBuf,
        db_file: PathBuf,
    },
    /// Vault is unlocked (only .db file exists)
    Unlocked {
        vault_file: PathBuf,
        db_file: PathBuf,
    },
}

/// Auto-detect vault file state and return appropriate paths
///
/// This function accepts a flexible vault path (with or without extensions)
/// and determines whether the vault is currently locked (.vault file) or
/// unlocked (.db file).
///
/// # Arguments
/// * `vault_path` - Path to vault (can be with or without extension)
///
/// # Returns
/// * `Ok(VaultState)` - Current state with both file paths
/// * `Err(Box<dyn std::error::Error>)` - If neither .vault nor .db exists
///
/// # Examples
/// ```
/// let state = detect_vault_state(Path::new("my_vault"))?;
/// match state {
///     VaultState::Locked { vault_file, db_file } => {
///         println!("Vault is locked at: {}", vault_file.display());
///     }
///     VaultState::Unlocked { vault_file, db_file } => {
///         println!("Vault is unlocked at: {}", db_file.display());
///     }
/// }
/// ```
pub fn detect_vault_state(vault_path: &Path) -> Result<VaultState, Box<dyn std::error::Error>> {
    // Remove any existing extension to get base path
    let base_path = vault_path.with_extension("");
    let vault_file = base_path.with_extension("vault");
    let db_file = base_path.with_extension("db");

    // Check .vault first (locked state)
    if vault_file.exists() {
        Ok(VaultState::Locked {
            vault_file,
            db_file,
        })
    } else if db_file.exists() {
        Ok(VaultState::Unlocked {
            vault_file,
            db_file,
        })
    } else {
        Err(format!(
            "No vault found at '{}' (checked {} and {})",
            base_path.display(),
            vault_file.display(),
            db_file.display()
        )
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use tempfile::tempdir;

    #[test]
    fn test_detect_locked_vault() {
        let temp_dir = tempdir().unwrap();
        let vault_file = temp_dir.path().join("test.vault");
        File::create(&vault_file).unwrap();

        let state = detect_vault_state(&temp_dir.path().join("test")).unwrap();
        match state {
            VaultState::Locked {
                vault_file: vf,
                db_file: _,
            } => {
                assert_eq!(vf, vault_file);
            }
            _ => panic!("Expected locked state"),
        }
    }

    #[test]
    fn test_detect_unlocked_vault() {
        let temp_dir = tempdir().unwrap();
        let db_file = temp_dir.path().join("test.db");
        File::create(&db_file).unwrap();

        let state = detect_vault_state(&temp_dir.path().join("test")).unwrap();
        match state {
            VaultState::Unlocked {
                vault_file: _,
                db_file: df,
            } => {
                assert_eq!(df, db_file);
            }
            _ => panic!("Expected unlocked state"),
        }
    }

    #[test]
    fn test_no_vault_found() {
        let temp_dir = tempdir().unwrap();
        let result = detect_vault_state(&temp_dir.path().join("nonexistent"));
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No vault found"));
    }
}
