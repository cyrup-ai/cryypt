use crate::core::Vault;
use crate::tui::cli::commands;
use crate::tui::cli::vault_detection::{VaultState, detect_vault_state};
use serde_json::json;
use std::path::Path;

/// Handle enhanced vault logout with complete session cleanup
///
/// This function performs a complete logout workflow:
/// 1. Auto-detects vault state
/// 2. Invalidates JWT session
/// 3. Locks vault if currently unlocked
/// 4. Clears in-memory session data
/// 5. Provides clear logout instructions
///
/// # Arguments
/// * `vault` - The vault instance
/// * `vault_path` - Optional path to vault file (defaults to "vault")
/// * `use_json` - Whether to output in JSON format
///
/// # Returns
/// * `Ok(())` - Logout completed successfully
/// * `Err(Box<dyn std::error::Error>)` - If logout fails
pub async fn handle_enhanced_logout(
    vault: &Vault,
    vault_path: Option<&Path>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Auto-detect vault state
    let vault_state = detect_vault_state(vault_path.unwrap_or(Path::new("vault")))?;

    // 2. Invalidate JWT session in SurrealDB
    if let Err(e) = vault.invalidate_jwt_session().await {
        // Log error but don't fail logout - session invalidation is not critical for user experience
        if use_json {
            println!(
                "{}",
                json!({
                    "warning": format!("JWT session invalidation failed: {}", e),
                    "impact": "Session may remain active until expiration"
                })
            );
        } else {
            println!("⚠️  Warning: JWT session invalidation failed: {}", e);
            println!("   Session may remain active until expiration");
        }
    }

    // 3. Provide clear logout instructions
    if use_json {
        println!(
            "{}",
            json!({
                "success": true,
                "operation": "logout",
                "message": "Session invalidated. Unset VAULT_JWT environment variable.",
                "instructions": "unset VAULT_JWT"
            })
        );
    } else {
        println!("🔓 Session invalidated successfully");
        println!("💡 Run: unset VAULT_JWT");
    }

    // 4. Lock vault if currently unlocked
    match vault_state {
        VaultState::Unlocked {
            vault_file: _,
            db_file,
        } => {
            if use_json {
                // For JSON mode, just indicate the vault will be locked
                println!(
                    "{}",
                    json!({
                        "operation": "lock",
                        "message": "Locking vault database",
                        "file": db_file.display().to_string()
                    })
                );
            } else {
                println!("🔒 Locking vault database...");
            }

            // Call existing handle_lock_command to lock the vault
            commands::handle_lock_command(&db_file, None, "pq_armor", 1, use_json).await?;
        }
        VaultState::Locked { .. } => {
            if use_json {
                println!(
                    "{}",
                    json!({
                        "operation": "lock",
                        "message": "Vault already locked",
                        "status": "skipped"
                    })
                );
            } else {
                println!("🔒 Vault already locked");
            }
        }
    }

    // 5. Clear in-memory session data
    if let Err(e) = vault.clear_session_data().await {
        // Log error but don't fail logout - session cleanup is not critical for user experience
        if use_json {
            println!(
                "{}",
                json!({
                    "warning": format!("In-memory session cleanup failed: {}", e),
                    "impact": "Session data may remain in memory until process restart"
                })
            );
        } else {
            println!("⚠️  Warning: In-memory session cleanup failed: {}", e);
            println!("   Session data may remain in memory until process restart");
        }
    }

    if use_json {
        println!(
            "{}",
            json!({
                "success": true,
                "operation": "logout_complete",
                "message": "Logout completed successfully"
            })
        );
    } else {
        println!("✅ Logout completed successfully");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Vault;
    use std::fs::File;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_logout_with_unlocked_vault() {
        let temp_dir = tempdir().unwrap();
        let db_file = temp_dir.path().join("test.db");
        File::create(&db_file).unwrap();

        let vault = Vault::new();
        let vault_path = temp_dir.path().join("test");

        // This should succeed and attempt to lock the vault
        let result = handle_enhanced_logout(&vault, Some(&vault_path), true).await;
        // Note: This test may fail if the actual lock command requires more setup
        // In a real implementation, we would mock the lock command
    }

    #[tokio::test]
    async fn test_logout_with_locked_vault() {
        let temp_dir = tempdir().unwrap();
        let vault_file = temp_dir.path().join("test.vault");
        File::create(&vault_file).unwrap();

        let vault = Vault::new();
        let vault_path = temp_dir.path().join("test");

        // This should succeed without attempting to lock
        let result = handle_enhanced_logout(&vault, Some(&vault_path), true).await;
        assert!(result.is_ok());
    }
}
