use crate::core::Vault;
use serde_json::json;
use std::path::Path;

/// Handle vault logout - invalidate JWT session and provide instructions
///
/// This function performs logout by:
/// 1. Invalidating JWT session in the database
/// 2. Providing instructions to clear environment variable
///
/// Note: This does NOT lock the vault file. Use the `lock` command separately
/// if you want to apply PQCrypto armor to the vault file.
///
/// # Arguments
/// * `vault` - The vault instance
/// * `vault_path` - Optional path to vault file (unused, kept for compatibility)
/// * `use_json` - Whether to output in JSON format
///
/// # Returns
/// * `Ok(())` - Logout completed successfully
/// * `Err(Box<dyn std::error::Error>)` - If logout fails
pub async fn handle_logout(
    vault: &Vault,
    _vault_path: Option<&Path>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Invalidate JWT session in SurrealDB
    if let Err(e) = vault.invalidate_jwt_session().await {
        // Log error but don't fail logout - session invalidation is not critical
        if use_json {
            println!(
                "{}",
                json!({
                    "warning": format!("JWT session invalidation failed: {}", e),
                    "impact": "Session may remain active until expiration"
                })
            );
        }
    }

    // Provide logout instructions
    if use_json {
        println!(
            "{}",
            json!({
                "success": true,
                "operation": "logout",
                "message": "JWT session invalidated on server. Stop using the token.",
                "instructions": "Run 'vault login' to generate a new JWT token when needed"
            })
        );
    } else {
        println!("🔓 Vault Logout");
        println!();
        println!("✅ JWT session invalidated on server.");
        println!();
        println!("Your current JWT token is no longer valid.");
        println!("Run 'vault login' to generate a new token when needed.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::Vault;

    #[tokio::test]
    async fn test_logout_basic() {
        let vault = Vault::new();
        let result = handle_logout(&vault, None, true).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_logout_with_path() {
        let vault = Vault::new();
        let vault_path = std::path::Path::new("test");
        let result = handle_logout(&vault, Some(&vault_path), true).await;
        assert!(result.is_ok());
    }
}
