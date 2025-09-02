//! Delete operations for vault CLI commands

use super::super::unlock_operations::ensure_unlocked;
use crate::core::Vault;
use crate::logging::log_security_event;
use serde_json::json;

pub async fn handle_delete(
    vault: &Vault,
    key: &str,
    passphrase_option: Option<&str>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = ensure_unlocked(vault, passphrase_option, use_json).await {
        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "delete",
                    "error": format!("Failed to unlock vault: {}", e)
                })
            );
            return Ok(());
        } else {
            return Err(e);
        }
    }

    if !use_json {
        println!("Deleting key '{}'...", key);
    }

    match vault.delete(key).await {
        Ok(_) => {
            log_security_event("CLI_DELETE", &format!("Deleted key: {}", key), true);

            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": true,
                        "operation": "delete",
                        "key": key
                    })
                );
            } else {
                println!("Key deleted successfully");
            }
        }
        Err(e) => {
            log_security_event(
                "CLI_DELETE",
                &format!("Failed to delete key {}: {}", key, e),
                false,
            );

            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "delete",
                        "key": key,
                        "error": format!("Failed to delete key: {}", e)
                    })
                );
                return Ok(());
            } else {
                return Err(Box::new(e));
            }
        }
    }
    Ok(())
}
