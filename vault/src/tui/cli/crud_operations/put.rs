//! Put operations for vault CLI commands

use super::super::unlock_operations::ensure_unlocked;
use crate::core::Vault;
use crate::logging::log_security_event;
use serde_json::json;

pub async fn handle_put(
    vault: &Vault,
    key: &str,
    value: &str,
    passphrase_option: Option<&str>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = ensure_unlocked(vault, passphrase_option, use_json).await {
        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "put",
                    "error": format!("Failed to unlock vault: {}", e)
                })
            );
            return Ok(());
        } else {
            return Err(e);
        }
    }

    if !use_json {
        println!("Storing value for key '{}'...", key);
    }

    match vault.put(key, value).await {
        Ok(_) => {
            log_security_event("CLI_PUT", &format!("Stored value for key: {}", key), true);

            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": true,
                        "operation": "put",
                        "key": key
                    })
                );
            } else {
                println!("Value stored successfully");
            }
        }
        Err(e) => {
            log_security_event(
                "CLI_PUT",
                &format!("Failed to store value for key {}: {}", key, e),
                false,
            );

            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "put",
                        "error": format!("Failed to store value: {}", e)
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
