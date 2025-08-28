//! Get operations for vault CLI commands

use super::super::unlock_operations::ensure_unlocked;
use crate::core::Vault;
use crate::logging::log_security_event;
use serde_json::json;

pub async fn handle_get(
    vault: &Vault,
    key: &str,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = ensure_unlocked(vault, use_json).await {
        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "get",
                    "error": format!("Failed to unlock vault: {}", e)
                })
            );
            return Ok(());
        } else {
            return Err(e);
        }
    }

    if !use_json {
        println!("Retrieving value for key '{}'...", key);
    }

    match vault.get(key).await {
        Ok(request) => match request.await {
            Ok(value) => {
                log_security_event(
                    "CLI_GET",
                    &format!("Retrieved value for key: {}", key),
                    true,
                );

                match value {
                    Some(v) => {
                        let value_str = v.expose_as_str().unwrap_or("[non-string value]");
                        if use_json {
                            println!(
                                "{}",
                                json!({
                                    "success": true,
                                    "operation": "get",
                                    "key": key,
                                    "value": value_str
                                })
                            );
                        } else {
                            println!("Value: {}", value_str);
                        }
                    }
                    None => {
                        if use_json {
                            println!(
                                "{}",
                                json!({
                                    "success": true,
                                    "operation": "get",
                                    "key": key,
                                    "value": "[not found]"
                                })
                            );
                        } else {
                            println!("Value: [not found]");
                        }
                    }
                }
            }
            Err(e) => {
                log_security_event(
                    "CLI_GET",
                    &format!("Failed to retrieve value for key {}: {}", key, e),
                    false,
                );

                if use_json {
                    println!(
                        "{}",
                        json!({
                            "success": false,
                            "operation": "get",
                            "key": key,
                            "error": format!("Failed to retrieve value: {}", e)
                        })
                    );
                    return Ok(());
                } else {
                    return Err(format!("Failed to retrieve value: {}", e).into());
                }
            }
        },
        Err(e) => {
            log_security_event(
                "CLI_GET",
                &format!("Failed to retrieve value for key {}: {}", key, e),
                false,
            );

            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "get",
                        "key": key,
                        "error": format!("Failed to retrieve value: {}", e)
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
