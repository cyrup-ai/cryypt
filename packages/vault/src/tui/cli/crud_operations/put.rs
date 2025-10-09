//! Put operations for vault CLI commands

use super::super::unlock_operations::ensure_unlocked;
use crate::core::Vault;
use crate::logging::log_security_event;
use serde_json::json;

pub async fn handle_put(
    vault: &Vault,
    key: &str,
    value: &str,
    namespace: Option<&str>,
    passphrase_option: Option<&str>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    log::info!("PUT_OPERATION: Starting ensure_unlocked check");
    if let Err(e) = ensure_unlocked(vault, passphrase_option, use_json).await {
        log::info!("PUT_OPERATION: ensure_unlocked failed: {}", e);
        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "put",
                    "error": format!("Failed to unlock vault: {e}")
                })
            );
            return Ok(());
        } else {
            return Err(e);
        }
    }

    if !use_json {
        if let Some(ns) = namespace {
            println!("Storing value for key '{}' in namespace '{}'...", key, ns);
        } else {
            println!("Storing value for key '{}'...", key);
        }
    }

    // Use namespace-aware put operation if namespace is provided
    let put_result = if let Some(ns) = namespace {
        vault.put_with_namespace(ns, key, value).await?.await
    } else {
        vault.put(key, value).await?.await
    };

    match put_result {
        Ok(()) => {
            let log_msg = if let Some(ns) = namespace {
                format!("Stored value for key: {key} in namespace: {ns}")
            } else {
                format!("Stored value for key: {key}")
            };
            log_security_event("CLI_PUT", &log_msg, true);

            if use_json {
                let mut response = json!({
                    "success": true,
                    "operation": "put",
                    "key": key
                });
                if let Some(ns) = namespace {
                    response["namespace"] = json!(ns);
                }
                println!("{}", response);
            } else {
                println!("Value stored successfully");
            }
        }
        Err(e) => {
            let log_msg = if let Some(ns) = namespace {
                format!("Failed to store value for key {key} in namespace {ns}: {e}")
            } else {
                format!("Failed to store value for key {key}: {e}")
            };
            log_security_event("CLI_PUT", &log_msg, false);

            if use_json {
                let mut response = json!({
                    "success": false,
                    "operation": "put",
                    "error": format!("Failed to store value: {e}")
                });
                if let Some(ns) = namespace {
                    response["namespace"] = json!(ns);
                }
                println!("{}", response);
                return Ok(());
            } else {
                return Err(Box::new(e));
            }
        }
    }
    Ok(())
}
