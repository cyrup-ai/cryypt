//! Get operations for vault CLI commands

use super::super::unlock_operations::ensure_unlocked;
use crate::core::Vault;
use crate::logging::log_security_event;
use serde_json::json;

pub async fn handle_get(
    vault: &Vault,
    key: &str,
    namespace: Option<&str>,
    passphrase_option: Option<&str>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = ensure_unlocked(vault, passphrase_option, use_json).await {
        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "get",
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
            println!(
                "Retrieving value for key '{}' from namespace '{}'...",
                key, ns
            );
        } else {
            println!("Retrieving value for key '{}'...", key);
        }
    }

    // Use namespace-aware get operation if namespace is provided
    let get_result = if let Some(ns) = namespace {
        vault.get_from_namespace(ns, key).await
    } else {
        vault.get(key).await
    };

    match get_result {
        Ok(request) => match request.await {
            Ok(value) => {
                let log_msg = if let Some(ns) = namespace {
                    format!("Retrieved value for key: {key} from namespace: {ns}")
                } else {
                    format!("Retrieved value for key: {key}")
                };
                log_security_event("CLI_GET", &log_msg, true);

                match value {
                    Some(v) => {
                        let value_str = v.expose_as_str().unwrap_or("[non-string value]");
                        if use_json {
                            let mut response = json!({
                                "success": true,
                                "operation": "get",
                                "key": key,
                                "value": value_str
                            });
                            if let Some(ns) = namespace {
                                response["namespace"] = json!(ns);
                            }
                            println!("{}", response);
                        } else {
                            println!("Value: {}", value_str);
                        }
                    }
                    None => {
                        let log_msg = if let Some(ns) = namespace {
                            format!("Key not found: {key} in namespace: {ns}")
                        } else {
                            format!("Key not found: {key}")
                        };
                        log_security_event("CLI_GET", &log_msg, false);

                        if use_json {
                            let mut response = json!({
                                "success": false,
                                "operation": "get",
                                "key": key,
                                "error": "Key not found",
                                "error_code": "KEY_NOT_FOUND"
                            });
                            if let Some(ns) = namespace {
                                response["namespace"] = json!(ns);
                            }
                            println!("{}", response);
                        } else if let Some(ns) = namespace {
                            println!("Error: Key '{}' not found in namespace '{}'", key, ns);
                        } else {
                            println!("Error: Key '{}' not found", key);
                        }

                        // Exit with code 1 for key not found (Unix convention)
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                let log_msg = if let Some(ns) = namespace {
                    format!(
                        "Failed to retrieve value for key {} from namespace {}: {}",
                        key, ns, e
                    )
                } else {
                    format!("Failed to retrieve value for key {key}: {e}")
                };
                log_security_event("CLI_GET", &log_msg, false);

                if use_json {
                    let mut response = json!({
                        "success": false,
                        "operation": "get",
                        "key": key,
                        "error": format!("Failed to retrieve value: {e}")
                    });
                    if let Some(ns) = namespace {
                        response["namespace"] = json!(ns);
                    }
                    println!("{}", response);
                    return Ok(());
                } else {
                    return Err(format!("Failed to retrieve value: {e}").into());
                }
            }
        },
        Err(e) => {
            let log_msg = if let Some(ns) = namespace {
                format!(
                    "Failed to retrieve value for key {} from namespace {}: {}",
                    key, ns, e
                )
            } else {
                format!("Failed to retrieve value for key {key}: {e}")
            };
            log_security_event("CLI_GET", &log_msg, false);

            if use_json {
                let mut response = json!({
                    "success": false,
                    "operation": "get",
                    "key": key,
                    "error": format!("Failed to retrieve value: {e}")
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
