//! Data operations (put, get, delete) for vault CLI

use super::auth::ensure_unlocked;
use crate::core::Vault;
use crate::logging::log_security_event;
use serde_json::json;

pub async fn handle_put(
    vault: &Vault,
    key: &str,
    value: &str,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = ensure_unlocked(vault, use_json).await {
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
        println!("Storing value for key '{}'...", key);
    }

    match vault.put(key, value).await {
        Ok(_) => {
            log_security_event("CLI_PUT", &format!("Stored value for key: {key}"), true);

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
                &format!("Failed to store value for key {key}: {e}"),
                false,
            );

            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "put",
                        "error": format!("Failed to store value: {e}")
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
                    "error": format!("Failed to unlock vault: {e}")
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
                log_security_event("CLI_GET", &format!("Retrieved value for key: {key}"), true);

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
                                    "success": false,
                                    "operation": "get",
                                    "key": key,
                                    "error": "Key not found",
                                    "error_code": "KEY_NOT_FOUND"
                                })
                            );
                        } else {
                            println!("Error: Key '{}' not found", key);
                        }

                        // Exit with code 1 for key not found (Unix convention)
                        std::process::exit(1);
                    }
                }
            }
            Err(e) => {
                log_security_event(
                    "CLI_GET",
                    &format!("Failed to retrieve value for key {key}: {e}"),
                    false,
                );

                if use_json {
                    println!(
                        "{}",
                        json!({
                            "success": false,
                            "operation": "get",
                            "key": key,
                            "error": format!("Failed to retrieve value: {e}")
                        })
                    );
                    return Ok(());
                } else {
                    return Err(format!("Failed to retrieve value: {e}").into());
                }
            }
        },
        Err(e) => {
            log_security_event(
                "CLI_GET",
                &format!("Failed to retrieve value for key {key}: {e}"),
                false,
            );

            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "get",
                        "key": key,
                        "error": format!("Failed to retrieve value: {e}")
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

pub async fn handle_delete(
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
                    "operation": "delete",
                    "error": format!("Failed to unlock vault: {e}")
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
            log_security_event("CLI_DELETE", &format!("Deleted key: {key}"), true);

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
                &format!("Failed to delete key {key}: {e}"),
                false,
            );

            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "delete",
                        "key": key,
                        "error": format!("Failed to delete key: {e}")
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
