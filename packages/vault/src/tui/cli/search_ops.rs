//! Search and discovery operations for vault CLI

use super::auth::ensure_unlocked;
use crate::core::Vault;
use crate::logging::log_security_event;
use serde_json::json;
use tokio_stream::StreamExt;

pub async fn handle_list(vault: &Vault, use_json: bool) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = ensure_unlocked(vault, use_json).await {
        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "list",
                    "error": format!("Failed to unlock vault: {e}")
                })
            );
            return Ok(());
        } else {
            return Err(e);
        }
    }

    if !use_json {
        println!("Listing all keys...");
    }

    let stream_result = vault.find(".*").await;
    let mut stream = match stream_result {
        Ok(s) => s,
        Err(e) => {
            log_security_event("CLI_LIST", &format!("Failed to list keys: {e}"), false);
            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "list",
                        "error": format!("Failed to list keys: {e}")
                    })
                );
            } else {
                return Err(format!("Failed to list keys: {e}").into());
            }
            return Ok(());
        }
    };
    let mut results = Vec::new();

    while let Some(result) = stream.next().await {
        match result {
            Ok(item) => results.push(item),
            Err(e) => {
                log_security_event("CLI_LIST", &format!("Failed to list keys: {e}"), false);
                if use_json {
                    println!(
                        "{}",
                        json!({
                            "success": false,
                            "operation": "list",
                            "error": format!("Failed to list keys: {e}")
                        })
                    );
                    return Ok(());
                } else {
                    return Err(Box::new(e));
                }
            }
        }
    }

    log_security_event("CLI_LIST", "Listed all keys", true);

    if use_json {
        let keys: Vec<String> = results.iter().map(|(k, _)| k.clone()).collect();
        println!(
            "{}",
            json!({
                "success": true,
                "operation": "list",
                "keys": keys,
                "count": keys.len()
            })
        );
    } else if results.is_empty() {
        println!("No keys found in vault");
    } else {
        println!("Keys in vault:");
        for (key, _) in results {
            println!("- {}", key);
        }
    }
    Ok(())
}

pub async fn handle_find(
    vault: &Vault,
    pattern: &str,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = ensure_unlocked(vault, use_json).await {
        if use_json {
            println!(
                "{}",
                json!({
                    "success": false,
                    "operation": "find",
                    "error": format!("Failed to unlock vault: {e}")
                })
            );
            return Ok(());
        } else {
            return Err(e);
        }
    }

    if !use_json {
        println!("Finding keys matching pattern '{}'...", pattern);
    }

    let stream_result = vault.find(pattern).await;
    let mut stream = match stream_result {
        Ok(s) => s,
        Err(e) => {
            log_security_event(
                "CLI_FIND",
                &format!("Failed to find keys matching pattern {pattern}: {e}"),
                false,
            );
            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "find",
                        "pattern": pattern,
                        "error": format!("Failed to find keys: {e}")
                    })
                );
            } else {
                return Err(format!("Failed to find keys: {e}").into());
            }
            return Ok(());
        }
    };
    let mut results = Vec::new();

    while let Some(result) = stream.next().await {
        match result {
            Ok(item) => results.push(item),
            Err(e) => {
                log_security_event(
                    "CLI_FIND",
                    &format!("Failed to find keys matching pattern {pattern}: {e}"),
                    false,
                );
                if use_json {
                    println!(
                        "{}",
                        json!({
                            "success": false,
                            "operation": "find",
                            "pattern": pattern,
                            "error": format!("Failed to find keys: {e}")
                        })
                    );
                    return Ok(());
                } else {
                    return Err(Box::new(e));
                }
            }
        }
    }

    log_security_event(
        "CLI_FIND",
        &format!("Found keys matching pattern: {pattern}"),
        true,
    );

    if use_json {
        let entries: Vec<serde_json::Value> = results
            .iter()
            .map(|(k, v)| {
                json!({
                    "key": k,
                    "value": v.expose_as_str().unwrap_or("[non-string value]")
                })
            })
            .collect();

        println!(
            "{}",
            json!({
                "success": true,
                "operation": "find",
                "pattern": pattern,
                "entries": entries,
                "count": entries.len()
            })
        );
    } else if results.is_empty() {
        println!("No keys found matching pattern");
    } else {
        println!("Keys matching pattern:");
        for (key, value) in results {
            println!(
                "- {}: {}",
                key,
                value.expose_as_str().unwrap_or("[non-string value]")
            );
        }
    }
    Ok(())
}
