//! Query operations for vault CLI commands

use super::unlock_operations::ensure_unlocked;
use crate::core::Vault;
use crate::logging::log_security_event;
use serde_json::json;
use tokio_stream::StreamExt;

pub async fn handle_list(
    vault: &Vault,
    namespace: Option<&str>,
    namespaces: bool,
    passphrase_option: Option<&str>,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = ensure_unlocked(vault, passphrase_option, use_json).await {
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

    // Handle listing namespaces request
    if namespaces {
        return handle_list_namespaces(vault, use_json).await;
    }

    if !use_json {
        if let Some(ns) = namespace {
            println!("Listing all keys in namespace '{}'...", ns);
        } else {
            println!("Listing all keys...");
        }
    }

    // Use namespace-aware find operation if namespace is provided
    let stream_result = if let Some(ns) = namespace {
        vault.find_in_namespace(ns, ".*").await
    } else {
        vault.find(".*").await
    };
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
        let mut response = json!({
            "success": true,
            "operation": "list",
            "keys": keys,
            "count": keys.len()
        });
        if let Some(ns) = namespace {
            response["namespace"] = json!(ns);
        }
        println!("{}", response);
    } else if results.is_empty() {
        if let Some(ns) = namespace {
            println!("No keys found in namespace '{}'", ns);
        } else {
            println!("No keys found in vault");
        }
    } else {
        if let Some(ns) = namespace {
            println!("Keys in namespace '{}':", ns);
        } else {
            println!("Keys in vault:");
        }
        for (key, _) in results {
            println!("- {}", key);
        }
    }
    Ok(())
}
pub async fn handle_find(
    vault: &Vault,
    pattern: &str,
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
        if let Some(ns) = namespace {
            println!(
                "Finding keys matching pattern '{}' in namespace '{}'...",
                pattern, ns
            );
        } else {
            println!("Finding keys matching pattern '{}'...", pattern);
        }
    }

    // Use namespace-aware find operation if namespace is provided
    let stream_result = if let Some(ns) = namespace {
        vault.find_in_namespace(ns, pattern).await
    } else {
        vault.find(pattern).await
    };
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

        let mut response = json!({
            "success": true,
            "operation": "find",
            "pattern": pattern,
            "entries": entries,
            "count": entries.len()
        });
        if let Some(ns) = namespace {
            response["namespace"] = json!(ns);
        }
        println!("{}", response);
    } else if results.is_empty() {
        if let Some(ns) = namespace {
            println!("No keys found matching pattern in namespace '{}'", ns);
        } else {
            println!("No keys found matching pattern");
        }
    } else {
        if let Some(ns) = namespace {
            println!("Keys matching pattern in namespace '{}':", ns);
        } else {
            println!("Keys matching pattern:");
        }
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

/// Handle listing all available namespaces
async fn handle_list_namespaces(
    vault: &Vault,
    use_json: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match vault.list_namespaces().await {
        Ok(request) => match request.await {
            Ok(namespaces) => {
                log_security_event("CLI_LIST_NAMESPACES", "Listed all namespaces", true);

                if use_json {
                    println!(
                        "{}",
                        json!({
                            "success": true,
                            "operation": "list_namespaces",
                            "namespaces": namespaces,
                            "count": namespaces.len()
                        })
                    );
                } else if namespaces.is_empty() {
                    println!("No namespaces found");
                } else {
                    println!("Available namespaces:");
                    for ns in namespaces {
                        println!("- {}", ns);
                    }
                }
            }
            Err(e) => {
                log_security_event(
                    "CLI_LIST_NAMESPACES",
                    &format!("Failed to list namespaces: {e}"),
                    false,
                );
                if use_json {
                    println!(
                        "{}",
                        json!({
                            "success": false,
                            "operation": "list_namespaces",
                            "error": format!("Failed to list namespaces: {e}")
                        })
                    );
                } else {
                    return Err(format!("Failed to list namespaces: {e}").into());
                }
            }
        },
        Err(e) => {
            log_security_event(
                "CLI_LIST_NAMESPACES",
                &format!("Failed to list namespaces: {e}"),
                false,
            );
            if use_json {
                println!(
                    "{}",
                    json!({
                        "success": false,
                        "operation": "list_namespaces",
                        "error": format!("Failed to list namespaces: {e}")
                    })
                );
            } else {
                return Err(Box::new(e));
            }
        }
    }
    Ok(())
}
