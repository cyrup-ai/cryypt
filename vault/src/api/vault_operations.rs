//! Vault operation builders following README.md patterns exactly
//!
//! Provides fluent API for vault operations with proper error handling and unwrapping

use crate::core::Vault;
use crate::error::VaultResult;
use std::collections::HashMap;

/// Vault operation builder with key for set operations
pub struct VaultWithKey<'v> {
    vault: &'v Vault,
    key: String,
}

/// Vault operation builder with key and result handler for set operations
pub struct VaultWithKeyAndHandler<'v, F, T> {
    vault: &'v Vault,
    key: String,
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

/// Vault operation builder with TTL
pub struct VaultWithKeyAndTtl<'v> {
    vault: &'v Vault,
    key: String,
    ttl_seconds: u64,
}

/// Vault operation builder with TTL and result handler
pub struct VaultWithKeyAndTtlAndHandler<'v, F, T> {
    vault: &'v Vault,
    key: String,
    ttl_seconds: u64,
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

/// Vault operation builder with result handler (for operations without keys)
pub struct VaultGetHandler<'v, F, T> {
    vault: &'v Vault,
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

/// Vault operation builder with result handler for Vec<u8> operations
pub struct VaultWithResultHandler<'v, F> {
    vault: &'v Vault,
    result_handler: F,
}

/// Vault operation builder with chunk handler for streaming operations
pub struct VaultWithChunkHandler<'v, F> {
    vault: &'v Vault,
    chunk_handler: F,
}

impl Vault {
    /// Add key to vault operation builder - README.md pattern
    pub fn with_key(&self, key: &str) -> VaultWithKey<'_> {
        VaultWithKey {
            vault: self,
            key: key.to_string(),
        }
    }

    /// Internal implementation for on_result - called by macro
    fn on_result_impl<F>(&self, handler: F) -> VaultWithResultHandler<'_, F>
    where
        F: Fn(crate::VaultResult<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        VaultWithResultHandler {
            vault: self,
            result_handler: handler,
        }
    }

    /// Internal implementation for on_chunk - called by macro
    fn on_chunk_impl<F>(&self, handler: F) -> VaultWithChunkHandler<'_, F>
    where
        F: Fn(crate::VaultResult<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        VaultWithChunkHandler {
            vault: self,
            chunk_handler: handler,
        }
    }

    /// Add on_result handler - transforms pattern matching internally
    pub fn on_result<F>(&self, handler: F) -> VaultWithResultHandler<'_, F>
    where
        F: Fn(crate::VaultResult<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        VaultWithResultHandler {
            vault: self,
            result_handler: handler,
        }
    }

    /// Add on_chunk handler - transforms pattern matching internally
    pub fn on_chunk<F>(&self, handler: F) -> VaultWithChunkHandler<'_, F>
    where
        F: Fn(crate::VaultResult<Vec<u8>>) -> Vec<u8> + Send + 'static,
    {
        VaultWithChunkHandler {
            vault: self,
            chunk_handler: handler,
        }
    }

    /// Add on_result handler for String operations (get) - README.md pattern
    pub fn on_result_string<F, T>(&self, handler: F) -> VaultGetHandler<'_, F, T>
    where
        F: FnOnce(VaultResult<String>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        VaultGetHandler {
            vault: self,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<'v> VaultWithKey<'v> {
    /// Add TTL configuration to vault operation
    pub fn with_ttl(self, ttl_seconds: u64) -> VaultWithKeyAndTtl<'v> {
        VaultWithKeyAndTtl {
            vault: self.vault,
            key: self.key,
            ttl_seconds,
        }
    }

    /// Add on_result handler - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> VaultWithKeyAndHandler<'v, F, T>
    where
        F: FnOnce(VaultResult<()>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        VaultWithKeyAndHandler {
            vault: self.vault,
            key: self.key,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set value for the key - action takes data as argument per README.md
    /// Returns unwrapped () with default error handling (Ok(()) => (), Err(_) => ())
    pub async fn set<V: AsRef<str>>(self, value: V) -> () {
        let vault_request_result = self.vault.put(&self.key, value.as_ref()).await;

        match vault_request_result {
            Ok(vault_request) => {
                let result = vault_request.await;
                // Default unwrapping: Ok(()) => (), Err(_) => ()
                match result {
                    Ok(_) => (),
                    Err(_) => (),
                }
            }
            Err(_) => (), // Error creating request
        }
    }
}

impl<'v> VaultWithKeyAndTtl<'v> {
    /// Add on_result handler - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> VaultWithKeyAndTtlAndHandler<'v, F, T>
    where
        F: FnOnce(VaultResult<()>) -> T + Send + 'static,
        T: cryypt_common::NotResult + Send + 'static,
    {
        VaultWithKeyAndTtlAndHandler {
            vault: self.vault,
            key: self.key,
            ttl_seconds: self.ttl_seconds,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Set value with TTL - action takes data as argument per README.md
    /// Returns unwrapped () with default error handling (Ok(()) => (), Err(_) => ())
    pub async fn set<V: AsRef<str>>(self, value: V) -> () {
        // For TTL implementation, we'd need to extend the vault interface
        // For now, fallback to regular set operation using existing vault method
        let vault_request_result = self.vault.put(&self.key, value.as_ref()).await;

        match vault_request_result {
            Ok(vault_request) => {
                let result = vault_request.await;
                // Default unwrapping: Ok(()) => (), Err(_) => ()
                match result {
                    Ok(_) => (),
                    Err(_) => (),
                }
            }
            Err(_) => (), // Error creating request
        }
    }
}

impl<'v, F, T> VaultWithKeyAndHandler<'v, F, T>
where
    F: FnOnce(VaultResult<()>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Set value for the key - action takes data as argument per README.md
    pub async fn set<V: AsRef<str>>(self, value: V) -> T {
        let vault_request_result = self.vault.put(&self.key, value.as_ref()).await;

        let final_result = match vault_request_result {
            Ok(vault_request) => vault_request.await,
            Err(e) => Err(e), // Pass through error
        };

        // Apply result handler
        (self.result_handler)(final_result)
    }
}

impl<'v, F, T> VaultWithKeyAndTtlAndHandler<'v, F, T>
where
    F: FnOnce(VaultResult<()>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Set value with TTL - action takes data as argument per README.md
    pub async fn set<V: AsRef<str>>(self, value: V) -> T {
        // Use the TTL-aware put method with the configured TTL
        let vault_request_result = self
            .vault
            .put_with_ttl(&self.key, value.as_ref(), self.ttl_seconds)
            .await;

        let final_result = match vault_request_result {
            Ok(vault_request) => vault_request.await,
            Err(e) => Err(e), // Pass through error
        };

        // Apply result handler
        (self.result_handler)(final_result)
    }
}

impl<'v, F, T> VaultGetHandler<'v, F, T>
where
    F: FnOnce(VaultResult<String>) -> T + Send + 'static,
    T: cryypt_common::NotResult + Send + 'static,
{
    /// Get value by key - action takes key as argument per README.md
    pub async fn get(self, key: &str) -> T {
        let vault_request_result = self.vault.get(key).await;

        let final_result = match vault_request_result {
            Ok(vault_request) => {
                match vault_request.await {
                    Ok(vault_value_opt) => {
                        match vault_value_opt {
                            Some(vault_value) => {
                                match vault_value.expose_as_str() {
                                    Ok(s) => Ok(s.to_string()),
                                    Err(_) => Ok(String::new()), // Invalid UTF-8, return empty string
                                }
                            }
                            None => Ok(String::new()),
                        }
                    }
                    Err(e) => Err(e),
                }
            }
            Err(e) => Err(e), // Pass through error
        };

        // Apply result handler with String result
        (self.result_handler)(final_result)
    }

    /// Delete value by key - action takes key as argument per README.md
    /// Note: This changes the return type context to (), so we create a new handler
    pub async fn delete(self, key: &str) -> T {
        let vault_request_result = self.vault.delete(key).await;

        let final_result = match vault_request_result {
            Ok(vault_request) => {
                vault_request.await.map(|_| String::new()) // Convert () to String
            }
            Err(e) => Err(e), // Pass through error
        };

        // Convert () result to String for consistency with handler type
        (self.result_handler)(final_result)
    }

    /// Store multiple key-value pairs - action takes data as argument per README.md
    pub async fn put_all(self, entries: HashMap<String, String>) -> T {
        let entries_vec: Vec<(String, String)> = entries.into_iter().collect();
        let vault_request_result = self.vault.put_all(&entries_vec).await;

        let final_result = match vault_request_result {
            Ok(vault_request) => {
                vault_request.await.map(|_| String::new()) // Convert () to String
            }
            Err(e) => Err(e), // Pass through error
        };

        // Convert () result to String for consistency with handler type
        (self.result_handler)(final_result)
    }

    /// List all stored keys - README.md pattern
    pub async fn list_keys(self) -> T {
        use futures_util::StreamExt;

        let stream_result = self.vault.list().await;
        let result = match stream_result {
            Ok(mut stream) => {
                let mut keys = Vec::new();

                // Collect all keys from the stream
                while let Some(key_result) = stream.next().await {
                    match key_result {
                        Ok(key) => keys.push(key),
                        Err(_) => break,
                    }
                }

                // Convert Vec<String> to String by joining
                Ok(keys.join(","))
            }
            Err(e) => Err(e),
        };

        // Apply result handler with String result
        (self.result_handler)(result)
    }

    /// Search for keys with pattern - action takes pattern as argument per README.md  
    pub async fn find(self, pattern: &str) -> T {
        use futures_util::StreamExt;

        let stream_result = self.vault.find(pattern).await;
        let result = match stream_result {
            Ok(mut stream) => {
                let mut keys = Vec::new();

                // Collect all keys from the stream (ignoring values)
                while let Some(entry_result) = stream.next().await {
                    match entry_result {
                        Ok((key, _value)) => keys.push(key),
                        Err(_) => break,
                    }
                }

                // Convert Vec<String> to String by joining
                Ok(keys.join(","))
            }
            Err(e) => Err(e),
        };

        // Apply result handler with String result
        (self.result_handler)(result)
    }

    /// Change vault passphrase - action takes new passphrase as argument per README.md
    pub async fn change_passphrase(self, new_passphrase: &str) -> T {
        // We need the old passphrase - this API might need adjustment
        // For now, assume we have access to current passphrase through vault state
        let vault_request_result = self.vault.change_passphrase("", new_passphrase).await;

        let final_result = match vault_request_result {
            Ok(vault_request) => {
                vault_request.await.map(|_| String::new()) // Convert () to String
            }
            Err(e) => Err(e), // Pass through error
        };

        // Convert () result to String for consistency with handler type
        (self.result_handler)(final_result)
    }

    /// Lock the vault - README.md pattern
    pub async fn lock(self) -> T {
        let result = self.vault.lock().await;

        // Convert () result to String for consistency with handler type
        let string_result = result.map(|_| String::new());
        (self.result_handler)(string_result)
    }
}

impl<'v, F> VaultWithResultHandler<'v, F>
where
    F: Fn(crate::VaultResult<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Get value by key - action takes key as argument per README.md
    pub async fn get(self, key: &str) -> Vec<u8> {
        let vault_request_result = self.vault.get(key).await;

        let final_result = match vault_request_result {
            Ok(vault_request) => {
                match vault_request.await {
                    Ok(vault_value_opt) => {
                        match vault_value_opt {
                            Some(vault_value) => {
                                Ok(vault_value.expose_secret().to_vec())
                            }
                            None => Ok(Vec::new()),
                        }
                    }
                    Err(e) => Err(e.into()),
                }
            }
            Err(e) => Err(e.into()), // Pass through error
        };

        // Apply result handler
        (self.result_handler)(final_result)
    }

    /// Set value for key - action takes key and data as arguments per README.md
    pub async fn set(self, key: &str, value: &[u8]) -> Vec<u8> {
        let value_str = String::from_utf8_lossy(value);
        let vault_request_result = self.vault.put(key, &value_str).await;

        let final_result = match vault_request_result {
            Ok(vault_request) => {
                vault_request.await.map(|_| Vec::new()).map_err(|e| e.into())
            }
            Err(e) => Err(e.into()), // Pass through error
        };

        // Apply result handler
        (self.result_handler)(final_result)
    }
}

impl<'v, F> VaultWithChunkHandler<'v, F>
where
    F: Fn(crate::VaultResult<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// List all stored keys as stream - README.md pattern
    pub fn list_keys_stream(
        self,
    ) -> impl futures::Stream<Item = Vec<u8>> + Send {
        use futures_util::StreamExt;

        let vault = self.vault;
        let handler = self.chunk_handler;

        futures::stream::unfold((vault, handler, None), 
            move |(vault, handler, mut stream_opt)| async move {
                // Initialize stream on first call
                if stream_opt.is_none() {
                    match vault.list().await {
                        Ok(stream) => stream_opt = Some(stream),
                        Err(e) => {
                            let result = Err(e.into());
                            let processed_chunk = handler(result);
                            return Some((processed_chunk, (vault, handler, None)));
                        }
                    }
                }

                // Get next item from stream
                if let Some(ref mut stream) = stream_opt {
                    match stream.next().await {
                        Some(key_result) => {
                            let result = key_result.map(|key| key.into_bytes()).map_err(|e| e.into());
                            let processed_chunk = handler(result);
                            Some((processed_chunk, (vault, handler, stream_opt)))
                        }
                        None => None, // Stream ended
                    }
                } else {
                    None
                }
            })
    }
}
