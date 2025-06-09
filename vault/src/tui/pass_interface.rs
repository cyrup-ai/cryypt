use std::path::{Path, PathBuf};
use std::process::Command;
use std::io::{self, Read};
use zeroize::Zeroizing;
use std::fs::{self, File, ReadDir};
use tokio::sync::mpsc;
use log::{error, info, debug};
use regex::Regex;
use async_trait::async_trait;

// Secret Service interface specification
// https://specifications.freedesktop.org/secret-service-spec/latest/

/// Interface for interacting with the Pass password store
pub struct PassInterface {
    store_path: PathBuf,
    gpg_path: PathBuf,
}

impl Default for PassInterface {
    fn default() -> Self {
        PassInterface {
            store_path: PathBuf::from(shellexpand::tilde("~/.password-store").to_string()),
            gpg_path: PathBuf::from("/usr/bin/gpg"),
        }
    }
}

/// Result type for Pass operations
pub type PassResult<T> = Result<T, PassError>;

/// Errors for Pass operations
#[derive(Debug, thiserror::Error)]
pub enum PassError {
    #[error("Store not found: {0}")]
    StoreNotFound(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] io::Error),
    
    #[error("Failed to decode GPG output: {0}")]
    DecodeError(String),
    
    #[error("GPG execution failed: {0}")]
    GpgError(String),
    
    #[error("Password not found: {0}")]
    PasswordNotFound(String),
}

/// Implementation of the Pass password manager interface
impl PassInterface {
    /// Create a new Pass interface with the specified password store path
    pub fn new(store_path: PathBuf) -> Self {
        PassInterface {
            store_path,
            gpg_path: PathBuf::from("/usr/bin/gpg"),
        }
    }
    
    /// Check if the password store exists
    pub fn store_exists(&self) -> bool {
        self.store_path.exists() && self.store_path.is_dir()
    }
    
    /// Get all password entries from the password store
    pub fn get_all_entries(&self) -> PassResult<Vec<String>> {
        if !self.store_exists() {
            return Err(PassError::StoreNotFound(self.store_path.to_string_lossy().to_string()));
        }
        
        let entries = self.walk_password_store(&self.store_path, "")?;
        Ok(entries)
    }
    
    /// Recursively walk the password store to find all entries
    fn walk_password_store(&self, dir: &Path, prefix: &str) -> PassResult<Vec<String>> {
        let mut entries = Vec::new();
        
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                let dir_name = path.file_name().unwrap().to_string_lossy().to_string();
                let new_prefix = if prefix.is_empty() {
                    dir_name.clone()
                } else {
                    format!("{}/{}", prefix, dir_name)
                };
                
                let subentries = self.walk_password_store(&path, &new_prefix)?;
                entries.extend(subentries);
            } else if path.is_file() && path.extension().map_or(false, |ext| ext == "gpg") {
                let file_name = path.file_stem().unwrap().to_string_lossy().to_string();
                let entry_name = if prefix.is_empty() {
                    file_name
                } else {
                    format!("{}/{}", prefix, file_name)
                };
                
                entries.push(entry_name);
            }
        }
        
        Ok(entries)
    }
    
    /// Search for password entries matching the given pattern
    pub fn search_entries(&self, pattern: &str) -> PassResult<Vec<String>> {
        let entries = self.get_all_entries()?;
        let regex = Regex::new(pattern).map_err(|e| PassError::DecodeError(e.to_string()))?;
        
        let matches = entries.into_iter()
            .filter(|entry| regex.is_match(entry))
            .collect();
            
        Ok(matches)
    }
    
    /// Get the content of a password entry
    pub fn get_password(&self, entry_name: &str) -> PassResult<Zeroizing<String>> {
        let gpg_file_path = self.entry_path(entry_name);
        
        if !gpg_file_path.exists() {
            return Err(PassError::PasswordNotFound(entry_name.to_string()));
        }
        
        let output = Command::new(&self.gpg_path)
            .args(&["-d", gpg_file_path.to_str().unwrap()])
            .output()?;
            
        if !output.status.success() {
            let error = String::from_utf8_lossy(&output.stderr).to_string();
            return Err(PassError::GpgError(error));
        }
        
        let content = String::from_utf8_lossy(&output.stdout).to_string();
        Ok(Zeroizing::new(content))
    }
    
    /// Get the first line of a password entry (the password itself)
    pub fn get_password_only(&self, entry_name: &str) -> PassResult<Zeroizing<String>> {
        let content = self.get_password(entry_name)?;
        let password = content.lines().next().unwrap_or("").to_string();
        Ok(Zeroizing::new(password))
    }
    
    /// Get the path to a password entry
    fn entry_path(&self, entry_name: &str) -> PathBuf {
        self.store_path.join(format!("{}.gpg", entry_name))
    }
}

/// The PassStream allows for asynchronous streaming of password entries
pub struct PassStream {
    receiver: mpsc::Receiver<PassResult<String>>,
}

impl PassStream {
    /// Create a new PassStream from a receiver channel
    pub fn new(receiver: mpsc::Receiver<PassResult<String>>) -> Self {
        PassStream { receiver }
    }
    
    /// Get the next password entry asynchronously
    pub async fn next(&mut self) -> Option<PassResult<String>> {
        self.receiver.recv().await
    }
}

/// Asynchronous interface for Pass operations
#[async_trait]
pub trait AsyncPassInterface: Send + Sync {
    /// Get all password entries asynchronously
    async fn get_all_entries_async(&self) -> PassResult<Vec<String>>;
    
    /// Search for password entries asynchronously
    async fn search_entries_async(&self, pattern: &str) -> PassResult<Vec<String>>;
    
    /// Get a password entry asynchronously
    async fn get_password_async(&self, entry_name: &str) -> PassResult<Zeroizing<String>>;
    
    /// Stream all password entries asynchronously
    async fn stream_entries(&self) -> PassStream;
}

/// Implementation of the asynchronous Pass interface using the "Hidden Box/Pin" pattern
pub struct AsyncPassInterfaceImpl {
    pass: PassInterface,
}

impl AsyncPassInterfaceImpl {
    /// Create a new asynchronous Pass interface
    pub fn new(store_path: PathBuf) -> Self {
        AsyncPassInterfaceImpl {
            pass: PassInterface::new(store_path),
        }
    }
}

#[async_trait]
impl AsyncPassInterface for AsyncPassInterfaceImpl {
    async fn get_all_entries_async(&self) -> PassResult<Vec<String>> {
        let pass = self.pass.clone();
        
        // Spawn a blocking task to perform the sync operation
        let result = tokio::task::spawn_blocking(move || {
            pass.get_all_entries()
        }).await.unwrap_or_else(|e| Err(PassError::GpgError(e.to_string())));
        
        result
    }
    
    async fn search_entries_async(&self, pattern: &str) -> PassResult<Vec<String>> {
        let pass = self.pass.clone();
        let pattern = pattern.to_string();
        
        // Spawn a blocking task to perform the sync operation
        let result = tokio::task::spawn_blocking(move || {
            pass.search_entries(&pattern)
        }).await.unwrap_or_else(|e| Err(PassError::GpgError(e.to_string())));
        
        result
    }
    
    async fn get_password_async(&self, entry_name: &str) -> PassResult<Zeroizing<String>> {
        let pass = self.pass.clone();
        let entry_name = entry_name.to_string();
        
        // Spawn a blocking task to perform the sync operation
        let result = tokio::task::spawn_blocking(move || {
            pass.get_password(&entry_name)
        }).await.unwrap_or_else(|e| Err(PassError::GpgError(e.to_string())));
        
        result
    }
    
    async fn stream_entries(&self) -> PassStream {
        let pass = self.pass.clone();
        let (tx, rx) = mpsc::channel(32);
        
        tokio::spawn(async move {
            match pass.get_all_entries() {
                Ok(entries) => {
                    for entry in entries {
                        if tx.send(Ok(entry)).await.is_err() {
                            break;
                        }
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e)).await;
                }
            }
        });
        
        PassStream::new(rx)
    }
}

// Make PassInterface cloneable for use in async contexts
impl Clone for PassInterface {
    fn clone(&self) -> Self {
        PassInterface {
            store_path: self.store_path.clone(),
            gpg_path: self.gpg_path.clone(),
        }
    }
}
