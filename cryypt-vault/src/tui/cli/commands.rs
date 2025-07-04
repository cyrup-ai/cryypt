//! CLI command definitions

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "cryypt")]
#[command(about = "Secure vault and key management")]
pub struct Cli {
    /// Path to the vault file
    #[arg(long)]
    pub vault_path: Option<PathBuf>,
    
    /// Path to the salt file
    #[arg(long)]
    pub salt_path: Option<PathBuf>,
    
    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
    
    /// Save vault after command execution
    #[arg(long)]
    pub save: bool,
    
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Save vault data to disk
    Save {},
    
    /// Store a key-value pair in the vault
    Put { 
        /// The key to store
        key: String, 
        /// The value to store
        value: String 
    },
    
    /// Retrieve a value from the vault
    Get { 
        /// The key to retrieve
        key: String 
    },
    
    /// Delete a key from the vault
    Delete { 
        /// The key to delete
        key: String 
    },
    
    /// List all keys in the vault
    List {},
    
    /// Find keys matching a pattern
    Find { 
        /// Regular expression pattern to match keys
        pattern: String 
    },
    
    /// Change the vault passphrase
    ChangePassphrase {
        /// Current passphrase (will prompt if not provided)
        #[arg(long)]
        old_passphrase: Option<String>,
        /// New passphrase (will prompt if not provided)
        #[arg(long)]
        new_passphrase: Option<String>,
    },
    
    /// Run a command with vault variables as environment variables
    Run { 
        /// Command and arguments to execute
        command: Vec<String> 
    },
    
    /// Generate a new cryptographic key
    GenerateKey {
        /// Namespace for organizing keys
        #[arg(long)]
        namespace: String,
        /// Version number for key rotation
        #[arg(long)]
        version: u32,
        /// Key size in bits (128, 192, 256, 384, or 512)
        #[arg(long, default_value = "256")]
        bits: u32,
        /// Storage backend (memory or file:<path>)
        #[arg(long, default_value = "memory")]
        store: String,
    },
    
    /// Retrieve an existing cryptographic key
    RetrieveKey {
        /// Namespace of the key to retrieve
        #[arg(long)]
        namespace: String,
        /// Version of the key to retrieve
        #[arg(long)]
        version: u32,
        /// Storage backend (memory or file:<path>)
        #[arg(long, default_value = "memory")]
        store: String,
    },
    
    /// Generate multiple keys in batch
    BatchGenerateKeys {
        /// Namespace for organizing keys
        #[arg(long)]
        namespace: String,
        /// Version number for key rotation
        #[arg(long)]
        version: u32,
        /// Key size in bits (128, 192, 256, 384, or 512)
        #[arg(long, default_value = "256")]
        bits: u32,
        /// Number of keys to generate
        #[arg(long)]
        count: usize,
        /// Storage backend (memory or file:<path>)
        #[arg(long, default_value = "memory")]
        store: String,
    },
}