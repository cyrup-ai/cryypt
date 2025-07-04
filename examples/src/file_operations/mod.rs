//! File Operations Examples Module
//!
//! Contains examples demonstrating various file encryption/decryption operations
//! matching README.md patterns exactly.

// Declare submodules
pub mod high_level;
pub mod single;
pub mod streaming;
pub mod batch;

// Re-export example functions for external use
pub use batch::*;
pub use high_level::*;
pub use single::*;
pub use streaming::*;

use std::error::Error;

// Placeholder Key type for examples
#[derive(Clone)]
pub struct Key(pub Vec<u8>);

/// Main entry point for file operations examples
pub async fn run_all_examples() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    
    // Create a master key for the key store
    let master_key = vec![0u8; 32]; // In production, use a secure master key
    
    // Example 1: High-level file operations
    example_highlevel_file_ops(master_key.clone()).await?;
    
    // Example 2: Single file encryption/decryption
    example_single_file_ops(master_key.clone()).await?;
    
    // Example 3: Stream large file encryption
    example_stream_large_file(master_key.clone()).await?;
    
    // Example 4: Multiple files processing
    example_multiple_files(master_key.clone()).await?;
    
    // Example 5: Batch compress and encrypt
    example_batch_compress_encrypt(master_key).await?;
    
    Ok(())
}