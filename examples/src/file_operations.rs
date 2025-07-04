//! File Operations Examples - Exactly matching README.md patterns
//! These examples demonstrate high-level file encryption/decryption operations

use cryypt::{Cryypt, Cipher, KeyRetriever, FileKeyStore, Compress, on_result, on_chunk, Bits};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_stream::StreamExt;
use futures::future::try_join_all;
use std::path::Path;

// Re-export all types from the file_operations module
pub use file_operations::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    file_operations::run_all_examples().await
}