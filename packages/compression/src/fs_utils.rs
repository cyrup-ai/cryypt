//! Filesystem utilities for path-based compression operations
//!
//! Provides functions to collect files from filesystem paths (files or directories)
//! and write compressed archives back to the filesystem with proper directory structure.

use crate::{CompressionError, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use walkdir::WalkDir;

/// Collect all files from a filesystem path (file or directory) into a HashMap
///
/// # Arguments
/// * `path` - Path to file or directory to collect
///
/// # Returns
/// HashMap with relative paths as keys and file contents as values
///
/// # Behavior
/// - Single file: Returns HashMap with just the filename as key
/// - Directory: Recursively walks all files, preserving relative path structure
/// - Follows symlinks by default
/// - Includes hidden files
/// - Empty directories are represented with a `.keep` file
///
/// # Errors
/// Returns `CompressionError` if:
/// - Path doesn't exist
/// - Permission denied
/// - I/O errors during file reading
pub async fn collect_files_from_path<P: AsRef<Path>>(path: P) -> Result<HashMap<String, Vec<u8>>> {
    let path = path.as_ref();
    
    if !path.exists() {
        return Err(CompressionError::compression_failed(format!(
            "Path does not exist: {}",
            path.display()
        )));
    }

    let mut files = HashMap::new();

    if path.is_file() {
        // Single file case
        let filename = path
            .file_name()
            .ok_or_else(|| {
                CompressionError::compression_failed(format!(
                    "Invalid filename: {}",
                    path.display()
                ))
            })?
            .to_string_lossy()
            .to_string();

        let content = fs::read(path).await.map_err(|e| {
            CompressionError::compression_failed(format!(
                "Failed to read file {}: {}",
                path.display(),
                e
            ))
        })?;

        files.insert(filename, content);
    } else if path.is_dir() {
        // Directory case - recursively walk all files
        let base_path = path.to_path_buf();
        
        // Collect entries first to avoid holding iterator across await points
        let entries: Vec<_> = WalkDir::new(path)
            .follow_links(true)
            .into_iter()
            .collect();

        let mut has_files = false;

        for entry_result in entries {
            let entry = entry_result.map_err(|e| {
                CompressionError::compression_failed(format!(
                    "Failed to walk directory: {}",
                    e
                ))
            })?;

            let entry_path = entry.path();

            // Only process files, skip directories (they're implicit in the paths)
            if entry_path.is_file() {
                has_files = true;

                // Get relative path from base directory
                let relative_path = entry_path
                    .strip_prefix(&base_path)
                    .map_err(|e| {
                        CompressionError::compression_failed(format!(
                            "Failed to get relative path: {}",
                            e
                        ))
                    })?
                    .to_string_lossy()
                    .to_string();

                // Validate path safety
                validate_path_safety(&relative_path)?;

                // Read file content
                let content = fs::read(entry_path).await.map_err(|e| {
                    CompressionError::compression_failed(format!(
                        "Failed to read file {}: {}",
                        entry_path.display(),
                        e
                    ))
                })?;

                // Yield for large operations
                let should_yield = content.len() > 8192;

                files.insert(relative_path, content);

                if should_yield {
                    tokio::task::yield_now().await;
                }
            }
        }

        // Handle empty directory
        if !has_files {
            files.insert(".keep".to_string(), Vec::new());
        }
    } else {
        return Err(CompressionError::compression_failed(format!(
            "Path is neither file nor directory: {}",
            path.display()
        )));
    }

    Ok(files)
}

/// Write files from HashMap to filesystem path
///
/// # Arguments
/// * `files` - HashMap of relative paths to file contents
/// * `path` - Output path (will be file or directory depending on content)
///
/// # Behavior
/// - Single file in HashMap: Writes to `path` as a file
/// - Multiple files: Creates `path` as directory and writes all files with structure
/// - Creates parent directories as needed
/// - Atomic operation using temporary files
/// - Skips `.keep` marker files
///
/// # Errors
/// Returns `CompressionError` if:
/// - Parent directory creation fails
/// - File write fails
/// - Path contains unsafe characters
pub async fn write_files_to_path<P: AsRef<Path>>(
    files: HashMap<String, Vec<u8>>,
    path: P,
) -> Result<()> {
    let path = path.as_ref();

    if files.is_empty() {
        return Err(CompressionError::decompression_failed(
            "No files to write".to_string()
        ));
    }

    // Filter out .keep files
    let real_files: HashMap<_, _> = files
        .into_iter()
        .filter(|(name, _)| name != ".keep")
        .collect();

    if real_files.is_empty() {
        // Only .keep file means empty directory
        fs::create_dir_all(path).await.map_err(|e| {
            CompressionError::decompression_failed(format!(
                "Failed to create directory {}: {}",
                path.display(),
                e
            ))
        })?;
        return Ok(());
    }

    if real_files.len() == 1 {
        // Single file case - write directly to path
        let (_, content) = real_files.into_iter().next().ok_or_else(|| {
            CompressionError::internal("Unexpected empty iterator".to_string())
        })?;

        // Create parent directory if needed
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent).await.map_err(|e| {
                    CompressionError::decompression_failed(format!(
                        "Failed to create parent directory {}: {}",
                        parent.display(),
                        e
                    ))
                })?;
            }
        }

        // Atomic write using temporary file
        let temp_path = path.with_extension("tmp");
        fs::write(&temp_path, content).await.map_err(|e| {
            CompressionError::decompression_failed(format!(
                "Failed to write temp file {}: {}",
                temp_path.display(),
                e
            ))
        })?;

        fs::rename(&temp_path, path).await.map_err(|e| {
            CompressionError::decompression_failed(format!(
                "Failed to rename {} to {}: {}",
                temp_path.display(),
                path.display(),
                e
            ))
        })?;
    } else {
        // Multiple files - create directory structure
        for (relative_path, content) in real_files {
            // Validate path safety
            validate_path_safety(&relative_path)?;

            let file_path = path.join(&relative_path);

            // Create parent directories
            if let Some(parent) = file_path.parent() {
                if !parent.exists() {
                    fs::create_dir_all(parent).await.map_err(|e| {
                        CompressionError::decompression_failed(format!(
                            "Failed to create directory {}: {}",
                            parent.display(),
                            e
                        ))
                    })?;
                }
            }

            // Atomic write using temporary file
            let temp_path = file_path.with_extension("tmp");
            fs::write(&temp_path, &content).await.map_err(|e| {
                CompressionError::decompression_failed(format!(
                    "Failed to write temp file {}: {}",
                    temp_path.display(),
                    e
                ))
            })?;

            fs::rename(&temp_path, &file_path).await.map_err(|e| {
                CompressionError::decompression_failed(format!(
                    "Failed to rename {} to {}: {}",
                    temp_path.display(),
                    file_path.display(),
                    e
                ))
            })?;

            // Yield for large operations
            if content.len() > 8192 {
                tokio::task::yield_now().await;
            }
        }
    }

    Ok(())
}

/// Validate that a relative path is safe and doesn't contain path traversal
///
/// # Arguments
/// * `path` - Relative path string to validate
///
/// # Errors
/// Returns `CompressionError` if path contains:
/// - `..` (parent directory traversal)
/// - Absolute path markers
/// - Other unsafe patterns
pub fn validate_path_safety(path: &str) -> Result<()> {
    // Check for parent directory traversal
    if path.contains("..") {
        return Err(CompressionError::compression_failed(format!(
            "Path contains unsafe parent directory reference: {}",
            path
        )));
    }

    // Check for absolute paths (Unix and Windows)
    if path.starts_with('/') || path.contains(':') {
        return Err(CompressionError::compression_failed(format!(
            "Path must be relative: {}",
            path
        )));
    }

    // Check for null bytes
    if path.contains('\0') {
        return Err(CompressionError::compression_failed(
            "Path contains null byte".to_string()
        ));
    }

    Ok(())
}
