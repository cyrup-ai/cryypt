//! Secure file operations module
//!
//! Provides secure file handling with atomic operations, proper permissions,
//! and protection against race conditions and file system attacks.

use async_task::{AsyncTask, TaskResult};
use std::fs::{File, OpenOptions, Permissions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use thiserror::Error;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

/// Secure file operation errors
#[derive(Error, Debug)]
pub enum SecureFileError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("File already exists: {0}")]
    FileExists(String),

    #[error("Atomic operation failed: {0}")]
    AtomicOperationFailed(String),

    #[error("Secure temp file creation failed: {0}")]
    TempFileCreationFailed(String),
}

/// Secure file operations trait
pub trait SecureFileOperations {
    /// Create file with secure permissions (600 - owner read/write only)
    fn create_secure_file(
        &self,
        path: &Path,
        data: &[u8],
    ) -> AsyncTask<Result<(), SecureFileError>>;

    /// Read file with security validation
    fn read_secure_file(&self, path: &Path) -> AsyncTask<Result<Vec<u8>, SecureFileError>>;

    /// Atomic file replacement using temp file + rename
    fn atomic_replace(&self, path: &Path, data: &[u8]) -> AsyncTask<Result<(), SecureFileError>>;

    /// Secure file deletion with overwrite
    fn secure_delete(&self, path: &Path) -> AsyncTask<Result<(), SecureFileError>>;
}

/// Production secure file operations implementation
pub struct ProductionSecureFileOps;

impl SecureFileOperations for ProductionSecureFileOps {
    fn create_secure_file(
        &self,
        path: &Path,
        data: &[u8],
    ) -> AsyncTask<Result<(), SecureFileError>> {
        let path = Arc::new(path.to_path_buf());
        let data = Arc::new(data.to_vec());
        AsyncTask::new(move || {
            let path = Arc::clone(&path);
            let data = Arc::clone(&data);
            async move { Ok(Self::create_secure_file_impl(&path, &data).await) }
        })
    }

    fn read_secure_file(&self, path: &Path) -> AsyncTask<Result<Vec<u8>, SecureFileError>> {
        let path = Arc::new(path.to_path_buf());
        AsyncTask::new(move || {
            let path = Arc::clone(&path);
            async move { Ok(Self::read_secure_file_impl(&path).await) }
        })
    }

    fn atomic_replace(&self, path: &Path, data: &[u8]) -> AsyncTask<Result<(), SecureFileError>> {
        let path = Arc::new(path.to_path_buf());
        let data = Arc::new(data.to_vec());
        AsyncTask::new(move || {
            let path = Arc::clone(&path);
            let data = Arc::clone(&data);
            async move { Ok(Self::atomic_replace_impl(&path, &data).await) }
        })
    }

    fn secure_delete(&self, path: &Path) -> AsyncTask<Result<(), SecureFileError>> {
        let path = Arc::new(path.to_path_buf());
        AsyncTask::new(move || {
            let path = Arc::clone(&path);
            async move { Ok(Self::secure_delete_impl(&path).await) }
        })
    }
}

impl ProductionSecureFileOps {
    async fn create_secure_file_impl(path: &Path, data: &[u8]) -> Result<(), SecureFileError> {
        // Check if file already exists to prevent accidental overwrites
        if path.exists() {
            return Err(SecureFileError::FileExists(path.display().to_string()));
        }

        // Create file with secure permissions (600)
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600) // Owner read/write only
            .open(path)?;

        // Write data
        use std::io::Write;
        file.write_all(data)?;
        file.sync_all()?; // Ensure data is written to disk

        Ok(())
    }

    async fn read_secure_file_impl(path: &Path) -> Result<Vec<u8>, SecureFileError> {
        // Validate file permissions before reading
        let metadata = fs::metadata(path).await?;
        let permissions = metadata.permissions();

        // Check that file is not world-readable (security requirement)
        if permissions.mode() & 0o044 != 0 {
            return Err(SecureFileError::PermissionDenied(format!(
                "File {} has unsafe permissions: {:o}",
                path.display(),
                permissions.mode()
            )));
        }

        // Read file content
        let data = fs::read(path).await?;
        Ok(data)
    }

    async fn atomic_replace_impl(path: &Path, data: &[u8]) -> Result<(), SecureFileError> {
        // Create secure temporary file in same directory as target
        let temp_path = path.with_extension(format!("tmp.{}", Uuid::new_v4()));

        // Write to temp file with secure permissions
        {
            let mut temp_file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temp_path)?;

            use std::io::Write;
            temp_file.write_all(data)?;
            temp_file.sync_all()?;
        }

        // Atomic rename (this is atomic on most filesystems)
        fs::rename(&temp_path, path).await.map_err(|e| {
            // Clean up temp file on failure
            let _ = std::fs::remove_file(&temp_path);
            SecureFileError::AtomicOperationFailed(format!("Rename failed: {}", e))
        })?;

        Ok(())
    }

    async fn secure_delete_impl(path: &Path) -> Result<(), SecureFileError> {
        // Get file size for overwrite
        let metadata = fs::metadata(path).await?;
        let file_size = metadata.len() as usize;

        // Overwrite with random data (basic secure deletion)
        if file_size > 0 {
            use rand::RngCore;
            let mut random_data = vec![0u8; file_size];
            rand::rng().fill_bytes(&mut random_data);

            let mut file = OpenOptions::new().write(true).truncate(false).open(path)?;

            use std::io::{Seek, SeekFrom, Write};
            file.seek(SeekFrom::Start(0))?;
            file.write_all(&random_data)?;
            file.sync_all()?;
        }

        // Remove file
        fs::remove_file(path).await?;

        Ok(())
    }
}

/// Atomic file writer for safe file operations
pub struct AtomicFileWriter {
    target_path: PathBuf,
    temp_path: PathBuf,
    temp_file: Option<File>,
}

impl AtomicFileWriter {
    /// Create new atomic file writer
    pub fn new(target_path: PathBuf) -> Result<Self, SecureFileError> {
        let temp_path = target_path.with_extension(format!("tmp.{}", Uuid::new_v4()));

        Ok(Self {
            target_path,
            temp_path,
            temp_file: None,
        })
    }

    /// Start writing (creates temp file)
    pub async fn start_write(&mut self) -> Result<(), SecureFileError> {
        let temp_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&self.temp_path)?;

        self.temp_file = Some(temp_file);
        Ok(())
    }

    /// Write data chunk
    pub async fn write_chunk(&mut self, data: &[u8]) -> Result<(), SecureFileError> {
        if let Some(ref mut file) = self.temp_file {
            use std::io::Write;
            file.write_all(data)?;
            Ok(())
        } else {
            Err(SecureFileError::AtomicOperationFailed(
                "Writer not started".to_string(),
            ))
        }
    }

    /// Commit the write (atomic rename)
    pub async fn commit(mut self) -> Result<(), SecureFileError> {
        if let Some(file) = self.temp_file.take() {
            use std::io::Write;
            file.sync_all()?;
            drop(file);

            // Atomic rename
            fs::rename(&self.temp_path, &self.target_path)
                .await
                .map_err(|e| {
                    let _ = std::fs::remove_file(&self.temp_path);
                    SecureFileError::AtomicOperationFailed(format!("Commit failed: {}", e))
                })?;

            Ok(())
        } else {
            Err(SecureFileError::AtomicOperationFailed(
                "No data to commit".to_string(),
            ))
        }
    }

    /// Abort the write (cleanup temp file)
    pub async fn abort(mut self) -> Result<(), SecureFileError> {
        self.temp_file.take(); // Take ownership to avoid Drop conflict
        if self.temp_path.exists() {
            fs::remove_file(&self.temp_path).await?;
        }
        Ok(())
    }
}

impl Drop for AtomicFileWriter {
    fn drop(&mut self) {
        // Cleanup temp file on drop
        if self.temp_path.exists() {
            let _ = std::fs::remove_file(&self.temp_path);
        }
    }
}

/// Secure temporary file with automatic cleanup
pub struct SecureTempFile {
    path: PathBuf,
    _file: File,
}

impl SecureTempFile {
    /// Create secure temporary file
    pub fn new() -> Result<Self, SecureFileError> {
        let temp_dir = std::env::temp_dir();
        let temp_name = format!("cryypt_secure_{}.tmp", Uuid::new_v4());
        let temp_path = temp_dir.join(temp_name);

        let file = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&temp_path)?;

        Ok(Self {
            path: temp_path,
            _file: file,
        })
    }

    /// Get path to temp file
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SecureTempFile {
    fn drop(&mut self) {
        // Secure deletion on drop
        if self.path.exists() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_atomic_file_writer() {
        let temp_dir = tempdir().unwrap();
        let target_path = temp_dir.path().join("test.txt");

        let mut writer = AtomicFileWriter::new(target_path.clone()).unwrap();
        writer.start_write().await.unwrap();
        writer.write_chunk(b"Hello, ").await.unwrap();
        writer.write_chunk(b"World!").await.unwrap();
        writer.commit().await.unwrap();

        let content = fs::read_to_string(&target_path).await.unwrap();
        assert_eq!(content, "Hello, World!");
    }

    #[tokio::test]
    async fn test_secure_temp_file() {
        let temp_file = SecureTempFile::new().unwrap();
        let path = temp_file.path().to_path_buf();

        assert!(path.exists());
        drop(temp_file);
        assert!(!path.exists());
    }
}
