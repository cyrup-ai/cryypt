//! ZIP compression implementation

use crate::{CompressionError, Result};
use std::io::{Read, Write};
use zip::{CompressionMethod, write::SimpleFileOptions};

/// Compress data using zip algorithm
///
/// # Arguments
/// * `data` - The data to compress
///
/// # Errors
/// Returns `CompressionError` if ZIP compression fails
pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buffer);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

        zip.start_file("data", options).map_err(|e| {
            CompressionError::compression_failed(format!("Failed to start ZIP file: {e}"))
        })?;
        zip.write_all(data).map_err(|e| {
            CompressionError::compression_failed(format!("Failed to write to ZIP: {e}"))
        })?;
        zip.finish().map_err(|e| {
            CompressionError::compression_failed(format!("Failed to finish ZIP: {e}"))
        })?;
    }
    Ok(buffer.into_inner())
}

/// Decompress zip compressed data
///
/// # Arguments
/// * `data` - The compressed data to decompress
///
/// # Errors
/// Returns `CompressionError` if ZIP decompression fails
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let reader = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| {
        CompressionError::decompression_failed(format!("Failed to read ZIP archive: {e}"))
    })?;

    let mut file = archive.by_index(0).map_err(|e| {
        CompressionError::decompression_failed(format!("Failed to access ZIP entry: {e}"))
    })?;

    let mut decompressed = Vec::new();
    file.read_to_end(&mut decompressed).map_err(|e| {
        CompressionError::decompression_failed(format!("Failed to read ZIP data: {e}"))
    })?;

    Ok(decompressed)
}

/// Compress data using zip with specified compression level
///
/// # Arguments
/// * `data` - The data to compress
/// * `level` - Compression level (0-9, higher is more compression)
///
/// # Errors
/// Returns `CompressionError` if ZIP compression fails
pub fn compress_with_level(data: &[u8], level: i32) -> Result<Vec<u8>> {
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buffer);

        // Convert level to CompressionMethod
        let method = match level {
            0 => CompressionMethod::Stored,
            _ => CompressionMethod::Deflated,
        };

        let options = SimpleFileOptions::default().compression_method(method);

        zip.start_file("data", options).map_err(|e| {
            CompressionError::compression_failed(format!("Failed to start ZIP file: {e}"))
        })?;
        zip.write_all(data).map_err(|e| {
            CompressionError::compression_failed(format!("Failed to write to ZIP: {e}"))
        })?;
        zip.finish().map_err(|e| {
            CompressionError::compression_failed(format!("Failed to finish ZIP: {e}"))
        })?;
    }
    Ok(buffer.into_inner())
}

/// Compress multiple files into a ZIP archive
///
/// # Arguments
/// * `files` - `HashMap` of filename -> file data
///
/// # Errors
/// Returns `CompressionError` if ZIP compression fails
pub fn compress_files<H: std::hash::BuildHasher>(
    files: std::collections::HashMap<String, Vec<u8>, H>,
) -> Result<Vec<u8>> {
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buffer);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

        for (filename, data) in files {
            zip.start_file(&filename, options).map_err(|e| {
                CompressionError::compression_failed(format!(
                    "Failed to start ZIP file '{filename}': {e}"
                ))
            })?;
            zip.write_all(&data).map_err(|e| {
                CompressionError::compression_failed(format!(
                    "Failed to write to ZIP file '{filename}': {e}"
                ))
            })?;
        }

        zip.finish().map_err(|e| {
            CompressionError::compression_failed(format!("Failed to finish ZIP archive: {e}"))
        })?;
    }
    Ok(buffer.into_inner())
}

/// Extract all files from a ZIP archive
///
/// # Arguments
/// * `data` - The compressed ZIP archive data
///
/// # Returns
/// * `HashMap` of filename -> file data
///
/// # Errors
/// Returns `CompressionError` if ZIP decompression fails
pub fn decompress_files(data: &[u8]) -> Result<std::collections::HashMap<String, Vec<u8>>> {
    let reader = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(reader).map_err(|e| {
        CompressionError::decompression_failed(format!("Failed to read ZIP archive: {e}"))
    })?;

    let mut files = std::collections::HashMap::new();

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).map_err(|e| {
            CompressionError::decompression_failed(format!("Failed to access ZIP entry {i}: {e}"))
        })?;

        let filename = file.name().to_string();
        let mut content = Vec::new();
        file.read_to_end(&mut content).map_err(|e| {
            CompressionError::decompression_failed(format!(
                "Failed to read ZIP file '{filename}': {e}"
            ))
        })?;

        files.insert(filename, content);
    }

    Ok(files)
}
