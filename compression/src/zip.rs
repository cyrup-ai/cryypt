//! ZIP compression implementation

use crate::{CryptError, Result};
use std::io::{Read, Write};
use zip::{write::SimpleFileOptions, CompressionMethod};

/// Compress data using zip algorithm
///
/// # Arguments
/// * `data` - The data to compress
pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buffer);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);

        zip.start_file("data", options)
            .map_err(|e| CryptError::compression(format!("Failed to start ZIP file: {}", e)))?;
        zip.write_all(data)
            .map_err(|e| CryptError::compression(format!("Failed to write to ZIP: {}", e)))?;
        zip.finish()
            .map_err(|e| CryptError::compression(format!("Failed to finish ZIP: {}", e)))?;
    }
    Ok(buffer.into_inner())
}

/// Decompress zip compressed data
///
/// # Arguments
/// * `data` - The compressed data to decompress
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let reader = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(reader)
        .map_err(|e| CryptError::decompression(format!("Failed to read ZIP archive: {}", e)))?;

    let mut file = archive
        .by_index(0)
        .map_err(|e| CryptError::decompression(format!("Failed to access ZIP entry: {}", e)))?;

    let mut decompressed = Vec::new();
    file.read_to_end(&mut decompressed)
        .map_err(|e| CryptError::decompression(format!("Failed to read ZIP data: {}", e)))?;

    Ok(decompressed)
}

/// Compress data using zip with specified compression level
///
/// # Arguments
/// * `data` - The data to compress
/// * `level` - Compression level (0-9, higher is more compression)
pub fn compress_with_level(data: &[u8], level: i32) -> Result<Vec<u8>> {
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buffer);

        // Convert level to CompressionMethod
        let method = match level {
            0 => CompressionMethod::Stored,
            1..=9 => CompressionMethod::Deflated,
            _ => CompressionMethod::Deflated,
        };

        let options = SimpleFileOptions::default().compression_method(method);

        zip.start_file("data", options)
            .map_err(|e| CryptError::compression(format!("Failed to start ZIP file: {}", e)))?;
        zip.write_all(data)
            .map_err(|e| CryptError::compression(format!("Failed to write to ZIP: {}", e)))?;
        zip.finish()
            .map_err(|e| CryptError::compression(format!("Failed to finish ZIP: {}", e)))?;
    }
    Ok(buffer.into_inner())
}
