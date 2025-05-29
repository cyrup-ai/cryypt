//! ZIP compression implementation

use std::io::{Write, Read};
use zip::{CompressionMethod, write::SimpleFileOptions};
use crate::{Result, CryptError};

pub fn compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buffer);
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated);
        
        zip.start_file("data", options)
            .map_err(|e| CryptError::compression(format!("Failed to start ZIP file: {}", e)))?;
        zip.write_all(data)
            .map_err(|e| CryptError::compression(format!("Failed to write to ZIP: {}", e)))?;
        zip.finish()
            .map_err(|e| CryptError::compression(format!("Failed to finish ZIP: {}", e)))?;
    }
    Ok(buffer.into_inner())
}

pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    let reader = std::io::Cursor::new(data);
    let mut archive = zip::ZipArchive::new(reader)
        .map_err(|e| CryptError::decompression(format!("Failed to read ZIP archive: {}", e)))?;
    
    let mut file = archive.by_index(0)
        .map_err(|e| CryptError::decompression(format!("Failed to access ZIP entry: {}", e)))?;
    
    let mut decompressed = Vec::new();
    file.read_to_end(&mut decompressed)
        .map_err(|e| CryptError::decompression(format!("Failed to read ZIP data: {}", e)))?;
    
    Ok(decompressed)
}

pub fn compress_with_level(data: &[u8], _level: i32) -> Result<Vec<u8>> {
    compress(data)
}