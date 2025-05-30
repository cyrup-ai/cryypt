//! Unit tests for EncodableResult functionality

use cryypt::cipher::encryption_result::EncodableResult;
use std::fs;

#[tokio::test]
async fn test_encodable_result_new() {
    let data = vec![1, 2, 3, 4, 5];
    let result = EncodableResult::new(data.clone());
    assert_eq!(result.to_bytes(), data);
}

#[tokio::test]
async fn test_encodable_result_from_vec() {
    let data = vec![1, 2, 3, 4, 5];
    let result: EncodableResult = data.clone().into();
    assert_eq!(result.to_bytes(), data);
}

#[tokio::test]
async fn test_encodable_result_into_vec() {
    let data = vec![1, 2, 3, 4, 5];
    let result = EncodableResult::new(data.clone());
    let extracted: Vec<u8> = result.into();
    assert_eq!(extracted, data);
}

#[tokio::test]
async fn test_to_base64() {
    let data = b"Hello, World!";
    let result = EncodableResult::new(data.to_vec());
    let base64 = result.to_base64();
    
    // Verify it's valid base64 and can be decoded back
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD.decode(&base64).unwrap();
    assert_eq!(decoded, data);
}

#[tokio::test]
async fn test_to_hex() {
    let data = b"Hello, World!";
    let result = EncodableResult::new(data.to_vec());
    let hex_string = result.to_hex();
    
    // Verify it's valid hex and can be decoded back
    let decoded = hex::decode(&hex_string).unwrap();
    assert_eq!(decoded, data);
}

#[tokio::test]
async fn test_to_bytes() {
    let data = vec![0x00, 0x01, 0x02, 0xFF];
    let result = EncodableResult::new(data.clone());
    assert_eq!(result.to_bytes(), data);
}

#[tokio::test]
async fn test_to_string_valid_utf8() {
    let text = "Hello, 世界! 🌍";
    let result = EncodableResult::new(text.as_bytes().to_vec());
    let decoded = result.to_string().unwrap();
    assert_eq!(decoded, text);
}

#[tokio::test]
async fn test_to_string_invalid_utf8() {
    let invalid_utf8 = vec![0xFF, 0xFE, 0xFD];
    let result = EncodableResult::new(invalid_utf8);
    let error = result.to_string().unwrap_err();
    assert!(matches!(error, cryypt::CryptError::InvalidEncryptedData(_)));
}

#[tokio::test]
async fn test_to_string_lossy() {
    let invalid_utf8 = vec![0x48, 0x65, 0x6C, 0x6C, 0x6F, 0xFF, 0x21]; // "Hello" + invalid byte + "!"
    let result = EncodableResult::new(invalid_utf8);
    let decoded = result.to_string_lossy();
    assert!(decoded.contains("Hello"));
    assert!(decoded.contains("!"));
    // Should contain replacement character for invalid byte
    assert!(decoded.contains('\u{FFFD}'));
}

#[tokio::test]
async fn test_to_file() -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = "/tmp/encodable_result_test";
    fs::create_dir_all(test_dir)?;
    
    let data = b"Test file content";
    let result = EncodableResult::new(data.to_vec());
    let file_path = format!("{}/test_output.bin", test_dir);
    
    result.to_file(&file_path).await?;
    
    // Verify file was written correctly
    let read_data = fs::read(&file_path)?;
    assert_eq!(read_data, data);
    
    // Cleanup
    fs::remove_dir_all(test_dir).ok();
    Ok(())
}

#[tokio::test]
async fn test_to_file_io_error() {
    let invalid_path = "/nonexistent/directory/file.txt";
    let result = EncodableResult::new(vec![1, 2, 3]);
    
    let error = result.to_file(invalid_path).await.unwrap_err();
    assert!(matches!(error, cryypt::CryptError::Io(_)));
}

#[tokio::test]
async fn test_len() {
    let data = vec![1, 2, 3, 4, 5];
    let result = EncodableResult::new(data.clone());
    assert_eq!(result.len(), data.len());
}

#[tokio::test]
async fn test_len_empty() {
    let result = EncodableResult::new(Vec::new());
    assert_eq!(result.len(), 0);
}

#[tokio::test]
async fn test_is_empty() {
    let empty_result = EncodableResult::new(Vec::new());
    assert!(empty_result.is_empty());
    
    let non_empty_result = EncodableResult::new(vec![1]);
    assert!(!non_empty_result.is_empty());
}

#[tokio::test]
async fn test_as_ref() {
    let data = vec![1, 2, 3, 4, 5];
    let result = EncodableResult::new(data.clone());
    let slice: &[u8] = result.as_ref();
    assert_eq!(slice, &data[..]);
}

#[tokio::test]
async fn test_base64_roundtrip() {
    let original = "This is a test message with various characters: 123 !@# 世界".as_bytes();
    let result = EncodableResult::new(original.to_vec());
    let base64 = result.to_base64();
    
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD.decode(&base64).unwrap();
    assert_eq!(decoded, original);
}

#[tokio::test]
async fn test_hex_roundtrip() {
    let original = b"Binary data \x00\x01\x02\xFF\xAB\xCD\xEF";
    let result = EncodableResult::new(original.to_vec());
    let hex_string = result.to_hex();
    
    let decoded = hex::decode(&hex_string).unwrap();
    assert_eq!(decoded, original);
}

#[tokio::test]
async fn test_large_data() {
    // Test with larger data to ensure no memory issues
    let large_data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
    let result = EncodableResult::new(large_data.clone());
    
    assert_eq!(result.len(), 10000);
    assert_eq!(result.to_bytes(), large_data);
    
    // Test encoding/decoding large data
    let base64 = result.to_base64();
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD.decode(&base64).unwrap();
    assert_eq!(decoded, large_data);
}

#[tokio::test]
async fn test_zero_length_data() {
    let result = EncodableResult::new(Vec::new());
    
    assert_eq!(result.len(), 0);
    assert!(result.is_empty());
    assert_eq!(result.to_bytes(), Vec::<u8>::new());
    assert_eq!(result.to_base64(), "");
    assert_eq!(result.to_hex(), "");
    assert_eq!(result.to_string().unwrap(), "");
}