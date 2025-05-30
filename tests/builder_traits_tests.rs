//! Unit tests for builder traits functionality

use cryypt::prelude::*;
use std::fs;

struct MockKeyProvider;
impl cryypt::cipher::api::builder_traits::KeyProviderBuilder for MockKeyProvider {
    fn resolve(&self) -> cryypt::key::KeyResult {
        cryypt::key::KeyResult::new(vec![42u8; 32], "test_id".to_string())
    }
}

struct MockDataBuilder {
    data: Vec<u8>,
}

impl cryypt::cipher::api::builder_traits::DataBuilder for MockDataBuilder {
    type Output = MockDataBuilderOutput;

    fn with_data<T: Into<Vec<u8>>>(self, data: T) -> Self::Output {
        MockDataBuilderOutput {
            original_data: self.data,
            new_data: data.into(),
        }
    }
}

struct MockDataBuilderOutput {
    original_data: Vec<u8>,
    new_data: Vec<u8>,
}

struct MockCiphertextBuilder {
    data: Vec<u8>,
}

impl cryypt::cipher::api::builder_traits::CiphertextBuilder for MockCiphertextBuilder {
    type Output = MockCiphertextBuilderOutput;

    fn with_ciphertext<T: Into<Vec<u8>>>(self, ciphertext: T) -> Self::Output {
        MockCiphertextBuilderOutput {
            original_data: self.data,
            ciphertext: ciphertext.into(),
        }
    }
}

struct MockCiphertextBuilderOutput {
    original_data: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[tokio::test]
async fn test_data_builder_with_data() {
    let builder = MockDataBuilder {
        data: vec![1, 2, 3],
    };
    let output = builder.with_data(vec![4, 5, 6]);
    assert_eq!(output.original_data, vec![1, 2, 3]);
    assert_eq!(output.new_data, vec![4, 5, 6]);
}

#[tokio::test]
async fn test_data_builder_with_text() {
    let builder = MockDataBuilder {
        data: vec![1, 2, 3],
    };
    let output = builder.with_text("Hello");
    assert_eq!(output.new_data, b"Hello");
}

#[tokio::test]
async fn test_data_builder_with_data_base64() -> Result<(), Box<dyn std::error::Error>> {
    let builder = MockDataBuilder {
        data: vec![1, 2, 3],
    };
    
    // Valid base64
    let output = builder.with_data_base64("SGVsbG8=")?; // "Hello" in base64
    assert_eq!(output.new_data, b"Hello");
    
    Ok(())
}

#[tokio::test]
async fn test_data_builder_with_data_base64_invalid() {
    let builder = MockDataBuilder {
        data: vec![1, 2, 3],
    };
    
    // Invalid base64
    let result = builder.with_data_base64("InvalidBase64!!!");
    assert!(result.is_err());
}

#[tokio::test]
async fn test_data_builder_with_data_hex() -> Result<(), Box<dyn std::error::Error>> {
    let builder = MockDataBuilder {
        data: vec![1, 2, 3],
    };
    
    // Valid hex
    let output = builder.with_data_hex("48656c6c6f")?; // "Hello" in hex
    assert_eq!(output.new_data, b"Hello");
    
    Ok(())
}

#[tokio::test]
async fn test_data_builder_with_data_hex_invalid() {
    let builder = MockDataBuilder {
        data: vec![1, 2, 3],
    };
    
    // Invalid hex (odd length)
    let result = builder.with_data_hex("48656c6c6");
    assert!(result.is_err());
    
    // Invalid hex (non-hex characters)
    let result = builder.with_data_hex("48656z6c6f");
    assert!(result.is_err());
}

#[tokio::test]
async fn test_data_builder_with_file() -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = "/tmp/builder_traits_test";
    fs::create_dir_all(test_dir)?;
    
    let test_file = format!("{}/test.txt", test_dir);
    let test_content = b"Test file content";
    fs::write(&test_file, test_content)?;
    
    let builder = MockDataBuilder {
        data: vec![1, 2, 3],
    };
    
    let output = builder.with_file(&test_file).await?;
    assert_eq!(output.new_data, test_content);
    
    // Cleanup
    fs::remove_dir_all(test_dir).ok();
    Ok(())
}

#[tokio::test]
async fn test_data_builder_with_file_not_found() {
    let builder = MockDataBuilder {
        data: vec![1, 2, 3],
    };
    
    let result = builder.with_file("/nonexistent/file.txt").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), cryypt::CryptError::Io(_)));
}

#[tokio::test]
async fn test_ciphertext_builder_with_ciphertext() {
    let builder = MockCiphertextBuilder {
        data: vec![1, 2, 3],
    };
    let output = builder.with_ciphertext(vec![4, 5, 6]);
    assert_eq!(output.original_data, vec![1, 2, 3]);
    assert_eq!(output.ciphertext, vec![4, 5, 6]);
}

#[tokio::test]
async fn test_ciphertext_builder_with_ciphertext_base64() -> Result<(), Box<dyn std::error::Error>> {
    let builder = MockCiphertextBuilder {
        data: vec![1, 2, 3],
    };
    
    // Valid base64
    let output = builder.with_ciphertext_base64("SGVsbG8=")?; // "Hello" in base64
    assert_eq!(output.ciphertext, b"Hello");
    
    Ok(())
}

#[tokio::test]
async fn test_ciphertext_builder_with_ciphertext_base64_invalid() {
    let builder = MockCiphertextBuilder {
        data: vec![1, 2, 3],
    };
    
    // Invalid base64
    let result = builder.with_ciphertext_base64("InvalidBase64!!!");
    assert!(result.is_err());
}

#[tokio::test]
async fn test_ciphertext_builder_with_ciphertext_hex() -> Result<(), Box<dyn std::error::Error>> {
    let builder = MockCiphertextBuilder {
        data: vec![1, 2, 3],
    };
    
    // Valid hex
    let output = builder.with_ciphertext_hex("48656c6c6f")?; // "Hello" in hex
    assert_eq!(output.ciphertext, b"Hello");
    
    Ok(())
}

#[tokio::test]
async fn test_ciphertext_builder_with_ciphertext_hex_invalid() {
    let builder = MockCiphertextBuilder {
        data: vec![1, 2, 3],
    };
    
    // Invalid hex
    let result = builder.with_ciphertext_hex("InvalidHex!!!");
    assert!(result.is_err());
}

#[tokio::test]
async fn test_ciphertext_builder_with_ciphertext_file() -> Result<(), Box<dyn std::error::Error>> {
    let test_dir = "/tmp/ciphertext_builder_test";
    fs::create_dir_all(test_dir)?;
    
    let test_file = format!("{}/ciphertext.bin", test_dir);
    let test_content = b"Test ciphertext content";
    fs::write(&test_file, test_content)?;
    
    let builder = MockCiphertextBuilder {
        data: vec![1, 2, 3],
    };
    
    let output = builder.with_ciphertext_file(&test_file).await?;
    assert_eq!(output.ciphertext, test_content);
    
    // Cleanup
    fs::remove_dir_all(test_dir).ok();
    Ok(())
}

#[tokio::test]
async fn test_ciphertext_builder_with_ciphertext_file_not_found() {
    let builder = MockCiphertextBuilder {
        data: vec![1, 2, 3],
    };
    
    let result = builder.with_ciphertext_file("/nonexistent/ciphertext.bin").await;
    assert!(result.is_err());
    assert!(matches!(result.unwrap_err(), cryypt::CryptError::Io(_)));
}

#[tokio::test]
async fn test_base64_edge_cases() -> Result<(), Box<dyn std::error::Error>> {
    let builder = MockDataBuilder {
        data: vec![],
    };
    
    // Empty base64
    let output = builder.with_data_base64("")?;
    assert_eq!(output.new_data, Vec::<u8>::new());
    
    Ok(())
}

#[tokio::test]
async fn test_hex_edge_cases() -> Result<(), Box<dyn std::error::Error>> {
    let builder = MockDataBuilder {
        data: vec![],
    };
    
    // Empty hex
    let output = builder.with_data_hex("")?;
    assert_eq!(output.new_data, Vec::<u8>::new());
    
    // Uppercase hex
    let output = builder.with_data_hex("48656C6C6F")?; // "Hello" in uppercase hex
    assert_eq!(output.new_data, b"Hello");
    
    Ok(())
}

#[tokio::test]
async fn test_unicode_text() {
    let builder = MockDataBuilder {
        data: vec![],
    };
    
    let unicode_text = "Hello, 世界! 🌍 Emoji test";
    let output = builder.with_text(unicode_text);
    assert_eq!(output.new_data, unicode_text.as_bytes());
}

#[tokio::test]
async fn test_binary_data() {
    let builder = MockDataBuilder {
        data: vec![],
    };
    
    let binary_data = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];
    let output = builder.with_data(binary_data.clone());
    assert_eq!(output.new_data, binary_data);
}

#[tokio::test]
async fn test_large_data() {
    let builder = MockDataBuilder {
        data: vec![],
    };
    
    // Test with large data
    let large_data: Vec<u8> = (0..10000).map(|i| (i % 256) as u8).collect();
    let output = builder.with_data(large_data.clone());
    assert_eq!(output.new_data, large_data);
    assert_eq!(output.new_data.len(), 10000);
}

#[test]
fn test_key_provider_builder_resolve() {
    let provider = MockKeyProvider;
    let key_result = provider.resolve();
    assert_eq!(key_result.key_data(), &vec![42u8; 32]);
    assert_eq!(key_result.key_id(), "test_id");
}

#[tokio::test]
async fn test_data_from_into_conversions() {
    let builder = MockDataBuilder {
        data: vec![1, 2, 3],
    };
    
    // Test with different Into<Vec<u8>> types
    let output1 = builder.with_data(b"test".to_vec());
    assert_eq!(output1.new_data, b"test");
    
    let builder = MockDataBuilder {
        data: vec![1, 2, 3],
    };
    let output2 = builder.with_data([1u8, 2, 3, 4].to_vec());
    assert_eq!(output2.new_data, vec![1, 2, 3, 4]);
}