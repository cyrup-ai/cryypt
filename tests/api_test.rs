//! Test the new fluent API

use cyrup_crypt::{Cipher, KeyId, CryptError, Result};
use std::sync::Arc;

#[derive(Debug, Clone)]
struct TestKeyId {
    id: String,
    version: u32,
}

impl KeyId for TestKeyId {
    fn id(&self) -> &str {
        &self.id
    }
    
    fn version(&self) -> u32 {
        self.version
    }
    
    fn clone_box(&self) -> Box<dyn KeyId> {
        Box::new(self.clone())
    }
}

impl std::fmt::Display for TestKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.id, self.version)
    }
}

#[tokio::test]
async fn test_aes_encryption() -> Result<()> {
    let key_id = Arc::new(TestKeyId {
        id: "test-key".to_string(),
        version: 1,
    });
    
    let plaintext = b"Hello, World!";
    
    let encrypted = Cipher::aes()
        .with_key(key_id)
        .with_data(plaintext)
        .encrypt()
        .await?;
    
    // Encrypted data should have nonce (12 bytes) + ciphertext + tag (16 bytes)
    assert!(encrypted.len() > plaintext.len() + 12 + 16);
    
    Ok(())
}

#[tokio::test]
async fn test_chacha_encryption() -> Result<()> {
    let key_id = Arc::new(TestKeyId {
        id: "test-key".to_string(),
        version: 1,
    });
    
    let plaintext = b"Hello, ChaCha!";
    
    let encrypted = Cipher::chachapoly()
        .with_key(key_id)
        .with_data(plaintext)
        .encrypt()
        .await?;
    
    // Encrypted data should have nonce (12 bytes) + ciphertext + tag (16 bytes)
    assert!(encrypted.len() > plaintext.len() + 12 + 16);
    
    Ok(())
}