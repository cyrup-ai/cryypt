//! Tests for secure nonce generation with replay protection

use cryypt::cipher::{NonceConfig, NonceManager, NonceSecretKey};
use std::time::Duration;

#[tokio::test]
async fn test_generate_and_verify() {
    let key = NonceSecretKey::generate();
    let mgr = NonceManager::new(&key, None);
    
    let nonce = mgr.generate_os().await;
    let parsed = mgr.verify(nonce.as_str()).unwrap();
    
    assert!(parsed.timestamp_ns > 0);
    assert_eq!(parsed.random.len(), 32);
}

#[tokio::test]
async fn test_replay_detection() {
    let key = NonceSecretKey::generate();
    let mgr = NonceManager::new(&key, None);
    
    let nonce = mgr.generate_os().await;
    
    // First verification should succeed
    assert!(mgr.verify(nonce.as_str()).is_ok());
    
    // Second verification should fail (replay)
    match mgr.verify(nonce.as_str()) {
        Err(e) => {
            let crypt_err = e.to_string();
            assert!(crypt_err.contains("replay detected"));
        }
        Ok(_) => panic!("Expected replay error"),
    }
}

#[tokio::test]
async fn test_expiration() {
    let key = NonceSecretKey::generate();
    let config = NonceConfig {
        ttl: Duration::from_millis(1), // Very short TTL
    };
    let mgr = NonceManager::new(&key, Some(config));
    
    let nonce = mgr.generate_os().await;
    
    // Wait for expiration
    tokio::time::sleep(Duration::from_millis(10)).await;
    
    match mgr.verify(nonce.as_str()) {
        Err(e) => {
            let crypt_err = e.to_string();
            assert!(crypt_err.contains("expired"));
        }
        Ok(_) => panic!("Expected expiration error"),
    }
}

#[tokio::test]
async fn test_bad_mac() {
    let key = NonceSecretKey::generate();
    let mgr = NonceManager::new(&key, None);
    
    let nonce = mgr.generate_os().await;
    let mut bad_nonce = nonce.as_str().to_string();
    
    // Corrupt the last character (part of MAC)
    bad_nonce.pop();
    bad_nonce.push('X');
    
    match mgr.verify(&bad_nonce) {
        Err(e) => {
            let crypt_err = e.to_string();
            assert!(crypt_err.contains("authentication tag mismatch"));
        }
        Ok(_) => panic!("Expected bad MAC error"),
    }
}

#[tokio::test]
async fn test_cleanup_expired() {
    let key = NonceSecretKey::generate();
    let config = NonceConfig {
        ttl: Duration::from_millis(50),
    };
    let mgr = NonceManager::new(&key, Some(config));
    
    // Generate several nonces
    let nonce1 = mgr.generate_os().await;
    let nonce2 = mgr.generate_os().await;
    let nonce3 = mgr.generate_os().await;
    
    // Verify them all
    mgr.verify(nonce1.as_str()).unwrap();
    mgr.verify(nonce2.as_str()).unwrap();
    mgr.verify(nonce3.as_str()).unwrap();
    
    // Wait for expiration
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    // Clean up expired entries
    mgr.cleanup_expired();
    
    // Now all should be expired but not in cache, so they fail with expired not replay
    match mgr.verify(nonce1.as_str()) {
        Err(e) => {
            let crypt_err = e.to_string();
            assert!(crypt_err.contains("expired"));
        }
        Ok(_) => panic!("Expected expiration error"),
    }
}

#[tokio::test]
async fn test_extract_cipher_nonce() {
    let key = NonceSecretKey::generate();
    let mgr = NonceManager::new(&key, None);
    
    let nonce = mgr.generate_os().await;
    
    // First verify to get the parsed data
    let parsed = mgr.verify(nonce.as_str()).unwrap();
    let ts_bytes = parsed.timestamp_ns.to_be_bytes();
    let expected_random_bytes = &parsed.random[..4];
    
    // Generate a new nonce for cipher extraction test
    let nonce2 = mgr.generate_os().await;
    let cipher_nonce = mgr.extract_cipher_nonce(&nonce2).unwrap();
    
    assert_eq!(cipher_nonce.len(), 12);
    
    // extract_cipher_nonce internally verifies, so we can't verify again
    // Just check the format is correct (8 bytes timestamp + 4 bytes random)
    // The first 8 bytes should be a valid timestamp
    let ts_from_cipher = u64::from_be_bytes(cipher_nonce[..8].try_into().unwrap());
    assert!(ts_from_cipher > 0);
    assert!(ts_from_cipher < u64::MAX);
}

#[tokio::test]
async fn test_from_bytes() {
    let mut bytes = [0u8; 64];
    bytes[0] = 0x42;
    bytes[63] = 0x24;
    
    let key = NonceSecretKey::from_bytes(bytes);
    let mgr = NonceManager::new(&key, None);
    
    let nonce = mgr.generate_os().await;
    assert!(mgr.verify(nonce.as_str()).is_ok());
}

#[tokio::test]
async fn test_encoded_length() {
    let key = NonceSecretKey::generate();
    let mgr = NonceManager::new(&key, None);
    
    let nonce = mgr.generate_os().await;
    assert_eq!(nonce.as_str().len(), 96); // ENCODED_LEN
}

#[tokio::test]
async fn test_bad_length() {
    let key = NonceSecretKey::generate();
    let mgr = NonceManager::new(&key, None);
    
    // Too short
    match mgr.verify("too_short") {
        Err(e) => {
            let crypt_err = e.to_string();
            assert!(crypt_err.contains("length mismatch"));
        }
        Ok(_) => panic!("Expected length error"),
    }
    
    // Too long
    let too_long = "x".repeat(100);
    match mgr.verify(&too_long) {
        Err(e) => {
            let crypt_err = e.to_string();
            assert!(crypt_err.contains("length mismatch"));
        }
        Ok(_) => panic!("Expected length error"),
    }
}

#[tokio::test]
async fn test_bad_base64() {
    let key = NonceSecretKey::generate();
    let mgr = NonceManager::new(&key, None);
    
    // Invalid base64 characters but right length
    let bad_b64 = "!".repeat(96);
    match mgr.verify(&bad_b64) {
        Err(e) => {
            let crypt_err = e.to_string();
            assert!(crypt_err.contains("decode failure"));
        }
        Ok(_) => panic!("Expected decode error"),
    }
}