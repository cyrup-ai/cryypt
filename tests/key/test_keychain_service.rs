//! Keychain service tests extracted from key/src/store/keychain_service.rs

use cryypt_key::store::{KeychainService, KeychainServiceConfig};

#[tokio::test]
async fn test_keychain_service_basic() {
    let service = KeychainService::new().expect("Keychain service should initialize successfully");
    
    // Test store and retrieve
    let test_data = b"test_secret_data".to_vec();
    service.store("test_service".to_string(), "test_key".to_string(), test_data.clone()).await.expect("Data should be stored successfully");
    
    let retrieved = service.retrieve("test_service".to_string(), "test_key".to_string()).await.expect("Data should be retrieved successfully");
    assert_eq!(retrieved, test_data);
    
    // Test exists
    let exists = service.exists("test_service".to_string(), "test_key".to_string()).await.expect("Existence check should succeed");
    assert!(exists);
    
    // Test delete
    service.delete("test_service".to_string(), "test_key".to_string()).await.expect("Data should be deleted successfully");
    
    let exists_after = service.exists("test_service".to_string(), "test_key".to_string()).await.expect("Post-deletion existence check should succeed");
    assert!(!exists_after);
}

#[tokio::test]
async fn test_keychain_service_list_unsupported() {
    let service = KeychainService::new().expect("Keychain service should initialize successfully");
    let result = service.list("test_service".to_string(), "*".to_string()).await;
    assert!(result.is_err());
    assert!(result.expect_err("List operation should fail for unsupported operation").to_string().contains("does not support listing"));
}

#[tokio::test]
async fn test_keychain_service_config() {
    let config = KeychainServiceConfig {
        channel_buffer_size: 50,
        thread_name: "test-keychain".to_string(),
    };
    let service = KeychainService::with_config(config).expect("Keychain service should initialize with custom config");
    
    // Test that service works with custom config
    let test_data = b"config_test_data".to_vec();
    service.store("test_service".to_string(), "config_test_key".to_string(), test_data.clone()).await.expect("Data should be stored with custom config");
    
    let retrieved = service.retrieve("test_service".to_string(), "config_test_key".to_string()).await.expect("Data should be retrieved with custom config");
    assert_eq!(retrieved, test_data);
    
    // Cleanup
    service.delete("test_service".to_string(), "config_test_key".to_string()).await.expect("Cleanup deletion should succeed");
}

#[tokio::test]
async fn test_keychain_service_shutdown() {
    let mut service = KeychainService::new().expect("Keychain service should initialize for shutdown test");
    
    // Test that service works before shutdown
    let test_data = b"shutdown_test_data".to_vec();
    service.store("test_service".to_string(), "shutdown_test_key".to_string(), test_data.clone()).await.expect("Data should be stored before shutdown");
    
    // Shutdown the service
    service.shutdown().await.expect("Service shutdown should complete successfully");
    
    // After shutdown, operations should fail
    let result = service.store("test_service".to_string(), "after_shutdown_key".to_string(), test_data).await;
    assert!(result.is_err());
}