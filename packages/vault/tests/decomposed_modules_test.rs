//! Test that our decomposed modules compile and work correctly

use cryypt_vault::api::{
    CompressionAlgorithm, CompressionOptimizer, ConnectionManager, ConnectionState, ErrorRecovery,
    StreamBuffer, StreamIdManager,
};
use cryypt_vault::error::VaultError;
use std::time::Duration;

#[tokio::test]
async fn test_stream_id_manager() {
    let manager = StreamIdManager::new();

    let client_bidi = manager.next_client_bidi_stream_id();
    let client_uni = manager.next_client_uni_stream_id();
    let server_bidi = manager.next_server_bidi_stream_id();
    let server_uni = manager.next_server_uni_stream_id();

    assert_eq!(client_bidi % 4, 0);
    assert_eq!(client_uni % 4, 2);
    assert_eq!(server_bidi % 4, 1);
    assert_eq!(server_uni % 4, 3);

    assert!(manager.is_client_bidi(client_bidi));
    assert!(manager.is_client_uni(client_uni));
    assert!(manager.is_server_bidi(server_bidi));
    assert!(manager.is_server_uni(server_uni));
}

#[test]
fn test_compression_optimizer() {
    let optimizer = CompressionOptimizer::new(CompressionAlgorithm::Gzip, 0.5, 1000);

    let small_data = b"hello world";
    let level = optimizer.optimize_level(small_data);
    assert!(level > 0);

    let large_data = vec![0u8; 2_000_000];
    let level = optimizer.optimize_level(&large_data);
    assert!(level > 0);
}

#[test]
fn test_stream_buffer() {
    let mut buffer = StreamBuffer::new(1024);

    let data = b"test data";
    let written = buffer.write(data);
    assert_eq!(written, data.len());

    let mut output = vec![0u8; data.len()];
    let read = buffer.read(&mut output);
    assert_eq!(read, data.len());
    assert_eq!(&output, data);

    assert!(buffer.is_empty());
    assert!(!buffer.is_full());
}

#[tokio::test]
async fn test_connection_manager() {
    let manager = ConnectionManager::new(Duration::from_secs(30));

    assert_eq!(manager.get_state().await, ConnectionState::Idle);
    assert!(!manager.is_active().await);

    manager.set_state(ConnectionState::Connected).await;
    assert_eq!(manager.get_state().await, ConnectionState::Connected);
    assert!(manager.is_active().await);

    manager.update_activity().await;
    assert!(!manager.is_timed_out().await);
}

#[test]
fn test_error_recovery() {
    let recovery = ErrorRecovery::new();

    // Test that error recovery can be created
    let test_error = VaultError::Other("test error".to_string());
    assert!(recovery.is_retryable(&test_error));
}
