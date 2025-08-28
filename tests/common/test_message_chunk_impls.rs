//! Tests for MessageChunk implementations in common crate
//!
//! This module tests the MessageChunk trait implementations for various chunk types.

use cryypt_common::chunk_types::*;

#[test]
fn test_chunk_types_message_chunk() {
    // Test CipherChunk
    let success_chunk = CipherChunk::new(vec![1, 2, 3, 4], "encrypt".to_string(), "aes".to_string());
    assert!(!success_chunk.is_error());
    assert_eq!(success_chunk.error(), None);

    let error_chunk = CipherChunk::bad_chunk("test error".to_string());
    assert!(error_chunk.is_error());
    assert_eq!(error_chunk.error(), Some("test error"));
}