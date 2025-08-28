//! Pattern tests extracted from async_task/src/patterns.rs
//!
//! Tests the request-response and producer-consumer patterns with proper async coordination.

use async_task::patterns::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::Duration;

#[tokio::test]
async fn test_request_response() {
    let pattern = PatternBuilder::request_response::<String, String>();
    
    // Start handler
    pattern.start_handler(|req| async move {
        format!("Response to: {}", req)
    }).await.expect("Pattern handler should start successfully");
    
    // Send request
    let response = pattern.request("Hello".to_string()).await.expect("Request should succeed");
    assert_eq!(response, "Response to: Hello");
}

#[tokio::test]
async fn test_producer_consumer() {
    let pattern = PatternBuilder::producer_consumer::<i32>(10);
    let received = Arc::new(RwLock::new(Vec::new()));
    let received_clone = Arc::clone(&received);
    
    // Start consumer
    pattern.start_consumer(move |item| {
        let received = Arc::clone(&received_clone);
        async move {
            received.write().await.push(item);
        }
    }).await.expect("Consumer should start successfully");
    
    // Produce items
    for i in 0..5 {
        pattern.produce(i).await.expect("Item production should succeed");
    }
    
    tokio::time::sleep(Duration::from_millis(100)).await;
    
    let items = received.read().await;
    assert_eq!(items.len(), 5);
}