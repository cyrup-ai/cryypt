//! Request Processing Pipeline for JSON-RPC 2.0
//!
//! Implements concurrent batch processing with proper error handling, request validation,
//! and response generation following JSON-RPC 2.0 specification requirements.

use super::{
    buffers::{BufferPool, ConnectionBuffers},
    registry::JsonRpcRegistry as RpcMethodRegistry,
    types::{BatchRequest, BatchResponse, Id, Request, Response, Result, RpcError, RpcResponse},
};
use simd_json::OwnedValue;
use std::sync::Arc;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, trace, warn};

/// Configuration for the request processor
#[derive(Debug, Clone)]
pub struct ProcessorConfig {
    /// Maximum number of concurrent requests per batch
    pub max_concurrent_requests: usize,
    /// Maximum batch size allowed
    pub max_batch_size: usize,
    /// Request timeout in milliseconds
    pub request_timeout_ms: u64,
    /// Enable request validation
    pub validate_requests: bool,
    /// Enable response compression
    pub enable_compression: bool,
}

impl Default for ProcessorConfig {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 100,
            max_batch_size: 50,
            request_timeout_ms: 30000, // 30 seconds
            validate_requests: true,
            enable_compression: false,
        }
    }
}

/// Statistics for request processing
#[derive(Debug, Clone)]
pub struct ProcessorStats {
    /// Total requests processed
    pub total_requests: u64,
    /// Total batch requests processed
    pub total_batches: u64,
    /// Total errors encountered
    pub total_errors: u64,
    /// Average processing time in microseconds
    pub avg_processing_time_us: f64,
    /// Current active requests
    pub active_requests: usize,
    /// Peak concurrent requests
    pub peak_concurrent_requests: usize,
}

/// Core request processor for JSON-RPC 2.0
pub struct RequestProcessor {
    /// Method registry for RPC calls
    registry: Arc<RpcMethodRegistry>,
    /// Buffer pool for zero-allocation parsing
    buffer_pool: Arc<BufferPool>,
    /// Concurrency control
    concurrency_limiter: Arc<Semaphore>,
    /// Processor configuration
    config: ProcessorConfig,
    /// Processing statistics
    stats: Arc<tokio::sync::Mutex<ProcessorStats>>,
}

impl RequestProcessor {
    /// Create a new request processor
    pub fn new(
        registry: Arc<RpcMethodRegistry>,
        buffer_pool: Arc<BufferPool>,
        config: ProcessorConfig,
    ) -> Self {
        let concurrency_limiter = Arc::new(Semaphore::new(config.max_concurrent_requests));

        Self {
            registry,
            buffer_pool,
            concurrency_limiter,
            config,
            stats: Arc::new(tokio::sync::Mutex::new(ProcessorStats {
                total_requests: 0,
                total_batches: 0,
                total_errors: 0,
                avg_processing_time_us: 0.0,
                active_requests: 0,
                peak_concurrent_requests: 0,
            })),
        }
    }

    /// Process raw JSON-RPC data and return response
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - JSON parsing fails due to invalid syntax
    /// - Method dispatch fails or method not found
    /// - Method execution returns an error
    /// - Response serialization fails
    /// - Buffer pool operations fail
    pub async fn process_raw_data(
        &self,
        mut data: Vec<u8>,
        connection_id: Option<String>,
    ) -> Result<Vec<u8>> {
        let start_time = std::time::Instant::now();

        // Acquire buffer from pool
        let mut buffers = self.buffer_pool.acquire();

        // Parse JSON with zero-allocation
        let parsed_value = buffers.process_request(&mut data).map_err(|e| {
            error!("Failed to parse JSON data: {}", e);
            e
        })?;

        // Process the parsed value
        let response = self
            .process_parsed_value(parsed_value, connection_id.clone())
            .await?;

        // Serialize response back to JSON
        let response_data = Self::serialize_response(response)?;

        // Return buffer to pool
        self.buffer_pool.release(buffers);

        // Update statistics
        #[allow(clippy::cast_precision_loss)]
        let processing_time = start_time.elapsed().as_micros() as f64;
        self.update_stats(processing_time, false).await;

        trace!("Processed request in {:.2}μs", processing_time);
        Ok(response_data)
    }

    /// Process parsed JSON value (single request or batch)
    async fn process_parsed_value(
        &self,
        value: OwnedValue,
        connection_id: Option<String>,
    ) -> Result<RpcResponse> {
        // Determine if this is a batch request or single request
        match value {
            OwnedValue::Array(array) => {
                // Batch request processing
                if array.is_empty() {
                    return Err(RpcError::invalid_request("Empty batch request".to_string()));
                }

                if array.len() > self.config.max_batch_size {
                    return Err(RpcError::invalid_request(format!(
                        "Batch size {} exceeds maximum allowed size {}",
                        array.len(),
                        self.config.max_batch_size
                    )));
                }

                // Convert array of OwnedValues to Vec<Request>
                let mut requests = Vec::new();
                for item in array.into_iter() {
                    let request: Request =
                        serde_json::from_value(serde_json::to_value(item).map_err(|e| {
                            RpcError::parse_error(format!("Value conversion failed: {e}"))
                        })?)
                        .map_err(|e| {
                            RpcError::parse_error(format!("Request parsing failed: {e}"))
                        })?;
                    requests.push(request);
                }
                let batch_request = BatchRequest::new(requests);
                self.process_batch_request(batch_request, connection_id)
                    .await
            }
            OwnedValue::Object(_) => {
                // Single request processing
                let request: Request =
                    serde_json::from_value(serde_json::to_value(value).map_err(|e| {
                        RpcError::parse_error(format!("Value conversion failed: {e}"))
                    })?)
                    .map_err(|e| RpcError::parse_error(format!("Request parsing failed: {e}")))?;
                let response = self.process_single_request(request, connection_id).await?;
                Ok(RpcResponse::Single(response))
            }
            _ => Err(RpcError::invalid_request(
                "Request must be JSON object or array".to_string(),
            )),
        }
    }

    /// Process a single JSON-RPC request
    async fn process_single_request(
        &self,
        request: Request,
        connection_id: Option<String>,
    ) -> Result<Response> {
        // Validate request if enabled
        if self.config.validate_requests {
            Self::validate_request(&request)?;
        }

        // Handle notifications (no response required)
        if request.id.is_none() {
            debug!("Processing notification: {}", request.method);

            // Still call the method but don't return response
            if let Err(e) = self
                .registry
                .call_method(
                    &request.method,
                    request.params,
                    Id::Null, // Notifications use null ID
                    connection_id,
                )
                .await
            {
                warn!("Notification method '{}' failed: {}", request.method, e);
            }

            // Notifications don't return responses per JSON-RPC 2.0 spec
            return Err(RpcError::internal_error(
                "Notification processed".to_string(),
            ));
        }

        let request_id = request.id.unwrap();

        // Acquire concurrency permit
        let _permit = self
            .concurrency_limiter
            .acquire()
            .await
            .map_err(|_| RpcError::internal_error("Concurrency limit exceeded".to_string()))?;

        // Update active request count
        self.increment_active_requests().await;

        // Call the method
        let result = self
            .registry
            .call_method(
                &request.method,
                request.params,
                request_id.clone(),
                connection_id,
            )
            .await;

        // Decrement active request count
        self.decrement_active_requests().await;

        // Create response
        match result {
            Ok(result_value) => Ok(Response::success(result_value, request_id)),
            Err(error) => {
                self.increment_error_count().await;
                Ok(Response::error(error.to_error_object(), request_id))
            }
        }
    }

    /// Process a batch of JSON-RPC requests concurrently
    async fn process_batch_request(
        &self,
        batch_request: BatchRequest,
        connection_id: Option<String>,
    ) -> Result<RpcResponse> {
        let batch_size = batch_request.0.len();
        info!("Processing batch of {} requests", batch_size);

        // Update batch statistics
        self.increment_batch_count().await;

        // Process requests concurrently using tokio::spawn for each request
        let mut tasks = Vec::with_capacity(batch_size);

        for request in batch_request.0 {
            let processor = self.clone_for_task();
            let conn_id = connection_id.clone();

            let task =
                tokio::spawn(
                    async move { processor.process_single_request(request, conn_id).await },
                );

            tasks.push(task);
        }

        // Collect results, handling both successful responses and notifications
        let mut responses = Vec::new();

        for task in tasks {
            match task.await {
                Ok(Ok(response)) => {
                    responses.push(response);
                }
                Ok(Err(e)) => {
                    // Check if this was a notification (which doesn't return a response)
                    if e.to_string().contains("Notification processed") {
                        // Skip notifications - they don't generate responses
                    } else {
                        // This is a real error, create error response
                        responses.push(Response::error(e.to_error_object(), Id::Null));
                    }
                }
                Err(join_error) => {
                    error!("Task join error: {}", join_error);
                    responses.push(Response::error(
                        RpcError::internal_error("Task execution failed".to_string())
                            .to_error_object(),
                        Id::Null,
                    ));
                }
            }
        }

        // If all requests were notifications, return empty batch
        if responses.is_empty() {
            return Err(RpcError::internal_error(
                "All requests were notifications".to_string(),
            ));
        }

        Ok(RpcResponse::Batch(BatchResponse::new(responses)))
    }

    /// Validate a JSON-RPC request
    fn validate_request(request: &Request) -> Result<()> {
        // Check JSON-RPC version
        if request.jsonrpc != "2.0" {
            return Err(RpcError::invalid_request(
                "Invalid JSON-RPC version, must be '2.0'".to_string(),
            ));
        }

        // Check method name
        if request.method.is_empty() {
            return Err(RpcError::invalid_request(
                "Method name cannot be empty".to_string(),
            ));
        }

        // Check for reserved method names (starting with "rpc.")
        if request.method.starts_with("rpc.") && !Self::is_allowed_rpc_method(&request.method) {
            return Err(RpcError::method_not_found(format!(
                "Reserved method '{}' not implemented",
                request.method
            )));
        }

        Ok(())
    }

    /// Check if an "rpc." method is allowed
    fn is_allowed_rpc_method(method: &str) -> bool {
        matches!(method, "rpc.discover" | "rpc.ping" | "rpc.echo")
    }

    /// Serialize response to JSON bytes
    fn serialize_response(response: RpcResponse) -> Result<Vec<u8>> {
        let json_value = match response {
            RpcResponse::Single(response) => serde_json::to_value(response)
                .map_err(|e| RpcError::internal_error(format!("Serialization failed: {e}")))?,
            RpcResponse::Batch(responses) => serde_json::to_value(responses).map_err(|e| {
                RpcError::internal_error(format!("Batch serialization failed: {e}"))
            })?,
        };

        serde_json::to_vec(&json_value)
            .map_err(|e| RpcError::internal_error(format!("JSON encoding failed: {e}")))
    }

    /// Clone processor for concurrent task execution
    fn clone_for_task(&self) -> Self {
        Self {
            registry: Arc::clone(&self.registry),
            buffer_pool: Arc::clone(&self.buffer_pool),
            concurrency_limiter: Arc::clone(&self.concurrency_limiter),
            config: self.config.clone(),
            stats: Arc::clone(&self.stats),
        }
    }

    /// Update processing statistics
    async fn update_stats(&self, processing_time_us: f64, is_error: bool) {
        let mut stats = self.stats.lock().await;
        stats.total_requests += 1;

        if is_error {
            stats.total_errors += 1;
        }

        // Update rolling average processing time
        #[allow(clippy::cast_precision_loss)]
        let total = stats.total_requests as f64;
        stats.avg_processing_time_us =
            ((stats.avg_processing_time_us * (total - 1.0)) + processing_time_us) / total;
    }

    /// Increment batch count
    async fn increment_batch_count(&self) {
        let mut stats = self.stats.lock().await;
        stats.total_batches += 1;
    }

    /// Increment error count
    async fn increment_error_count(&self) {
        let mut stats = self.stats.lock().await;
        stats.total_errors += 1;
    }

    /// Increment active request count
    async fn increment_active_requests(&self) {
        let mut stats = self.stats.lock().await;
        stats.active_requests += 1;
        if stats.active_requests > stats.peak_concurrent_requests {
            stats.peak_concurrent_requests = stats.active_requests;
        }
    }

    /// Decrement active request count
    async fn decrement_active_requests(&self) {
        let mut stats = self.stats.lock().await;
        if stats.active_requests > 0 {
            stats.active_requests -= 1;
        }
    }

    /// Get current processing statistics
    pub async fn get_stats(&self) -> ProcessorStats {
        self.stats.lock().await.clone()
    }

    /// Get processor configuration
    #[must_use]
    pub fn get_config(&self) -> &ProcessorConfig {
        &self.config
    }

    /// Update processor configuration
    pub fn update_config(&mut self, config: ProcessorConfig) {
        // Update concurrency limiter if limit changed
        if config.max_concurrent_requests != self.config.max_concurrent_requests {
            self.concurrency_limiter = Arc::new(Semaphore::new(config.max_concurrent_requests));
        }

        self.config = config;
        info!("Processor configuration updated");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::rpc::buffers::BufferPool;
    use crate::protocols::rpc::registry::JsonRpcRegistry as RpcMethodRegistry;
    use serde_json::json;
    use simd_json::OwnedValue;

    fn create_test_processor() -> RequestProcessor {
        let registry = Arc::new(RpcMethodRegistry::new());

        // Register a test method
        registry.register("test_method", |_ctx, params| async move {
            match params {
                Some(params) => Ok(simd_json::OwnedValue::try_from(params)?),
                None => Ok(OwnedValue::from("test_result")),
            }
        });

        let buffer_pool = Arc::new(BufferPool::default());
        let config = ProcessorConfig::default();

        RequestProcessor::new(registry, buffer_pool, config)
    }

    #[tokio::test]
    async fn test_single_request_processing() {
        let processor = create_test_processor();

        let request_json = json!({
            "jsonrpc": "2.0",
            "method": "test_method",
            "params": {"test": "value"},
            "id": 1
        });

        let request_data = serde_json::to_vec(&request_json).unwrap();
        let result = processor.process_raw_data(request_data, None).await;

        assert!(result.is_ok());
        let response_data = result.unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response_data).unwrap();

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        assert!(response["result"].is_object());
    }

    #[tokio::test]
    async fn test_batch_request_processing() {
        let processor = create_test_processor();

        let batch_json = json!([
            {
                "jsonrpc": "2.0",
                "method": "test_method",
                "params": {"test": "value1"},
                "id": 1
            },
            {
                "jsonrpc": "2.0",
                "method": "test_method",
                "params": {"test": "value2"},
                "id": 2
            }
        ]);

        let request_data = serde_json::to_vec(&batch_json).unwrap();
        let result = processor.process_raw_data(request_data, None).await;

        assert!(result.is_ok());
        let response_data = result.unwrap();
        let responses: serde_json::Value = serde_json::from_slice(&response_data).unwrap();

        assert!(responses.is_array());
        let response_array = responses.as_array().unwrap();
        assert_eq!(response_array.len(), 2);
    }

    #[tokio::test]
    async fn test_notification_processing() {
        let processor = create_test_processor();

        let notification_json = json!({
            "jsonrpc": "2.0",
            "method": "test_method",
            "params": {"test": "notification"}
        });

        let request_data = serde_json::to_vec(&notification_json).unwrap();
        let result = processor.process_raw_data(request_data, None).await;

        // Notifications should not return responses
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_invalid_json() {
        let processor = create_test_processor();

        let invalid_data = b"invalid json".to_vec();
        let result = processor.process_raw_data(invalid_data, None).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_method_not_found() {
        let processor = create_test_processor();

        let request_json = json!({
            "jsonrpc": "2.0",
            "method": "nonexistent_method",
            "id": 1
        });

        let request_data = serde_json::to_vec(&request_json).unwrap();
        let result = processor.process_raw_data(request_data, None).await;

        assert!(result.is_ok());
        let response_data = result.unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response_data).unwrap();

        assert!(response["error"].is_object());
        assert_eq!(response["error"]["code"], -32601); // Method not found
    }

    #[tokio::test]
    async fn test_batch_size_limit() {
        let config = ProcessorConfig {
            max_batch_size: 2,
            ..Default::default()
        };

        let registry = Arc::new(RpcMethodRegistry::new());
        let buffer_pool = Arc::new(BufferPool::default());
        let processor = RequestProcessor::new(registry, buffer_pool, config);

        let large_batch = json!([
            {"jsonrpc": "2.0", "method": "test", "id": 1},
            {"jsonrpc": "2.0", "method": "test", "id": 2},
            {"jsonrpc": "2.0", "method": "test", "id": 3}
        ]);

        let request_data = serde_json::to_vec(&large_batch).unwrap();
        let result = processor.process_raw_data(request_data, None).await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_statistics_tracking() {
        let processor = create_test_processor();

        let request_json = json!({
            "jsonrpc": "2.0",
            "method": "test_method",
            "id": 1
        });

        let request_data = serde_json::to_vec(&request_json).unwrap();
        let _ = processor.process_raw_data(request_data, None).await;

        let stats = processor.get_stats().await;
        assert_eq!(stats.total_requests, 1);
        assert!(stats.avg_processing_time_us > 0.0);
    }
}
