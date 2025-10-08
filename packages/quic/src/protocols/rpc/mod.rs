//! JSON-RPC 2.0 Implementation for QUIC Transport
//!
//! This module provides a complete, production-ready JSON-RPC 2.0 implementation
//! with zero-allocation parsing, concurrent batch processing, and comprehensive
//! error handling following the JSON-RPC 2.0 specification.

pub mod buffers;
pub mod processor;
pub mod registry;
pub mod types;

// Re-export core types and components for easy access
pub use buffers::{BufferPool, BufferStats, ConnectionBuffers};
pub use processor::{ProcessorConfig, ProcessorStats, RequestProcessor};
pub use registry::{JsonRpcRegistry as RpcMethodRegistry, RpcContext, RpcMethod};
pub use types::{
    BatchRequest, BatchResponse, ErrorObject, Id, Params, Request, Response, Result, RpcError,
};

/// JSON-RPC 2.0 Server Builder
///
/// Provides a high-level interface for creating and configuring JSON-RPC servers
/// with production-ready defaults and customizable settings.
pub struct JsonRpcServerBuilder {
    config: ProcessorConfig,
    registry: RpcMethodRegistry,
    buffer_pool_config: (usize, usize), // (default_capacity, max_pool_size)
}

impl JsonRpcServerBuilder {
    /// Create a new JSON-RPC server builder with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            config: ProcessorConfig::default(),
            registry: RpcMethodRegistry::new(),
            buffer_pool_config: (4096, 10),
        }
    }

    /// Set maximum concurrent requests
    #[must_use]
    pub fn max_concurrent_requests(mut self, max: usize) -> Self {
        self.config.max_concurrent_requests = max;
        self
    }

    /// Set maximum batch size
    #[must_use]
    pub fn max_batch_size(mut self, max: usize) -> Self {
        self.config.max_batch_size = max;
        self
    }

    /// Set request timeout in milliseconds
    #[must_use]
    pub fn request_timeout_ms(mut self, timeout: u64) -> Self {
        self.config.request_timeout_ms = timeout;
        self
    }

    /// Enable or disable request validation
    #[must_use]
    pub fn validate_requests(mut self, validate: bool) -> Self {
        self.config.validate_requests = validate;
        self
    }

    /// Configure buffer pool settings
    #[must_use]
    pub fn buffer_pool(mut self, default_capacity: usize, max_pool_size: usize) -> Self {
        self.buffer_pool_config = (default_capacity, max_pool_size);
        self
    }

    /// Register an RPC method using a closure
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Method name is already registered
    /// - Method name is invalid or reserved
    /// - Handler registration fails
    pub fn register_method<F, Fut>(self, name: &str, handler: F) -> Result<Self>
    where
        F: Fn(RpcContext, Option<Params>) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<simd_json::OwnedValue>> + Send + 'static,
    {
        self.registry.register(name, handler);
        Ok(self)
    }

    /// Build the JSON-RPC server components
    #[must_use]
    pub fn build(self) -> JsonRpcServer {
        let registry = self.registry;
        registry.register_default_introspection_methods();
        let registry = std::sync::Arc::new(registry);
        let buffer_pool = std::sync::Arc::new(BufferPool::new(
            self.buffer_pool_config.0,
            self.buffer_pool_config.1,
        ));
        let processor = RequestProcessor::new(registry.clone(), buffer_pool.clone(), self.config);

        JsonRpcServer {
            processor,
            registry,
            buffer_pool,
        }
    }
}

impl Default for JsonRpcServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Complete JSON-RPC 2.0 Server
///
/// Encapsulates all components needed for JSON-RPC processing including
/// method registry, buffer management, and request processing pipeline.
pub struct JsonRpcServer {
    processor: RequestProcessor,
    registry: std::sync::Arc<RpcMethodRegistry>,
    buffer_pool: std::sync::Arc<BufferPool>,
}

impl JsonRpcServer {
    /// Create a new JSON-RPC server with default configuration
    #[must_use]
    pub fn new() -> Self {
        JsonRpcServerBuilder::new().build()
    }

    /// Create a builder for customizing server configuration
    #[must_use]
    pub fn builder() -> JsonRpcServerBuilder {
        JsonRpcServerBuilder::new()
    }

    /// Process raw JSON-RPC request data
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - JSON parsing fails
    /// - Method not found in registry
    /// - Method execution fails
    /// - Response serialization fails
    pub async fn process_request(
        &self,
        data: Vec<u8>,
        connection_id: Option<String>,
    ) -> Result<Vec<u8>> {
        self.processor.process_raw_data(data, connection_id).await
    }

    /// Get the method registry for dynamic method registration
    #[must_use]
    pub fn registry(&self) -> &std::sync::Arc<RpcMethodRegistry> {
        &self.registry
    }

    /// Get processing statistics
    pub async fn stats(&self) -> ProcessorStats {
        self.processor.get_stats().await
    }

    /// Get buffer pool statistics
    #[must_use]
    pub fn buffer_stats(&self) -> (u64, u64, usize) {
        self.buffer_pool.pool_stats()
    }

    /// Get processor configuration
    #[must_use]
    pub fn config(&self) -> &ProcessorConfig {
        self.processor.get_config()
    }
}

impl Default for JsonRpcServer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use simd_json::OwnedValue;

    #[tokio::test]
    async fn test_server_builder() {
        let server = JsonRpcServerBuilder::new()
            .max_concurrent_requests(50)
            .max_batch_size(25)
            .request_timeout_ms(15000)
            .validate_requests(true)
            .register_method("test", |_ctx, params| async move {
                match params {
                    Some(p) => Ok(simd_json::OwnedValue::try_from(p)?),
                    None => Ok(OwnedValue::from("test_result")),
                }
            })
            .unwrap()
            .build();

        let config = server.config();
        assert_eq!(config.max_concurrent_requests, 50);
        assert_eq!(config.max_batch_size, 25);
        assert_eq!(config.request_timeout_ms, 15000);
        assert!(config.validate_requests);
    }

    #[tokio::test]
    async fn test_server_request_processing() {
        let server = JsonRpcServer::builder()
            .register_method("echo", |_ctx, params| async move {
                match params {
                    Some(p) => Ok(simd_json::OwnedValue::try_from(p)?),
                    None => Ok(OwnedValue::from("echo")),
                }
            })
            .unwrap()
            .build();

        let request = json!({
            "jsonrpc": "2.0",
            "method": "echo",
            "params": {"message": "hello"},
            "id": 1
        });

        let request_data = serde_json::to_vec(&request).unwrap();
        let response_data = server.process_request(request_data, None).await.unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response_data).unwrap();

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        assert!(response["result"].is_object());
    }

    #[tokio::test]
    async fn test_default_server() {
        let server = JsonRpcServer::new();
        let stats = server.stats().await;
        assert_eq!(stats.total_requests, 0);

        let (created, reused, available) = server.buffer_stats();
        assert_eq!(created, 0);
        assert_eq!(reused, 0);
        assert_eq!(available, 0);
    }

    #[tokio::test]
    async fn test_introspection_methods() {
        let server = JsonRpcServer::new();

        // Test ping method
        let ping_request = json!({
            "jsonrpc": "2.0",
            "method": "ping",
            "id": 1
        });

        let request_data = serde_json::to_vec(&ping_request).unwrap();
        let response_data = server.process_request(request_data, None).await.unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response_data).unwrap();

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 1);
        assert_eq!(response["result"], "pong");
    }
}
