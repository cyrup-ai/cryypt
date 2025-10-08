//! Enhanced Method Registry with Async Support and Request Tracking
//!
//! Production-quality method registry based on tarpc patterns with:
//! - Async trait support for method handlers
//! - Request tracking and timeout management
//! - Thread-safe concurrent access
//! - Proper error handling and context passing

use super::types::{Id, Params, Result, RpcError};
use async_trait::async_trait;
use dashmap::DashMap;
use fnv::FnvHashMap;
use simd_json::OwnedValue;
use simd_json::prelude::ValueAsScalar;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;
use tokio_util::time::DelayQueue;
use tracing::{debug, error, info, warn};

/// Context passed to RPC method handlers
#[derive(Debug, Clone)]
pub struct RpcContext {
    /// Request ID for correlation
    pub request_id: Id,
    /// Method name being called
    pub method: String,
    /// Request start time for metrics
    pub start_time: Instant,
    /// Optional connection identifier
    pub connection_id: Option<String>,
    /// Request timeout deadline
    pub deadline: Instant,
}

impl RpcContext {
    /// Create a new RPC context
    #[must_use]
    pub fn new(request_id: Id, method: String, timeout: Duration) -> Self {
        let start_time = Instant::now();
        Self {
            request_id,
            method,
            start_time,
            connection_id: None,
            deadline: start_time + timeout,
        }
    }

    /// Set the connection ID
    #[must_use]
    pub fn with_connection_id(mut self, connection_id: String) -> Self {
        self.connection_id = Some(connection_id);
        self
    }

    /// Get elapsed time since request start
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Check if the request has timed out
    #[must_use]
    pub fn is_timed_out(&self) -> bool {
        Instant::now() > self.deadline
    }

    /// Get remaining time until deadline
    #[must_use]
    pub fn time_remaining(&self) -> Duration {
        self.deadline.saturating_duration_since(Instant::now())
    }
}

/// Async RPC method handler trait
#[async_trait]
pub trait RpcMethod: Send + Sync {
    /// Execute the RPC method
    async fn call(&self, ctx: RpcContext, params: Option<Params>) -> Result<OwnedValue>;
}

/// Closure-based method handler
pub struct ClosureMethod<F, Fut>
where
    F: Fn(RpcContext, Option<Params>) -> Fut + Send + Sync,
    Fut: Future<Output = Result<OwnedValue>> + Send,
{
    handler: F,
}

impl<F, Fut> ClosureMethod<F, Fut>
where
    F: Fn(RpcContext, Option<Params>) -> Fut + Send + Sync,
    Fut: Future<Output = Result<OwnedValue>> + Send,
{
    pub fn new(handler: F) -> Self {
        Self { handler }
    }
}

#[async_trait]
impl<F, Fut> RpcMethod for ClosureMethod<F, Fut>
where
    F: Fn(RpcContext, Option<Params>) -> Fut + Send + Sync,
    Fut: Future<Output = Result<OwnedValue>> + Send,
{
    async fn call(&self, ctx: RpcContext, params: Option<Params>) -> Result<OwnedValue> {
        (self.handler)(ctx, params).await
    }
}

/// Request handle for tracking in-flight requests
#[derive(Debug)]
struct RequestHandle {
    /// Request context
    ctx: RpcContext,
    /// Abort handle for cancellation
    abort_handle: tokio_util::sync::CancellationToken,
    /// Deadline key for timeout tracking
    deadline_key: tokio_util::time::delay_queue::Key,
}

/// In-flight request tracking (based on tarpc's `InFlightRequests`)
#[derive(Debug)]
pub struct InFlightRequests {
    /// Map of request ID to request data
    requests: FnvHashMap<Id, RequestHandle>,
    /// Deadline queue for timeout management
    deadlines: DelayQueue<Id>,
}

impl InFlightRequests {
    /// Create a new in-flight requests tracker
    #[must_use]
    pub fn new() -> Self {
        Self {
            requests: FnvHashMap::default(),
            deadlines: DelayQueue::new(),
        }
    }

    /// Start tracking a request
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Request ID already exists and is in flight
    /// - Maximum concurrent requests limit reached
    /// - Request context validation fails
    pub fn start_request(
        &mut self,
        ctx: RpcContext,
    ) -> Result<tokio_util::sync::CancellationToken> {
        let request_id = ctx.request_id.clone();

        // Check if request ID already exists
        if self.requests.contains_key(&request_id) {
            return Err(RpcError::invalid_request(format!(
                "Request ID {request_id:?} already in flight"
            )));
        }

        let timeout = ctx.time_remaining();
        let abort_handle = tokio_util::sync::CancellationToken::new();
        let deadline_key = self.deadlines.insert(request_id.clone(), timeout);

        let handle = RequestHandle {
            ctx,
            abort_handle: abort_handle.clone(),
            deadline_key,
        };

        self.requests.insert(request_id, handle);
        Ok(abort_handle)
    }

    /// Complete a request (remove from tracking)
    pub fn complete_request(&mut self, request_id: &Id) -> Option<RpcContext> {
        if let Some(handle) = self.requests.remove(request_id) {
            self.deadlines.remove(&handle.deadline_key);
            Some(handle.ctx)
        } else {
            None
        }
    }

    /// Cancel a request
    pub fn cancel_request(&mut self, request_id: &Id) -> bool {
        if let Some(handle) = self.requests.remove(request_id) {
            handle.abort_handle.cancel();
            self.deadlines.remove(&handle.deadline_key);
            true
        } else {
            false
        }
    }

    /// Get the number of in-flight requests
    #[must_use]
    pub fn len(&self) -> usize {
        self.requests.len()
    }

    /// Check if there are any in-flight requests
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.requests.is_empty()
    }

    /// Poll for expired requests
    pub fn poll_expired(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Id>> {
        use std::task::Poll;

        match self.deadlines.poll_expired(cx) {
            Poll::Ready(Some(expired)) => {
                let request_id = expired.into_inner();
                if let Some(handle) = self.requests.remove(&request_id) {
                    handle.abort_handle.cancel();
                    warn!("Request {:?} timed out", request_id);
                    return Poll::Ready(Some(request_id));
                }
                Poll::Ready(None)
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Default for InFlightRequests {
    fn default() -> Self {
        Self::new()
    }
}

/// Enhanced JSON-RPC method registry
#[derive(Clone)]
pub struct JsonRpcRegistry {
    /// Registered methods
    methods: DashMap<String, Arc<dyn RpcMethod>>,
    /// In-flight request tracking
    in_flight: Arc<Mutex<InFlightRequests>>,
    /// Default request timeout
    default_timeout: Duration,
    /// Maximum concurrent requests
    max_concurrent: usize,
}

impl JsonRpcRegistry {
    /// Create a new registry
    #[must_use]
    pub fn new() -> Self {
        Self {
            methods: DashMap::new(),
            in_flight: Arc::new(Mutex::new(InFlightRequests::new())),
            default_timeout: Duration::from_secs(30),
            max_concurrent: 100,
        }
    }

    /// Create a registry with custom configuration
    #[must_use]
    pub fn with_config(default_timeout: Duration, max_concurrent: usize) -> Self {
        Self {
            methods: DashMap::new(),
            in_flight: Arc::new(Mutex::new(InFlightRequests::new())),
            default_timeout,
            max_concurrent,
        }
    }

    /// Register a method with a closure handler
    pub fn register<F, Fut>(&self, name: &str, handler: F)
    where
        F: Fn(RpcContext, Option<Params>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<OwnedValue>> + Send + 'static,
    {
        let method = Arc::new(ClosureMethod::new(handler));
        self.methods.insert(name.to_string(), method);
        debug!("Registered RPC method: {}", name);
    }

    /// Register a method with a trait object
    pub fn register_method(&self, name: &str, method: Arc<dyn RpcMethod>) {
        self.methods.insert(name.to_string(), method);
        debug!("Registered RPC method: {}", name);
    }

    /// Call a method by name
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Method name is not found in the registry
    /// - Method execution fails or panics
    /// - Parameter validation fails
    /// - Method returns an error result
    pub async fn call_method(
        &self,
        method_name: &str,
        params: Option<Params>,
        request_id: Id,
        connection_id: Option<String>,
    ) -> Result<OwnedValue> {
        // Check if method exists
        let method = self
            .methods
            .get(method_name)
            .ok_or_else(|| RpcError::method_not_found(method_name.to_string()))?;

        // Create context
        let mut ctx = RpcContext::new(
            request_id.clone(),
            method_name.to_string(),
            self.default_timeout,
        );
        if let Some(conn_id) = connection_id {
            ctx = ctx.with_connection_id(conn_id);
        }

        // Check concurrent request limit
        {
            let in_flight = self.in_flight.lock().map_err(|_| {
                RpcError::internal_error("Failed to acquire in-flight requests lock".to_string())
            })?;

            if in_flight.len() >= self.max_concurrent {
                return Err(RpcError::server_error(
                    -32000,
                    "Too many concurrent requests".to_string(),
                ));
            }
        }

        // Start request tracking
        let cancellation_token = {
            let mut in_flight = self.in_flight.lock().map_err(|_| {
                RpcError::internal_error("Failed to acquire in-flight requests lock".to_string())
            })?;
            in_flight.start_request(ctx.clone())?
        };

        // Execute method with timeout and cancellation
        let result = tokio::select! {
            result = method.call(ctx.clone(), params) => {
                result
            }
            () = cancellation_token.cancelled() => {
                Err(RpcError::internal_error("Request was cancelled".to_string()))
            }
            () = tokio::time::sleep(ctx.time_remaining()) => {
                Err(RpcError::internal_error("Request timed out".to_string()))
            }
        };

        // Complete request tracking
        {
            let mut in_flight = self.in_flight.lock().map_err(|_| {
                RpcError::internal_error("Failed to acquire in-flight requests lock".to_string())
            })?;
            in_flight.complete_request(&request_id);
        }

        // Log result
        match &result {
            Ok(_) => {
                info!(
                    "RPC method '{}' completed successfully in {:?}",
                    method_name,
                    ctx.elapsed()
                );
            }
            Err(e) => {
                error!(
                    "RPC method '{}' failed after {:?}: {}",
                    method_name,
                    ctx.elapsed(),
                    e
                );
            }
        }

        result
    }

    /// Get list of registered method names
    #[must_use]
    pub fn list_methods(&self) -> Vec<String> {
        self.methods
            .iter()
            .map(|entry| entry.key().clone())
            .collect()
    }

    /// Check if a method is registered
    #[must_use]
    pub fn has_method(&self, name: &str) -> bool {
        self.methods.contains_key(name)
    }

    /// Get the number of registered methods
    #[must_use]
    pub fn method_count(&self) -> usize {
        self.methods.len()
    }

    /// Get the number of in-flight requests
    #[must_use]
    pub fn in_flight_count(&self) -> usize {
        self.in_flight.lock().map(|guard| guard.len()).unwrap_or(0)
    }

    /// Cancel a specific request
    #[must_use]
    pub fn cancel_request(&self, request_id: &Id) -> bool {
        self.in_flight
            .lock()
            .map(|mut guard| guard.cancel_request(request_id))
            .unwrap_or(false)
    }

    /// Register default introspection methods
    pub fn register_introspection_methods(&self) {
        // List available methods
        self.register("rpc.discover", {
            let registry = Arc::downgrade(&Arc::new(self.methods.clone()));
            move |_ctx, _params| {
                let registry = registry.clone();
                async move {
                    if let Some(methods) = registry.upgrade() {
                        let method_names: Vec<String> =
                            methods.iter().map(|entry| entry.key().clone()).collect();
                        Ok(OwnedValue::from(method_names))
                    } else {
                        Err(RpcError::internal_error("Registry unavailable".to_string()))
                    }
                }
            }
        });

        // Ping method for health checks
        self.register("ping", |_ctx, _params| async {
            Ok(OwnedValue::from("pong"))
        });

        // Echo method for testing
        self.register("echo", |_ctx, params| async {
            match params {
                Some(Params::Array(mut arr)) if !arr.is_empty() => Ok(arr.remove(0)),
                Some(Params::Object(mut obj)) if obj.contains_key("message") => Ok(obj
                    .remove("message")
                    .unwrap_or(OwnedValue::from("no message"))),
                _ => Ok(OwnedValue::from("echo")),
            }
        });

        info!("Registered introspection methods: rpc.discover, ping, echo");
    }

    /// Register default introspection methods only if they don't already exist
    pub fn register_default_introspection_methods(&self) {
        let mut registered_methods = Vec::new();

        // List available methods (only register if not already present)
        if !self.has_method("rpc.discover") {
            self.register("rpc.discover", {
                let registry = Arc::downgrade(&Arc::new(self.methods.clone()));
                move |_ctx, _params| {
                    let registry = registry.clone();
                    async move {
                        if let Some(methods) = registry.upgrade() {
                            let method_names: Vec<String> =
                                methods.iter().map(|entry| entry.key().clone()).collect();
                            Ok(OwnedValue::from(method_names))
                        } else {
                            Err(RpcError::internal_error("Registry unavailable".to_string()))
                        }
                    }
                }
            });
            registered_methods.push("rpc.discover");
        }

        // Ping method for health checks (only register if not already present)
        if !self.has_method("ping") {
            self.register("ping", |_ctx, _params| async {
                Ok(OwnedValue::from("pong"))
            });
            registered_methods.push("ping");
        }

        // Echo method for testing (only register if not already present)
        if !self.has_method("echo") {
            self.register("echo", |_ctx, params| async {
                match params {
                    Some(Params::Array(mut arr)) if !arr.is_empty() => Ok(arr.remove(0)),
                    Some(Params::Object(mut obj)) if obj.contains_key("message") => Ok(obj
                        .remove("message")
                        .unwrap_or(OwnedValue::from("no message"))),
                    _ => Ok(OwnedValue::from("echo")),
                }
            });
            registered_methods.push("echo");
        }

        if !registered_methods.is_empty() {
            info!(
                "Registered default introspection methods: {}",
                registered_methods.join(", ")
            );
        }
    }
}

impl Default for JsonRpcRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{Duration, sleep};

    #[tokio::test]
    async fn test_method_registration_and_call() {
        let registry = JsonRpcRegistry::new();

        // Register a simple method
        registry.register("add", |_ctx, params| async move {
            match params {
                Some(Params::Array(arr)) if arr.len() == 2 => {
                    if let (Some(a), Some(b)) = (arr[0].as_i64(), arr[1].as_i64()) {
                        Ok(OwnedValue::from(a + b))
                    } else {
                        Err(RpcError::invalid_params("Expected two numbers".to_string()))
                    }
                }
                _ => Err(RpcError::invalid_params(
                    "Expected array of two numbers".to_string(),
                )),
            }
        });

        // Test successful call
        let params = Some(Params::Array(vec![
            OwnedValue::from(5),
            OwnedValue::from(3),
        ]));
        let result = registry
            .call_method("add", params, Id::Number(1), None)
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_i64(), Some(8));

        // Test method not found
        let result = registry
            .call_method("subtract", None, Id::Number(2), None)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_introspection_methods() {
        let registry = JsonRpcRegistry::new();
        registry.register_introspection_methods();

        // Test ping
        let result = registry
            .call_method("ping", None, Id::Number(1), None)
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), Some("pong"));

        // Test echo
        let params = Some(Params::Array(vec![OwnedValue::from("hello")]));
        let result = registry
            .call_method("echo", params, Id::Number(2), None)
            .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), Some("hello"));
    }

    #[tokio::test]
    async fn test_request_tracking() {
        let registry = JsonRpcRegistry::new();

        // Register a slow method
        registry.register("slow", |_ctx, _params| async {
            sleep(Duration::from_millis(100)).await;
            Ok(OwnedValue::from("done"))
        });

        // Start multiple requests
        let handle1 = tokio::spawn({
            let registry = registry.clone();
            async move {
                registry
                    .call_method("slow", None, Id::Number(1), None)
                    .await
            }
        });

        let handle2 = tokio::spawn({
            let registry = registry.clone();
            async move {
                registry
                    .call_method("slow", None, Id::Number(2), None)
                    .await
            }
        });

        // Both should complete successfully
        let (result1, result2) = tokio::join!(handle1, handle2);
        assert!(result1.unwrap().is_ok());
        assert!(result2.unwrap().is_ok());

        // In-flight count should be back to 0
        assert_eq!(registry.in_flight_count(), 0);
    }

    #[tokio::test]
    async fn test_concurrent_limit() {
        let registry = JsonRpcRegistry::with_config(Duration::from_secs(1), 1);

        // Register a slow method
        registry.register("slow", |_ctx, _params| async {
            sleep(Duration::from_millis(200)).await;
            Ok(OwnedValue::from("done"))
        });

        // Start first request
        let handle1 = tokio::spawn({
            let registry = registry.clone();
            async move {
                registry
                    .call_method("slow", None, Id::Number(1), None)
                    .await
            }
        });

        // Give it time to start
        sleep(Duration::from_millis(10)).await;

        // Second request should be rejected due to limit
        let result2 = registry
            .call_method("slow", None, Id::Number(2), None)
            .await;
        assert!(result2.is_err());

        // First request should still complete
        let result1 = handle1.await.unwrap();
        assert!(result1.is_ok());
    }
}
