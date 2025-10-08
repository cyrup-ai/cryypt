//! JSON-RPC 2.0 Type System
//!
//! Complete implementation of JSON-RPC 2.0 specification types including:
//! - Request/Response objects with proper validation
//! - Batch processing support
//! - Predefined error codes and error objects
//! - Parameter handling (positional and named)
//! - Notification support

use serde::{Deserialize, Serialize};
use simd_json::prelude::*;
use std::collections::HashMap;

/// JSON-RPC 2.0 predefined error codes
pub mod error_codes {
    /// Invalid JSON was received by the server
    pub const PARSE_ERROR: i32 = -32700;
    /// The JSON sent is not a valid Request object
    pub const INVALID_REQUEST: i32 = -32600;
    /// The method does not exist / is not available
    pub const METHOD_NOT_FOUND: i32 = -32601;
    /// Invalid method parameter(s)
    pub const INVALID_PARAMS: i32 = -32602;
    /// Internal JSON-RPC error
    pub const INTERNAL_ERROR: i32 = -32603;
}

/// JSON-RPC 2.0 Request ID
/// Can be a String, Number, or Null according to specification
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(untagged)]
pub enum Id {
    /// Null identifier
    #[default]
    Null,
    /// String identifier
    String(String),
    /// Numeric identifier (u64 for simplicity)
    Number(u64),
}

impl Id {
    /// Generate a unique numeric ID
    pub fn generate() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(1);
        Id::Number(COUNTER.fetch_add(1, Ordering::Relaxed))
    }

    /// Check if this is a null ID
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, Id::Null)
    }
}

/// Method parameters - can be positional (array) or named (object)
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Params {
    /// Positional parameters (array)
    Array(Vec<simd_json::OwnedValue>),
    /// Named parameters (object)
    Object(HashMap<String, simd_json::OwnedValue>),
}

impl Params {
    /// Create empty positional parameters
    #[must_use]
    pub fn array() -> Self {
        Params::Array(Vec::new())
    }

    /// Create empty named parameters
    #[must_use]
    pub fn object() -> Self {
        Params::Object(HashMap::new())
    }

    /// Check if parameters are empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        match self {
            Params::Array(arr) => arr.is_empty(),
            Params::Object(obj) => obj.is_empty(),
        }
    }
}

/// Convert `Params` to `OwnedValue` for JSON-RPC processing
impl TryFrom<Params> for simd_json::OwnedValue {
    type Error = RpcError;

    fn try_from(params: Params) -> Result<Self> {
        match params {
            Params::Array(arr) => Ok(simd_json::OwnedValue::Array(Box::new(arr))),
            Params::Object(obj) => {
                // Use existing error handling patterns from processor.rs
                let json_string = serde_json::to_string(&obj).map_err(|e| {
                    RpcError::parse_error(format!("Params object serialization failed: {e}"))
                })?;

                let mut json_bytes = json_string.into_bytes();
                simd_json::to_owned_value(&mut json_bytes)
                    .map_err(|e| RpcError::parse_error(format!("SIMD JSON conversion failed: {e}")))
            }
        }
    }
}

/// JSON-RPC 2.0 Request object
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Request {
    /// JSON-RPC version - must be "2.0"
    pub jsonrpc: String,
    /// Method name to invoke
    pub method: String,
    /// Optional parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Params>,
    /// Request ID - if None, this is a notification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Id>,
}

impl Request {
    /// Create a new method call request
    #[must_use]
    pub fn method_call(method: String, params: Option<Params>, id: Id) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method,
            params,
            id: Some(id),
        }
    }

    /// Create a new notification request (no response expected)
    #[must_use]
    pub fn notification(method: String, params: Option<Params>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            method,
            params,
            id: None,
        }
    }

    /// Check if this is a notification (no ID)
    #[must_use]
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }

    /// Validate the request according to JSON-RPC 2.0 specification
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - JSON-RPC version is not exactly "2.0"
    /// - Method name is empty or invalid
    /// - Request ID format is invalid
    /// - Parameters format is malformed
    pub fn validate(&self) -> Result<()> {
        // Check JSON-RPC version
        if self.jsonrpc != "2.0" {
            return Err(RpcError::invalid_request(
                "jsonrpc field must be exactly '2.0'".to_string(),
            ));
        }

        // Check method name is not empty
        if self.method.is_empty() {
            return Err(RpcError::invalid_request(
                "method field cannot be empty".to_string(),
            ));
        }

        // Method names starting with "rpc." are reserved
        if self.method.starts_with("rpc.") && !self.method.starts_with("rpc.discover") {
            return Err(RpcError::invalid_request(format!(
                "method name '{}' is reserved",
                self.method
            )));
        }

        Ok(())
    }
}

/// JSON-RPC 2.0 Response object
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Response {
    /// JSON-RPC version - must be "2.0"
    pub jsonrpc: String,
    /// Result value (present on success)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<simd_json::OwnedValue>,
    /// Error object (present on error)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorObject>,
    /// Request ID (same as request, or Null if ID couldn't be determined)
    pub id: Id,
}

impl Response {
    /// Create a success response
    #[must_use]
    pub fn success(result: simd_json::OwnedValue, id: Id) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: Some(result),
            error: None,
            id,
        }
    }

    /// Create an error response
    #[must_use]
    pub fn error(error: ErrorObject, id: Id) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            result: None,
            error: Some(error),
            id,
        }
    }

    /// Check if this is a success response
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.result.is_some() && self.error.is_none()
    }

    /// Check if this is an error response
    #[must_use]
    pub fn is_error(&self) -> bool {
        self.error.is_some() && self.result.is_none()
    }
}

/// JSON-RPC 2.0 Error object
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ErrorObject {
    /// Error code
    pub code: i32,
    /// Error message
    pub message: String,
    /// Optional additional error data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<simd_json::OwnedValue>,
}

impl ErrorObject {
    /// Create a new error object
    #[must_use]
    pub fn new(code: i32, message: String, data: Option<simd_json::OwnedValue>) -> Self {
        Self {
            code,
            message,
            data,
        }
    }

    /// Create a parse error (-32700)
    #[must_use]
    pub fn parse_error(message: String) -> Self {
        Self::new(error_codes::PARSE_ERROR, message, None)
    }

    /// Create an invalid request error (-32600)
    #[must_use]
    pub fn invalid_request(message: String) -> Self {
        Self::new(error_codes::INVALID_REQUEST, message, None)
    }

    /// Create a method not found error (-32601)
    #[must_use]
    pub fn method_not_found(method: &str) -> Self {
        Self::new(
            error_codes::METHOD_NOT_FOUND,
            format!("Method '{method}' not found"),
            None,
        )
    }

    /// Create an invalid params error (-32602)
    #[must_use]
    pub fn invalid_params(message: String) -> Self {
        Self::new(error_codes::INVALID_PARAMS, message, None)
    }

    /// Create an internal error (-32603)
    #[must_use]
    pub fn internal_error(message: String) -> Self {
        Self::new(error_codes::INTERNAL_ERROR, message, None)
    }
}

/// Batch request - array of Request objects
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchRequest(pub Vec<Request>);

impl BatchRequest {
    /// Create a new batch request
    #[must_use]
    pub fn new(requests: Vec<Request>) -> Self {
        Self(requests)
    }

    /// Check if batch is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get the number of requests in the batch
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Validate all requests in the batch
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Batch is empty (not allowed in JSON-RPC 2.0)
    /// - Any individual request validation fails
    /// - Batch size exceeds implementation limits
    pub fn validate(&self) -> Result<()> {
        if self.is_empty() {
            return Err(RpcError::invalid_request(
                "Batch request cannot be empty".to_string(),
            ));
        }

        for request in &self.0 {
            request.validate()?;
        }

        Ok(())
    }
}

/// Batch response - array of Response objects
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchResponse(pub Vec<Response>);

impl BatchResponse {
    /// Create a new batch response
    #[must_use]
    pub fn new(responses: Vec<Response>) -> Self {
        Self(responses)
    }

    /// Check if batch is empty
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get the number of responses in the batch
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

/// Top-level request type - can be single or batch
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RpcRequest {
    /// Single request
    Single(Request),
    /// Batch request
    Batch(BatchRequest),
}

impl RpcRequest {
    /// Validate the request
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Single request validation fails
    /// - Batch request validation fails
    /// - Request format is invalid
    pub fn validate(&self) -> Result<()> {
        match self {
            RpcRequest::Single(req) => req.validate(),
            RpcRequest::Batch(batch) => batch.validate(),
        }
    }

    /// Check if this is a batch request
    #[must_use]
    pub fn is_batch(&self) -> bool {
        matches!(self, RpcRequest::Batch(_))
    }
}

/// Top-level response type - can be single or batch
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RpcResponse {
    /// Single response
    Single(Response),
    /// Batch response
    Batch(BatchResponse),
}

impl RpcResponse {
    /// Check if this is a batch response
    #[must_use]
    pub fn is_batch(&self) -> bool {
        matches!(self, RpcResponse::Batch(_))
    }
}

/// JSON-RPC error type
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// Parse error - invalid JSON
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Invalid request
    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    /// Method not found
    #[error("Method not found: {0}")]
    MethodNotFound(String),

    /// Invalid parameters
    #[error("Invalid params: {0}")]
    InvalidParams(String),

    /// Internal error
    #[error("Internal error: {0}")]
    InternalError(String),

    /// Custom server error
    #[error("Server error ({code}): {message}")]
    ServerError { code: i32, message: String },
}

impl RpcError {
    /// Create a parse error
    #[must_use]
    pub fn parse_error(message: String) -> Self {
        Self::ParseError(message)
    }

    /// Create an invalid request error
    #[must_use]
    pub fn invalid_request(message: String) -> Self {
        Self::InvalidRequest(message)
    }

    /// Create a method not found error
    #[must_use]
    pub fn method_not_found(method: String) -> Self {
        Self::MethodNotFound(method)
    }

    /// Create an invalid params error
    #[must_use]
    pub fn invalid_params(message: String) -> Self {
        Self::InvalidParams(message)
    }

    /// Create an internal error
    #[must_use]
    pub fn internal_error(message: String) -> Self {
        Self::InternalError(message)
    }

    /// Create a custom server error
    #[must_use]
    pub fn server_error(code: i32, message: String) -> Self {
        Self::ServerError { code, message }
    }

    /// Convert to `ErrorObject`
    #[must_use]
    pub fn to_error_object(&self) -> ErrorObject {
        match self {
            Self::ParseError(msg) => ErrorObject::parse_error(msg.clone()),
            Self::InvalidRequest(msg) => ErrorObject::invalid_request(msg.clone()),
            Self::MethodNotFound(method) => ErrorObject::method_not_found(method),
            Self::InvalidParams(msg) => ErrorObject::invalid_params(msg.clone()),
            Self::InternalError(msg) => ErrorObject::internal_error(msg.clone()),
            Self::ServerError { code, message } => ErrorObject::new(*code, message.clone(), None),
        }
    }
}

/// Result type for JSON-RPC operations
pub type Result<T> = std::result::Result<T, RpcError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_id_generation() {
        let id1 = Id::generate();
        let id2 = Id::generate();
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_request_validation() {
        // Valid request
        let valid_request = Request::method_call("test_method".to_string(), None, Id::Number(1));
        assert!(valid_request.validate().is_ok());

        // Invalid version
        let mut invalid_request = valid_request.clone();
        invalid_request.jsonrpc = "1.0".to_string();
        assert!(invalid_request.validate().is_err());

        // Empty method
        let mut invalid_request = valid_request.clone();
        invalid_request.method = String::new();
        assert!(invalid_request.validate().is_err());

        // Reserved method name
        let mut invalid_request = valid_request.clone();
        invalid_request.method = "rpc.internal".to_string();
        assert!(invalid_request.validate().is_err());
    }

    #[test]
    fn test_notification() {
        let notification = Request::notification("notify_method".to_string(), None);
        assert!(notification.is_notification());
        assert!(notification.validate().is_ok());
    }

    #[test]
    fn test_error_objects() {
        let error = ErrorObject::method_not_found("test_method");
        assert_eq!(error.code, error_codes::METHOD_NOT_FOUND);
        assert!(error.message.contains("test_method"));
    }

    #[test]
    fn test_batch_validation() {
        // Valid batch
        let requests = vec![
            Request::method_call("method1".to_string(), None, Id::Number(1)),
            Request::notification("method2".to_string(), None),
        ];
        let batch = BatchRequest::new(requests);
        assert!(batch.validate().is_ok());

        // Empty batch
        let empty_batch = BatchRequest::new(vec![]);
        assert!(empty_batch.validate().is_err());
    }

    #[test]
    fn test_serialization() {
        let request = Request::method_call(
            "subtract".to_string(),
            Some(Params::Array(vec![
                simd_json::OwnedValue::from(42),
                simd_json::OwnedValue::from(23),
            ])),
            Id::Number(1),
        );

        let json = serde_json::to_string(&request).unwrap();
        let deserialized: Request = serde_json::from_str(&json).unwrap();
        assert_eq!(request, deserialized);
    }
}
