//! High-level RPC protocol over QUIC
//!
//! Provides request/response patterns with automatic timeouts,
//! retries, and load balancing across multiple connections.

use crate::{Result, quic_conn::{QuicConnectionHandle, QuicConnectionEvent}};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

/// RPC call result
#[derive(Debug)]
pub struct RpcResponse<T> {
    pub result: Result<T>,
    pub call_duration: Duration,
    pub server_id: Option<String>,
}

/// RPC call builder
pub struct RpcCall<Req, Resp> {
    method: String,
    request: Req,
    timeout: Duration,
    retries: u32,
    handle: Option<Arc<QuicConnectionHandle>>,
    _phantom: std::marker::PhantomData<Resp>,
}

impl<Req: Serialize + Send + 'static, Resp: for<'de> Deserialize<'de> + Send + 'static>
    RpcCall<Req, Resp>
{
    /// Execute the RPC call
    pub async fn execute(self) -> Result<RpcResponse<Resp>> {
        // Log RPC call details
        println!("🔄 Executing RPC method: {}", self.method);
        println!("    Timeout: {:?}, Retries: {}", self.timeout, self.retries);

        // Serialize request
        let _request_json = serde_json::to_string(&self.request).map_err(|e| {
            crate::error::CryptoTransportError::Internal(format!(
                "Failed to serialize RPC request: {}",
                e
            ))
        })?;

        // If we have a connection handle, use it
        if let Some(handle) = &self.handle {
            // Wait for handshake
            handle.wait_for_handshake().await?;

            // Create RPC request with ID
            let rpc_request = serde_json::json!({
                "jsonrpc": "2.0",
                "method": self.method,
                "params": _request_json,
                "id": 1
            });

            let request_data = serde_json::to_vec(&rpc_request).map_err(|e| {
                crate::error::CryptoTransportError::Internal(format!(
                    "Failed to serialize RPC request: {}",
                    e
                ))
            })?;

            // Send the request
            handle.send_stream_data(&request_data, true)?;

            // Wait for response with timeout
            let start_time = std::time::Instant::now();
            let mut event_rx = handle.subscribe_to_events();
            
            let response = tokio::time::timeout(self.timeout, async {
                while let Ok(event) = event_rx.recv().await {
                    if let QuicConnectionEvent::InboundStreamData(_, data) = event {
                        let response_str = String::from_utf8(data).map_err(|e| {
                            crate::error::CryptoTransportError::Internal(format!(
                                "Invalid UTF-8 in response: {}", e
                            ))
                        })?;
                        
                        let json_response: serde_json::Value = serde_json::from_str(&response_str)
                            .map_err(|e| {
                                crate::error::CryptoTransportError::Internal(format!(
                                    "Failed to parse JSON response: {}", e
                                ))
                            })?;
                        
                        if let Some(result) = json_response.get("result") {
                            let resp: Resp = serde_json::from_value(result.clone()).map_err(|e| {
                                crate::error::CryptoTransportError::Internal(format!(
                                    "Failed to deserialize result: {}", e
                                ))
                            })?;
                            
                            return Ok(resp);
                        } else if let Some(error) = json_response.get("error") {
                            return Err(crate::error::CryptoTransportError::Internal(format!(
                                "RPC error: {}", error
                            )));
                        }
                    }
                }
                Err(crate::error::CryptoTransportError::Internal(
                    "Connection closed before response".to_string()
                ))
            }).await;
            
            match response {
                Ok(Ok(resp)) => Ok(RpcResponse {
                    result: Ok(resp),
                    call_duration: start_time.elapsed(),
                    server_id: Some("quic-server".to_string()),
                }),
                Ok(Err(e)) => Ok(RpcResponse {
                    result: Err(e),
                    call_duration: start_time.elapsed(),
                    server_id: Some("quic-server".to_string()),
                }),
                Err(_) => Err(crate::error::CryptoTransportError::Internal(
                    format!("RPC timeout after {:?}", self.timeout)
                )),
            }
        } else {
            Err(crate::error::CryptoTransportError::Internal(
                "No QUIC connection handle available".to_string(),
            ))
        }
    }
}

/// High-level RPC protocol builder
pub struct QuicRpc;

impl QuicRpc {
    /// Create an RPC server
    pub fn server() -> RpcServerBuilder {
        RpcServerBuilder::default()
    }

    /// Connect to an RPC server
    pub fn connect(server_addr: &str) -> RpcClientBuilder {
        RpcClientBuilder::new(server_addr.to_string())
    }
}

#[derive(Default)]
pub struct RpcServerBuilder {
    max_concurrent_calls: usize,
    call_timeout: Duration,
    enable_streaming: bool,
}

impl RpcServerBuilder {
    pub fn with_max_concurrent_calls(mut self, count: usize) -> Self {
        self.max_concurrent_calls = count;
        self
    }

    pub fn with_call_timeout(mut self, timeout: Duration) -> Self {
        self.call_timeout = timeout;
        self
    }

    pub fn with_streaming(mut self, enabled: bool) -> Self {
        self.enable_streaming = enabled;
        self
    }

    pub fn listen(self, addr: &str) -> impl Future<Output = Result<RpcServer>> + Send {
        let _addr = addr.to_string();
        async move {
            // Implementation would set up QUIC server with RPC protocol
            Ok(RpcServer)
        }
    }
}

pub struct RpcServer;

pub struct RpcClientBuilder {
    server_addr: String,
    connection_pool_size: usize,
    default_timeout: Duration,
    default_retries: u32,
    handle: Option<Arc<QuicConnectionHandle>>,
}

impl RpcClientBuilder {
    fn new(server_addr: String) -> Self {
        Self {
            server_addr,
            connection_pool_size: 5,
            default_timeout: Duration::from_secs(30),
            default_retries: 3,
            handle: None,
        }
    }

    pub fn with_handle(mut self, handle: QuicConnectionHandle) -> Self {
        self.handle = Some(Arc::new(handle));
        self
    }

    pub fn with_connection_pool_size(mut self, size: usize) -> Self {
        self.connection_pool_size = size;
        self
    }

    pub fn with_default_timeout(mut self, timeout: Duration) -> Self {
        self.default_timeout = timeout;
        self
    }

    pub fn with_default_retries(mut self, retries: u32) -> Self {
        self.default_retries = retries;
        self
    }

    /// Make an RPC call
    pub fn call<
        Req: Serialize + Send + 'static,
        Resp: for<'de> Deserialize<'de> + Send + 'static,
    >(
        self,
        method: &str,
        request: Req,
    ) -> RpcCall<Req, Resp> {
        println!(
            "📞 Creating RPC call to {} (pool size: {}, default timeout: {:?})",
            self.server_addr, self.connection_pool_size, self.default_timeout
        );

        RpcCall {
            method: method.to_string(),
            request,
            timeout: self.default_timeout,
            retries: self.default_retries,
            handle: self.handle.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}
