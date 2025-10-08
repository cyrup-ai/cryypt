//! RPC protocol over QUIC stream

use crate::quic_conn::QuicConnectionHandle;
use serde_json::Value;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, info};

/// RPC protocol over QUIC stream
pub struct RpcProtocol {
    addr: SocketAddr,
    handle: Option<QuicConnectionHandle>,
}

impl RpcProtocol {
    pub(super) fn new(addr: SocketAddr, handle: Option<QuicConnectionHandle>) -> Self {
        Self { addr, handle }
    }

    /// Call a remote procedure
    pub fn call(&self, method: impl Into<String>, params: impl Into<String>) -> RpcBuilder {
        RpcBuilder::new(method.into(), params.into(), self.addr, self.handle.clone())
    }
}

/// Builder for RPC operations
pub struct RpcBuilder {
    method: String,
    params: String,
    addr: SocketAddr,
    timeout: Option<Duration>,
    handle: Option<QuicConnectionHandle>,
}

impl RpcBuilder {
    pub(super) fn new(
        method: String,
        params: String,
        addr: SocketAddr,
        handle: Option<QuicConnectionHandle>,
    ) -> Self {
        Self {
            method,
            params,
            addr,
            timeout: None,
            handle,
        }
    }

    /// Set RPC timeout
    #[must_use]
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

impl std::future::Future for RpcBuilder {
    type Output = Result<String, crate::CryptoTransportError>;

    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        if let Some(handle) = &self.handle {
            let handle_clone = handle.clone();
            let method = self.method.clone();
            let params = self.params.clone();
            let timeout_duration = self.timeout.unwrap_or(Duration::from_secs(30));

            let target_addr = self.addr;
            let fut = async move {
                // Log RPC details
                info!(
                    method = %method,
                    target = %target_addr,
                    timeout = ?timeout_duration,
                    "Initiating RPC call"
                );
                debug!(params = %params, "RPC call parameters");

                // Wait for handshake
                handle_clone.wait_for_handshake().await?;

                // Subscribe to events before sending request
                let mut event_rx = handle_clone.subscribe_to_events();

                // Generate unique stream ID for this request
                let stream_id = generate_stream_id();

                // Create RPC request
                let request = serde_json::json!({
                    "jsonrpc": "2.0",
                    "method": method,
                    "params": params,
                    "id": stream_id
                });

                let data = serde_json::to_vec(&request).map_err(|e| {
                    crate::CryptoTransportError::Internal(format!("Failed to serialize RPC: {e}"))
                })?;

                // Send RPC request to specific stream
                handle_clone.send_stream_data_with_id(stream_id, &data, true)?;

                // Wait for response with timeout
                let response_result = timeout(timeout_duration, async {
                    while let Ok(event) = event_rx.recv().await {
                        match event {
                            crate::quic_conn::QuicConnectionEvent::InboundStreamData(sid, data) => {
                                if sid == stream_id {
                                    // Parse JSON-RPC response
                                    let response_str = String::from_utf8(data).map_err(|e| {
                                        crate::CryptoTransportError::Internal(format!(
                                            "Invalid UTF-8 in response: {e}"
                                        ))
                                    })?;

                                    // Validate JSON-RPC response format
                                    let response_json: Value = serde_json::from_str(&response_str)
                                        .map_err(|e| {
                                            crate::CryptoTransportError::Internal(format!(
                                                "Invalid JSON in response: {e}"
                                            ))
                                        })?;

                                    // Check for JSON-RPC 2.0 format
                                    if response_json.get("jsonrpc")
                                        == Some(&Value::String("2.0".to_string()))
                                    {
                                        if let Some(result) = response_json.get("result") {
                                            return Ok(result.to_string());
                                        } else if let Some(error) = response_json.get("error") {
                                            return Err(crate::CryptoTransportError::Internal(
                                                format!("RPC error: {error}"),
                                            ));
                                        }
                                    }

                                    // Fallback to raw response
                                    return Ok(response_str);
                                }
                            }
                            crate::quic_conn::QuicConnectionEvent::StreamFinished(sid) => {
                                if sid == stream_id {
                                    return Err(crate::CryptoTransportError::Internal(
                                        "Stream finished without response".to_string(),
                                    ));
                                }
                            }
                            _ => {} // Ignore other events
                        }
                    }
                    Err(crate::CryptoTransportError::Internal(
                        "No response received".to_string(),
                    ))
                })
                .await;

                match response_result {
                    Ok(result) => result,
                    Err(_) => Err(crate::CryptoTransportError::Internal(
                        "RPC request timed out".to_string(),
                    )),
                }
            };

            // Create a pinned future and poll it
            let mut pinned = Box::pin(fut);
            pinned.as_mut().poll(cx)
        } else {
            std::task::Poll::Ready(Err(crate::CryptoTransportError::Internal(
                "No QUIC connection handle available".to_string(),
            )))
        }
    }
}

// Helper function to generate unique stream IDs
fn generate_stream_id() -> u64 {
    crate::quic_conn::generate_next_stream_id()
}
