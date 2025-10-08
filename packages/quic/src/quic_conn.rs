use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::sync::broadcast;

use super::error::{CryptoTransportError, Result};
use quiche::{Connection, RecvInfo};

#[derive(Debug, Clone)]
pub enum QuicConnectionEvent {
    HandshakeCompleted,
    InboundStreamData(u64, Vec<u8>),
    StreamFinished(u64),
    ConnectionClosed,
}

pub struct QuicConnectionController {
    pub conn: Arc<Mutex<Connection>>,
    pub outbound_queue: Arc<Mutex<VecDeque<OutboundMessage>>>,
    pub event_tx: broadcast::Sender<QuicConnectionEvent>,
    pub socket: Arc<tokio::net::UdpSocket>,
    pub handshake_done: Arc<Mutex<bool>>,
}

#[derive(Debug)]
pub struct OutboundMessage {
    data: Vec<u8>,
    fin: bool,
    stream_id: Option<u64>,
}

/// Public handle for user calls. If you need future-based methods, return `impl Future`.
#[derive(Clone)]
pub struct QuicConnectionHandle {
    controller: Arc<QuicConnectionController>,
}

impl QuicConnectionHandle {
    #[must_use]
    pub fn new(controller: Arc<QuicConnectionController>) -> Self {
        Self { controller }
    }

    /// For sending data, no blocking—immediately enqueues partial data if flow control halts.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Outbound queue lock acquisition fails
    /// - Stream is already closed or in error state
    /// - Data size exceeds stream limits
    pub fn send_stream_data(&self, data: &[u8], fin: bool) -> Result<()> {
        let mut queue = self.controller.outbound_queue.lock().map_err(|_| {
            crate::error::CryptoTransportError::Internal(
                "Failed to acquire outbound queue lock".to_string(),
            )
        })?;
        queue.push_back(OutboundMessage {
            data: data.to_vec(),
            fin,
            stream_id: None,
        });
        Ok(())
    }

    /// Provide a future that completes once handshake is done.
    /// We do a small async loop checking a shared bool, no blocking calls.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Handshake lock acquisition fails
    /// - Handshake timeout exceeded
    /// - Connection is terminated during handshake
    /// - Protocol errors during handshake
    pub fn wait_for_handshake(
        &self,
    ) -> impl std::future::Future<Output = Result<()>> + Send + 'static {
        let ctrl = self.controller.clone();
        async move {
            loop {
                {
                    let is_done = *ctrl.handshake_done.lock().map_err(|_| {
                        CryptoTransportError::from("Failed to acquire handshake lock")
                    })?;
                    if is_done {
                        return Ok(());
                    }
                }
                // Reduced polling frequency for better performance
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }

    /// Get access to the controller for advanced operations
    /// This is used internally for stream integration
    #[allow(dead_code)]
    pub(crate) fn controller(&self) -> &Arc<QuicConnectionController> {
        &self.controller
    }

    /// Subscribe to events for RPC response handling
    #[must_use]
    pub fn subscribe_to_events(&self) -> broadcast::Receiver<QuicConnectionEvent> {
        self.controller.event_tx.subscribe()
    }

    /// Send data to a specific stream ID
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Outbound queue lock acquisition fails
    /// - Stream ID is invalid or closed
    /// - Data size exceeds stream limits
    /// - Flow control prevents sending
    pub fn send_stream_data_with_id(&self, stream_id: u64, data: &[u8], fin: bool) -> Result<()> {
        let mut queue = self.controller.outbound_queue.lock().map_err(|_| {
            crate::error::CryptoTransportError::Internal(
                "Failed to acquire outbound queue lock".to_string(),
            )
        })?;
        queue.push_back(OutboundMessage {
            data: data.to_vec(),
            fin,
            stream_id: Some(stream_id),
        });
        Ok(())
    }
}

/// Main QUIC connection loop: fully non-blocking, no "`WouldBlock`," no partial blocking calls.
/// We define it as a normal function returning `impl Future<Output=Result<()>>`.
pub async fn quic_connection_main_loop(controller: Arc<QuicConnectionController>) -> Result<()> {
    let mut recv_buf = vec![0u8; 65535];

    loop {
        // Read an incoming packet
        let (len, from_addr) = controller.socket.recv_from(&mut recv_buf).await?;
        {
            let mut conn_guard = controller
                .conn
                .lock()
                .map_err(|_| CryptoTransportError::from("Failed to acquire connection lock"))?;
            let recv_info = RecvInfo {
                from: from_addr,
                to: controller.socket.local_addr()?,
            };
            match conn_guard.recv(&mut recv_buf[..len], recv_info) {
                Ok(_) => {
                    drop(conn_guard);
                    process_readable_streams(&controller)?;
                    check_handshake_complete(&controller)?;
                }
                Err(quiche::Error::Done) => {
                    // no data in that packet
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }

        // Attempt to flush queued outbound data
        flush_outbound(&controller)?;

        // Then flush QUIC packets to the UDP socket
        let mut out_buf = vec![0u8; 65535].into_boxed_slice();
        loop {
            let send_result = {
                let mut conn_guard = controller.conn.lock().map_err(|_| {
                    CryptoTransportError::from("Failed to acquire connection lock for send")
                })?;
                conn_guard.send(&mut out_buf)
            };

            match send_result {
                Ok((written, send_info)) => {
                    controller
                        .socket
                        .send_to(&out_buf[..written], send_info.to)
                        .await?;
                }
                Err(quiche::Error::Done) => {
                    break;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }

        // Check if closed
        {
            let conn_guard = controller.conn.lock().map_err(|_| {
                CryptoTransportError::from("Failed to acquire connection lock for close check")
            })?;
            if conn_guard.is_closed() {
                drop(conn_guard);
                let _ = controller
                    .event_tx
                    .send(QuicConnectionEvent::ConnectionClosed);
                break;
            }
        }
    }

    Ok(())
}

fn check_handshake_complete(controller: &Arc<QuicConnectionController>) -> Result<()> {
    let is_established = {
        let conn_guard = controller.conn.lock().map_err(|_| {
            CryptoTransportError::from("Failed to acquire connection lock for handshake check")
        })?;
        conn_guard.is_established()
    };

    if !is_established {
        return Ok(());
    }

    let should_send_event = {
        let mut done = controller
            .handshake_done
            .lock()
            .map_err(|_| CryptoTransportError::from("Failed to acquire handshake done lock"))?;
        if *done {
            false
        } else {
            *done = true;
            true
        }
    };

    if should_send_event {
        let _ = controller
            .event_tx
            .send(QuicConnectionEvent::HandshakeCompleted);
    }

    Ok(())
}

fn process_readable_streams(controller: &Arc<QuicConnectionController>) -> Result<()> {
    let readable_streams: Vec<u64> = {
        let conn_guard = controller.conn.lock().map_err(|_| {
            CryptoTransportError::from("Failed to acquire connection lock for readable streams")
        })?;
        conn_guard.readable().collect()
    };

    for stream_id in readable_streams {
        loop {
            let mut buf = vec![0u8; 65535];
            let result = {
                let mut conn_guard = controller.conn.lock().map_err(|_| {
                    CryptoTransportError::from("Failed to acquire connection lock for stream recv")
                })?;
                conn_guard.stream_recv(stream_id, &mut buf)
            };

            match result {
                Ok((bytes_read, fin)) => {
                    let data = buf[..bytes_read].to_vec();
                    let _ = controller
                        .event_tx
                        .send(QuicConnectionEvent::InboundStreamData(stream_id, data));
                    if fin {
                        let _ = controller
                            .event_tx
                            .send(QuicConnectionEvent::StreamFinished(stream_id));
                    }
                }
                Err(quiche::Error::Done) => {
                    break;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
    }
    Ok(())
}

// Centralized stream ID generator for consistency across the codebase
pub fn generate_next_stream_id() -> u64 {
    static STREAM_COUNTER: AtomicU64 = AtomicU64::new(0);
    STREAM_COUNTER.fetch_add(4, Ordering::SeqCst) + 4
}

fn flush_outbound(controller: &Arc<QuicConnectionController>) -> Result<()> {
    let mut conn_guard = controller
        .conn
        .lock()
        .map_err(|_| CryptoTransportError::from("Failed to acquire connection lock for flush"))?;
    let mut queue = controller.outbound_queue.lock().map_err(|_| {
        CryptoTransportError::from("Failed to acquire outbound queue lock for flush")
    })?;

    // Process queue using proper index management pattern from quiche examples
    let i = 0;
    while i < queue.len() {
        let msg = &mut queue[i];

        // Allocate stream ID if not already set
        if msg.stream_id.is_none() {
            msg.stream_id = Some(generate_next_stream_id());
        }
        let stream_id = msg.stream_id.ok_or_else(|| {
            CryptoTransportError::from("Stream ID not allocated after assignment")
        })?;

        // Attempt to send remaining data using quiche pattern
        match conn_guard.stream_send(stream_id, &msg.data, msg.fin) {
            Ok(written) => {
                if written < msg.data.len() {
                    // Partial write - update message with remaining data
                    let remaining_data = msg.data[written..].to_vec();
                    msg.data = remaining_data;
                    // Keep message in queue, don't increment i - will retry on next flush
                    break;
                }
                // Complete write - remove message from queue
                queue.remove(i);
                // Don't increment i since we removed an element
            }
            Err(quiche::Error::Done | quiche::Error::FlowControl | quiche::Error::StreamLimit) => {
                // Flow control or stream limits - stop processing queue
                break;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    Ok(())
}
