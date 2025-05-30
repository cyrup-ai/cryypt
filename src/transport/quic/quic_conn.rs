use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use tokio::sync::mpsc::UnboundedSender;

use super::error::Result;
use quiche::{Connection, RecvInfo};

#[derive(Debug)]
pub enum QuicConnectionEvent {
    HandshakeCompleted,
    InboundStreamData(u64, Vec<u8>),
    StreamFinished(u64),
    ConnectionClosed,
}

pub struct QuicConnectionController {
    pub conn: Arc<Mutex<Connection>>,
    pub outbound_queue: Arc<Mutex<VecDeque<OutboundMessage>>>,
    pub event_tx: UnboundedSender<QuicConnectionEvent>,
    pub socket: Arc<tokio::net::UdpSocket>,
    pub handshake_done: Arc<Mutex<bool>>,
}

#[derive(Debug)]
struct OutboundMessage {
    data: Vec<u8>,
    fin: bool,
}

/// Public handle for user calls. If you need future-based methods, return `impl Future`.
#[derive(Clone)]
pub struct QuicConnectionHandle {
    controller: Arc<QuicConnectionController>,
}

impl QuicConnectionHandle {
    pub fn new(controller: Arc<QuicConnectionController>) -> Self {
        Self { controller }
    }

    /// For sending data, no blocking—immediately enqueues partial data if flow control halts.
    pub fn send_stream_data(&self, data: &[u8], fin: bool) -> Result<()> {
        let mut queue = self.controller.outbound_queue.lock().unwrap();
        queue.push_back(OutboundMessage {
            data: data.to_vec(),
            fin,
        });
        Ok(())
    }

    /// Provide a future that completes once handshake is done. 
    /// We do a small async loop checking a shared bool, no blocking calls.
    pub fn wait_for_handshake(&self) -> impl std::future::Future<Output=Result<()>> + Send + 'static {
        let ctrl = self.controller.clone();
        async move {
            loop {
                {
                    let is_done = *ctrl.handshake_done.lock().unwrap();
                    if is_done {
                        return Ok(());
                    }
                }
                // Sleep a short time so we re-check. Could integrate wakers or quiche events.
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        }
    }
}

/// Main QUIC connection loop: fully non-blocking, no "WouldBlock," no partial blocking calls. 
/// We define it as a normal function returning `impl Future<Output=Result<()>>`.
pub fn quic_connection_main_loop(
    controller: Arc<QuicConnectionController>
) -> impl std::future::Future<Output = Result<()>> + Send + 'static {
    async move {
        let mut recv_buf = vec![0u8; 65535];

        loop {
            // Read an incoming packet
            let (len, from_addr) = controller.socket.recv_from(&mut recv_buf).await?;
            {
                let mut conn_guard = controller.conn.lock().unwrap();
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
            let mut out_buf = [0u8; 65535];
            loop {
                let send_result = {
                    let mut conn_guard = controller.conn.lock().unwrap();
                    conn_guard.send(&mut out_buf)
                };
                
                match send_result {
                    Ok((written, send_info)) => {
                        controller.socket.send_to(&out_buf[..written], send_info.to).await?;
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
                let conn_guard = controller.conn.lock().unwrap();
                if conn_guard.is_closed() {
                    drop(conn_guard);
                    let _ = controller.event_tx.send(QuicConnectionEvent::ConnectionClosed);
                    break;
                }
            }
        }

        Ok(())
    }
}

fn check_handshake_complete(controller: &Arc<QuicConnectionController>) -> Result<()> {
    let is_established = {
        let conn_guard = controller.conn.lock().unwrap();
        conn_guard.is_established()
    };
    
    if !is_established {
        return Ok(());
    }
    
    let should_send_event = {
        let mut done = controller.handshake_done.lock().unwrap();
        if !*done {
            *done = true;
            true
        } else {
            false
        }
    };
    
    if should_send_event {
        let _ = controller.event_tx.send(QuicConnectionEvent::HandshakeCompleted);
    }
    
    Ok(())
}

fn process_readable_streams(controller: &Arc<QuicConnectionController>) -> Result<()> {
    let readable_streams: Vec<u64> = {
        let conn_guard = controller.conn.lock().unwrap();
        conn_guard.readable().collect()
    };
    
    for stream_id in readable_streams {
        loop {
            let mut buf = vec![0u8; 65535];
            let result = {
                let mut conn_guard = controller.conn.lock().unwrap();
                conn_guard.stream_recv(stream_id, &mut buf)
            };
            
            match result {
                Ok((bytes_read, fin)) => {
                    let data = buf[..bytes_read].to_vec();
                    let _ = controller.event_tx.send(
                        QuicConnectionEvent::InboundStreamData(stream_id, data)
                    );
                    if fin {
                        let _ = controller.event_tx.send(
                            QuicConnectionEvent::StreamFinished(stream_id)
                        );
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

fn flush_outbound(controller: &Arc<QuicConnectionController>) -> Result<()> {
    let mut conn_guard = controller.conn.lock().unwrap();
    let mut queue = controller.outbound_queue.lock().unwrap();

    let mut i = 0;
    while i < queue.len() {
        let msg = &mut queue[i];
        // Use a deterministic stream ID for now (proper stream management would be more complex)
        let stream_id = (i as u64) * 4; // Client-initiated bidirectional streams start at 0 and increment by 4

        let mut offset = 0;
        while offset < msg.data.len() {
            match conn_guard.stream_send(
                stream_id,
                &msg.data[offset..],
                msg.fin && (offset + 1 >= msg.data.len()),
            ) {
                Ok(written) => {
                    offset += written;
                }
                Err(quiche::Error::Done)
                | Err(quiche::Error::FlowControl)
                | Err(quiche::Error::StreamLimit) => {
                    break;
                }
                Err(e) => {
                    return Err(e.into());
                }
            }
        }
        if offset < msg.data.len() {
            let leftover = msg.data[offset..].to_vec();
            msg.data = leftover;
            break;
        } else {
            queue.remove(i);
            // Don't increment i since we removed an element
        }
    }

    Ok(())
}