use futures::Future;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc::unbounded_channel};
use tracing::{debug, info};

use super::builder::QuicCryptoConfig;
use super::error::{CryptoTransportError, Result};
use super::quic_conn::{
    QuicConnectionController, QuicConnectionEvent, QuicConnectionHandle, quic_connection_main_loop,
};
use quiche::{ConnectionId, connect};

/// Connect a QUIC client to a remote server
///
/// # Errors
///
/// Returns an error if:
/// - Socket binding to local address fails
/// - Connection to remote address fails
/// - QUIC handshake fails
/// - Configuration is invalid
/// - Network I/O errors occur
pub fn connect_quic_client(
    local_addr: &str,
    remote_addr: &str,
    crypto: Arc<QuicCryptoConfig>,
) -> impl Future<Output = Result<QuicConnectionHandle>> + Send + 'static {
    let local_addr = local_addr.to_string();
    let remote_addr = remote_addr.to_string();
    async move {
        let socket = Arc::new(tokio::net::UdpSocket::bind(&local_addr).await?);
        socket.connect(&remote_addr).await?;

        let scid_bytes = random_16_bytes();
        let scid = ConnectionId::from_ref(&scid_bytes);
        let remote_addr_parsed = remote_addr
            .parse()
            .map_err(|e| CryptoTransportError::Internal(format!("Invalid remote address: {e}")))?;
        let mut config = crypto.build_config()?;
        let conn = connect(
            None,
            &scid,
            socket.local_addr()?,
            remote_addr_parsed,
            &mut config,
        )?;

        let event_tx = client_event_reporter();
        let (_stop_tx, _stop_rx) = unbounded_channel::<()>();

        let controller = Arc::new(QuicConnectionController {
            conn: Arc::new(std::sync::Mutex::new(conn)),
            outbound_queue: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
            event_tx,
            socket: socket.clone(),
            handshake_done: Arc::new(std::sync::Mutex::new(false)),
        });

        let conn_loop = quic_connection_main_loop(controller.clone());
        tokio::spawn(async move {
            let _ = Box::pin(conn_loop).await;
        });

        let handle = QuicConnectionHandle::new(controller);
        Ok(handle)
    }
}

fn client_event_reporter() -> broadcast::Sender<QuicConnectionEvent> {
    let (tx, mut rx) = broadcast::channel(1000);
    tokio::spawn(async move {
        while let Ok(evt) = rx.recv().await {
            match evt {
                QuicConnectionEvent::HandshakeCompleted => {
                    info!("Client handshake completed");
                }
                QuicConnectionEvent::InboundStreamData(sid, data) => {
                    debug!(
                        stream_id = sid,
                        bytes = data.len(),
                        "Client received stream data"
                    );
                }
                QuicConnectionEvent::StreamFinished(sid) => {
                    debug!(stream_id = sid, "Client stream finished");
                }
                QuicConnectionEvent::ConnectionClosed => {
                    info!("Client connection closed");
                }
            }
        }
    });
    tx
}

fn random_16_bytes() -> [u8; 16] {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::rng().fill_bytes(&mut buf);
    buf
}

/// Default QUIC client for master builder pattern
#[derive(Default)]
pub struct Client;
