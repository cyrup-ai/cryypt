use std::sync::Arc;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use futures::Future;

use quiche::{connect, ConnectionId};
use super::error::{Result, CryptoTransportError};
use super::builder::QuicCryptoConfig;
use super::quic_conn::{
    QuicConnectionController,
    QuicConnectionHandle,
    QuicConnectionEvent,
    quic_connection_main_loop,
};

pub fn connect_quic_client(
    local_addr: &str,
    remote_addr: &str,
    crypto: Arc<QuicCryptoConfig>,
) -> impl Future<Output=Result<QuicConnectionHandle>> + Send + 'static {
    let local_addr = local_addr.to_string();
    let remote_addr = remote_addr.to_string();
    async move {
        let socket = Arc::new(tokio::net::UdpSocket::bind(&local_addr).await?);
        socket.connect(&remote_addr).await?;

        let scid_bytes = random_16_bytes();
        let scid = ConnectionId::from_ref(&scid_bytes);
        let remote_addr_parsed = remote_addr.parse()
            .map_err(|e| CryptoTransportError::Internal(format!("Invalid remote address: {}", e)))?;
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
            let _ = conn_loop.await;
        });

        let handle = QuicConnectionHandle::new(controller);
        Ok(handle)
    }
}

fn client_event_reporter() -> UnboundedSender<QuicConnectionEvent> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(evt) = rx.recv().await {
            match evt {
                QuicConnectionEvent::HandshakeCompleted => {
                    println!("Client: Handshake completed");
                }
                QuicConnectionEvent::InboundStreamData(sid, data) => {
                    println!("Client: Received {} bytes on stream {}", data.len(), sid);
                }
                QuicConnectionEvent::StreamFinished(sid) => {
                    println!("Client: Stream {} finished", sid);
                }
                QuicConnectionEvent::ConnectionClosed => {
                    println!("Client: Connection closed");
                }
            }
        }
    });
    tx
}

fn random_16_bytes() -> [u8; 16] {
    use rand::Rng;
    let mut buf = [0u8; 16];
    rand::rng().fill(&mut buf);
    buf
}