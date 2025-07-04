use futures::Future;
use std::sync::Arc;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

use quiche::{accept, ConnectionId, Header};

use super::builder::QuicCryptoConfig;
use super::error::Result;
use super::quic_conn::{
    quic_connection_main_loop, QuicConnectionController, QuicConnectionEvent, QuicConnectionHandle,
};

pub struct QuicServerConfig {
    pub listen_addr: String,
    pub crypto: Arc<QuicCryptoConfig>,
}

/// Return an `impl Future` that never blocks the thread. We do `.await` on `bind` and `.await` on `recv_from`.
pub fn run_quic_server(
    config: QuicServerConfig,
) -> impl Future<Output = Result<()>> + Send + 'static {
    let listen_addr = config.listen_addr.clone();
    let crypto = config.crypto;
    async move {
        let socket = Arc::new(tokio::net::UdpSocket::bind(&listen_addr).await?);

        let mut buf = vec![0u8; 65535];
        loop {
            let (len, from_addr) = socket.recv_from(&mut buf).await?;
            let hdr = match Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN) {
                Ok(h) => h,
                Err(_) => {
                    continue;
                }
            };

            let scid = ConnectionId::from_ref(&hdr.scid);
            let mut quic_config = match crypto.build_config() {
                Ok(c) => c,
                Err(_) => continue,
            };
            let mut quic_conn = match accept(
                &scid,
                None,
                socket.local_addr()?,
                from_addr,
                &mut quic_config,
            ) {
                Ok(c) => c,
                Err(_) => {
                    continue;
                }
            };

            let recv_info = quiche::RecvInfo {
                from: from_addr,
                to: socket.local_addr()?,
            };
            let _ = quic_conn.recv(&mut buf[..len], recv_info);

            let event_tx = server_event_reporter();
            let (_stop_tx, _stop_rx) = unbounded_channel::<()>();

            let controller = Arc::new(QuicConnectionController {
                conn: Arc::new(std::sync::Mutex::new(quic_conn)),
                outbound_queue: Arc::new(std::sync::Mutex::new(std::collections::VecDeque::new())),
                event_tx,
                socket: socket.clone(),
                handshake_done: Arc::new(std::sync::Mutex::new(false)),
            });

            let conn_loop = quic_connection_main_loop(controller.clone());
            tokio::spawn(async move {
                let _ = conn_loop.await;
            });

            let _handle = QuicConnectionHandle::new(controller);
        }
    }
}

fn server_event_reporter() -> UnboundedSender<QuicConnectionEvent> {
    let (tx, mut rx) = unbounded_channel();
    tokio::spawn(async move {
        while let Some(evt) = rx.recv().await {
            match evt {
                QuicConnectionEvent::HandshakeCompleted => {
                    println!("Server: Handshake completed");
                }
                QuicConnectionEvent::InboundStreamData(sid, data) => {
                    println!("Server: Received {} bytes on stream {}", data.len(), sid);
                }
                QuicConnectionEvent::StreamFinished(sid) => {
                    println!("Server: Stream {} finished", sid);
                }
                QuicConnectionEvent::ConnectionClosed => {
                    println!("Server: Connection closed");
                }
            }
        }
    });
    tx
}
