use futures::Future;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc::unbounded_channel};
use tracing::{debug, info};

use quiche::{ConnectionId, Header, accept};

use super::builder::QuicCryptoConfig;
use super::error::Result;
use super::quic_conn::{
    QuicConnectionController, QuicConnectionEvent, QuicConnectionHandle, quic_connection_main_loop,
};

pub struct QuicServerConfig {
    pub listen_addr: String,
    pub crypto: Arc<QuicCryptoConfig>,
}

/// Return an `impl Future` that never blocks the thread. We do `.await` on `bind` and `.await` on `recv_from`.
///
/// # Errors
///
/// Returns an error if:
/// - Socket binding to listen address fails
/// - UDP packet reception fails
/// - QUIC connection processing fails
/// - Protocol parsing errors occur
/// - Network I/O errors occur during operation
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
            let Ok(hdr) = Header::from_slice(&mut buf[..len], quiche::MAX_CONN_ID_LEN) else {
                continue;
            };

            let scid = ConnectionId::from_ref(&hdr.scid);
            let Ok(mut quic_config) = crypto.build_config() else {
                continue;
            };
            let Ok(mut quic_conn) = accept(
                &scid,
                None,
                socket.local_addr()?,
                from_addr,
                &mut quic_config,
            ) else {
                continue;
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
                let _ = Box::pin(conn_loop).await;
            });

            let _handle = QuicConnectionHandle::new(controller);
        }
    }
}

fn server_event_reporter() -> broadcast::Sender<QuicConnectionEvent> {
    let (tx, mut rx) = broadcast::channel(1000);
    tokio::spawn(async move {
        while let Ok(evt) = rx.recv().await {
            match evt {
                QuicConnectionEvent::HandshakeCompleted => {
                    info!("Server handshake completed");
                }
                QuicConnectionEvent::InboundStreamData(sid, data) => {
                    debug!(
                        stream_id = sid,
                        bytes = data.len(),
                        "Server received stream data"
                    );
                }
                QuicConnectionEvent::StreamFinished(sid) => {
                    debug!(stream_id = sid, "Server stream finished");
                }
                QuicConnectionEvent::ConnectionClosed => {
                    info!("Server connection closed");
                }
            }
        }
    });
    tx
}

/// Default QUIC server for master builder pattern
#[derive(Default)]
pub struct Server;

impl Server {
    #[must_use]
    pub fn new() -> Self {
        Server
    }
}
