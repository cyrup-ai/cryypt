//! Stream dispatcher for multiplexed protocols

use super::config::Protocol;
use super::file_transfer::FileTransferProtocol;
use super::messaging::MessagingProtocol;
use super::rpc::RpcProtocol;
use crate::quic_conn::QuicConnectionHandle;
use std::net::SocketAddr;

/// Stream dispatcher for multiplexed protocols
pub struct QuicStreamDispatcher {
    addr: SocketAddr,
    handle: Option<QuicConnectionHandle>,
}

impl QuicStreamDispatcher {
    pub(super) fn new(addr: SocketAddr, handle: Option<QuicConnectionHandle>) -> Self {
        Self { addr, handle }
    }

    /// Access file transfer protocol
    #[must_use]
    pub fn file_transfer(&self) -> FileTransferProtocol {
        FileTransferProtocol::new(self.addr)
    }

    /// Access messaging protocol
    #[must_use]
    pub fn messaging(&self) -> MessagingProtocol {
        MessagingProtocol::new(self.addr, self.handle.clone())
    }

    /// Access RPC protocol
    #[must_use]
    pub fn rpc(&self) -> RpcProtocol {
        RpcProtocol::new(self.addr, self.handle.clone())
    }
}

/// Individual QUIC stream for protocol handling
pub struct QuicStream {
    protocol: Protocol,
    stream_id: u64,
}

impl QuicStream {
    /// Create new QUIC stream
    #[must_use]
    pub fn new(protocol: Protocol, stream_id: u64) -> Self {
        Self {
            protocol,
            stream_id,
        }
    }

    /// Get the protocol type for this stream
    #[must_use]
    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    /// Get the stream ID
    #[must_use]
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }
}
