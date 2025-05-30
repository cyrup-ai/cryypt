//! Error types for crypto transport
use std::fmt;

#[derive(Debug)]
pub enum CryptoTransportError {
    Io(std::io::Error),
    Quiche(quiche::Error),
    CertificateInvalid(String),
    HandshakeFailed(String),
    ConnectionLost(String),
    Internal(String),
}

impl fmt::Display for CryptoTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "IO error: {}", e),
            Self::Quiche(e) => write!(f, "QUIC error: {}", e),
            Self::CertificateInvalid(s) => write!(f, "Certificate invalid: {}", s),
            Self::HandshakeFailed(s) => write!(f, "Handshake failed: {}", s),
            Self::ConnectionLost(s) => write!(f, "Connection lost: {}", s),
            Self::Internal(s) => write!(f, "Internal error: {}", s),
        }
    }
}

impl std::error::Error for CryptoTransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Quiche(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for CryptoTransportError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<quiche::Error> for CryptoTransportError {
    fn from(e: quiche::Error) -> Self {
        Self::Quiche(e)
    }
}

pub type Result<T> = std::result::Result<T, CryptoTransportError>;