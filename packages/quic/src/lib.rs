#![feature(negative_impls)]
#![feature(marker_trait_attr)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::bind_instead_of_map)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::double_must_use)]
#![allow(clippy::doc_markdown)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::return_self_not_must_use)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::single_match_else)]
#![allow(clippy::trivially_copy_pass_by_ref)]
#![allow(clippy::result_large_err)]
#![allow(clippy::cloned_ref_to_slice_refs)]
#![allow(clippy::implicit_clone)]
#![allow(clippy::new_without_default)]
#![allow(clippy::redundant_closure_for_method_calls)]
#![allow(clippy::inefficient_to_string)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::manual_strip)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::nonminimal_bool)]
#![allow(clippy::unnecessary_map_or)]
#![allow(clippy::unnested_or_patterns)]

//! QUIC encrypted transport protocol implementation
//!
//! This module provides encrypted transport using QUIC protocol with quantum-resistant
//! key exchange and post-quantum TLS configurations.

// New beautiful QUIC API (primary public API)
pub mod quic;

// New cryypt-pattern API
pub mod api;
mod quic_result;

// Re-export result types
pub use quic_result::{
    QuicClientResult, QuicResult, QuicServerResult, QuicStreamResult, QuicWriteResult,
};

// Legacy high-level protocol builders
pub mod protocols;

// Low-level QUIC primitives (internal implementation)
mod builder;
mod client;
pub mod error;
mod keys;
mod quic_conn;
mod server;
pub mod tls;

// Export the new cryypt-pattern API (primary)
pub use api::{QuicClient, QuicMasterBuilder, QuicRecv, QuicSend, QuicServer, quic};

// Re-export common handlers from cryypt_common
pub use cryypt_common::{on_error, on_result};

// Implement NotResult for QUIC types to support on_result handlers
use cryypt_common::traits::NotResult;
impl NotResult for QuicServer {}
impl NotResult for QuicClient {}
impl NotResult for QuicSend {}
impl NotResult for QuicRecv {}

/// Main entry point - README.md pattern: "Cryypt offers two equivalent APIs"
pub struct Cryypt;

impl Cryypt {
    /// Master builder for QUIC operations - README.md pattern
    #[must_use]
    pub fn quic() -> QuicMasterBuilder {
        QuicMasterBuilder
    }
}

// Export protocol builders
pub use protocols::{
    FileTransferProgress, MessageDelivery, QuicFileTransfer, QuicMessaging, TransferResult,
};

// Export low-level primitives for advanced users
pub use builder::{QuicCryptoBuilder, QuicCryptoConfig};
pub use client::{Client, connect_quic_client};
pub use error::{CryptoTransportError, Result};
pub use quic_conn::{QuicConnectionEvent, QuicConnectionHandle};
pub use server::{QuicServerConfig, Server, run_quic_server};
