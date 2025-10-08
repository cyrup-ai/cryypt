//! Server builder with fluent API

use crate::{QuicCryptoBuilder, QuicServerConfig, error::Result, run_quic_server};
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::fs::create_dir_all;
use tokio::sync::{RwLock, Semaphore};

/// Server builder with fluent API
#[derive(Debug)]
pub struct FileTransferServerBuilder {
    pub(super) storage_dir: PathBuf,
    pub(super) max_file_size: u64,
    pub(super) max_concurrent: usize,
    pub(super) compression_enabled: bool,
    pub(super) require_auth: bool,
    pub(super) rate_limit_mbps: Option<u64>,
    pub(super) cert_path: Option<String>,
    pub(super) key_path: Option<String>,
}

impl Default for FileTransferServerBuilder {
    fn default() -> Self {
        Self {
            storage_dir: PathBuf::from("./uploads"),
            max_file_size: 1024 * 1024 * 1024, // 1GB
            max_concurrent: 100,
            compression_enabled: true,
            require_auth: false,
            rate_limit_mbps: None,
            cert_path: None,
            key_path: None,
        }
    }
}

impl FileTransferServerBuilder {
    /// Set the directory where uploaded files will be stored
    #[must_use]
    pub fn with_storage_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.storage_dir = dir.into();
        self
    }

    /// Set maximum file size in bytes
    #[must_use]
    pub fn with_max_file_size(mut self, size: u64) -> Self {
        self.max_file_size = size;
        self
    }

    /// Set maximum concurrent transfers
    #[must_use]
    pub fn with_max_concurrent_transfers(mut self, count: usize) -> Self {
        self.max_concurrent = count;
        self
    }

    /// Enable/disable automatic compression
    #[must_use]
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.compression_enabled = enabled;
        self
    }

    /// Require client authentication
    #[must_use]
    pub fn with_authentication(mut self, required: bool) -> Self {
        self.require_auth = required;
        self
    }

    /// Set bandwidth rate limit in Mbps
    #[must_use]
    pub fn with_rate_limit_mbps(mut self, mbps: u64) -> Self {
        self.rate_limit_mbps = Some(mbps);
        self
    }

    /// Set TLS certificate and key paths
    #[must_use]
    pub fn with_tls_cert(mut self, cert_path: &str, key_path: &str) -> Self {
        self.cert_path = Some(cert_path.to_string());
        self.key_path = Some(key_path.to_string());
        self
    }

    /// Start the server listening on the specified address
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Storage directory creation fails
    /// - TLS certificate generation fails  
    /// - Server binding to address fails
    /// - QUIC server startup fails
    pub fn listen(
        self,
        addr: &str,
    ) -> impl Future<Output = Result<super::FileTransferServer>> + Send {
        let addr = addr.to_string();
        async move {
            // Ensure storage directory exists
            create_dir_all(&self.storage_dir).await?;

            // Generate self-signed cert if none provided (for demos)
            // Clone cert/key paths before moving self fields
            let cert_path_clone = self.cert_path.clone();
            let key_path_clone = self.key_path.clone();

            let (cert_path, key_path) =
                if let (Some(cert), Some(key)) = (self.cert_path, self.key_path) {
                    (cert, key)
                } else {
                    super::helpers::generate_temp_certificates().await?
                };

            // Build QUIC crypto config with optimal settings
            let crypto = QuicCryptoBuilder::new()
                .with_verify_peer(self.require_auth)
                .with_max_idle_timeout(300_000) // 5 minutes
                .with_initial_max_data(self.max_file_size)
                .with_max_udp_payload_size(9000) // Jumbo frames
                .build_server(&cert_path, &key_path)?;

            let quic_config = QuicServerConfig {
                listen_addr: addr,
                crypto,
            };

            // Start the server with integrated file transfer protocol
            let storage_dir = self.storage_dir.clone();
            let max_concurrent = self.max_concurrent;

            let config_clone = FileTransferServerBuilder {
                storage_dir: storage_dir.clone(),
                max_file_size: self.max_file_size,
                max_concurrent,
                compression_enabled: self.compression_enabled,
                require_auth: self.require_auth,
                rate_limit_mbps: self.rate_limit_mbps,
                cert_path: cert_path_clone,
                key_path: key_path_clone,
            };

            let server = super::FileTransferServer {
                config: config_clone,
                storage_dir,
                active_transfers: Arc::new(RwLock::new(std::collections::HashMap::new())),
                semaphore: Arc::new(Semaphore::new(max_concurrent)),
            };

            // This would integrate with the QUIC server to handle file transfer protocol
            run_quic_server(quic_config).await?;

            Ok(server)
        }
    }
}
