//! Production-quality streaming file upload over QUIC using existing protocol infrastructure

use super::types::{FileProgress, FileTransferResult};
use crate::error::Result;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::fs::metadata;

// Additional imports for certificate verification
use rustls_native_certs;
use tokio::time::Duration;
use tracing;

/// Execute production-quality streaming file upload using existing protocol
pub(crate) async fn execute_upload_streaming(
    path: PathBuf,
    addr: SocketAddr,
    compression: bool,
    resume: bool,
    progress_callback: Option<Box<dyn Fn(FileProgress) + Send + Sync>>,
) -> Result<FileTransferResult> {
    let start = std::time::Instant::now();

    // Validate file exists and get metadata
    let file_metadata = metadata(&path).await?;
    let file_size = file_metadata.len();

    if file_size == 0 {
        return Err(crate::error::CryptoTransportError::Internal(
            "Cannot upload empty file".to_string(),
        ));
    }

    // Calculate checksum using production helper
    let checksum =
        crate::protocols::file_transfer::sender::helpers::calculate_file_checksum(&path).await?;

    // Get filename
    let filename = path
        .file_name()
        .ok_or_else(|| {
            crate::error::CryptoTransportError::Internal("Invalid filename".to_string())
        })?
        .to_string_lossy()
        .to_string();

    // Establish QUIC connection with proper certificate verification
    let mut crypto_builder = crate::builder::QuicCryptoBuilder::new()
        .with_verify_peer(true)
        .with_max_idle_timeout(300 * 1000)
        .with_initial_max_data(10_000_000_000); // 10GB

    // Parse server address to get hostname for certificate verification
    let server_hostname = if let Some(colon_pos) = addr.to_string().rfind(':') {
        &addr.to_string()[..colon_pos]
    } else {
        &addr.to_string()
    };

    crypto_builder = crypto_builder
        .with_server_name(server_hostname)
        .with_certificate_verification(true)
        .with_hostname_verification(true);

    // Load system certificate store for production security
    let cert_result = rustls_native_certs::load_native_certs();
    for cert in cert_result.certs {
        crypto_builder = crypto_builder.add_root_certificate(cert);
    }
    if !cert_result.errors.is_empty() {
        tracing::warn!(
            "Some certificate loading errors occurred: {:?}",
            cert_result.errors
        );
    }

    let crypto_config = crypto_builder.build_client()?;
    let connection =
        crate::connect_quic_client("0.0.0.0:0", &addr.to_string(), crypto_config).await?;

    // Wait for handshake completion with timeout
    tokio::time::timeout(Duration::from_secs(30), connection.wait_for_handshake()).await??;

    // Convert progress callback to match production format
    let production_callback = progress_callback.map(|callback| {
        Box::new(
            move |progress: crate::protocols::file_transfer::FileTransferProgress| {
                callback(FileProgress {
                    #[allow(clippy::cast_precision_loss)]
                    percent: (progress.bytes_transferred as f64 / progress.total_bytes as f64)
                        * 100.0,
                    bytes_transferred: progress.bytes_transferred,
                    total_bytes: progress.total_bytes,
                    mbps: progress.throughput_mbps,
                });
            },
        )
            as Box<dyn Fn(crate::protocols::file_transfer::FileTransferProgress) + Send + Sync>
    });

    // Use production upload protocol implementation
    let config = crate::protocols::file_transfer::sender::helpers::UploadConfig {
        file_path: &path,
        filename: &filename,
        file_size,
        checksum: &checksum,
        compress: compression,
        resume,
        progress_callback: production_callback,
    };

    let transfer_result =
        crate::protocols::file_transfer::sender::helpers::execute_upload_protocol(
            connection, config,
        )
        .await?;

    // Convert production result to our format
    Ok(FileTransferResult {
        bytes_transferred: transfer_result.bytes_transferred,
        duration: transfer_result.duration,
        success: transfer_result.success,
    })
}
