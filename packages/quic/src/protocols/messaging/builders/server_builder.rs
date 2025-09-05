//! Builder for configuring messaging server

use std::future::Future;
use std::time::Duration;

use super::super::types::{CompressionAlgorithm, EncryptionAlgorithm};
use super::super::server::{MessagingServer, MessagingServerConfig};

/// Builder for configuring messaging server
pub struct MessagingServerBuilder {
    max_message_size: usize,
    retain_messages: bool,
    delivery_timeout: Duration,
    default_compression: CompressionAlgorithm,
    compression_level: u8,
    default_encryption: EncryptionAlgorithm,
    shared_secret: Option<Vec<u8>>,
}

impl Default for MessagingServerBuilder {
    fn default() -> Self {
        Self {
            max_message_size: 0,
            retain_messages: false,
            delivery_timeout: Duration::default(),
            default_compression: CompressionAlgorithm::Zstd,
            compression_level: 3, // Balanced performance/compression ratio
            default_encryption: EncryptionAlgorithm::Aes256Gcm,
            shared_secret: None, // Will be generated if not provided
        }
    }
}

impl MessagingServerBuilder {
    /// Create a testing-oriented builder with minimal security for development and testing
    pub fn testing() -> Self {
        Self {
            max_message_size: 1_048_576, // 1MB
            retain_messages: false,
            delivery_timeout: Duration::from_secs(5), // Short timeout for tests
            default_compression: CompressionAlgorithm::None, // No compression for testing
            compression_level: 1,
            default_encryption: EncryptionAlgorithm::ChaCha20Poly1305, // Fast encryption
            shared_secret: None,
        }
    }

    /// Create a development-oriented builder with sensible defaults
    pub fn development() -> Self {
        Self {
            max_message_size: 1_048_576, // 1MB
            retain_messages: false,
            delivery_timeout: Duration::from_secs(30),
            default_compression: CompressionAlgorithm::Zstd,
            compression_level: 3,
            default_encryption: EncryptionAlgorithm::Aes256Gcm,
            shared_secret: None,
        }
    }
    
    /// Create a production-oriented builder with robust defaults
    pub fn production() -> Self {
        Self {
            max_message_size: 10_485_760, // 10MB
            retain_messages: true,
            delivery_timeout: Duration::from_secs(60),
            default_compression: CompressionAlgorithm::Zstd,
            compression_level: 6,
            default_encryption: EncryptionAlgorithm::Aes256Gcm,
            shared_secret: None,
        }
    }
    
    /// Create a low-latency builder optimized for speed
    pub fn low_latency() -> Self {
        Self {
            max_message_size: 65536, // 64KB
            retain_messages: false,
            delivery_timeout: Duration::from_secs(5),
            default_compression: CompressionAlgorithm::None,
            compression_level: 1,
            default_encryption: EncryptionAlgorithm::ChaCha20Poly1305,
            shared_secret: None,
        }
    }
    
    /// Create a high-throughput builder optimized for large payloads
    pub fn high_throughput() -> Self {
        Self {
            max_message_size: 50_331_648, // 48MB
            retain_messages: true,
            delivery_timeout: Duration::from_secs(300),
            default_compression: CompressionAlgorithm::Zstd,
            compression_level: 9,
            default_encryption: EncryptionAlgorithm::Aes256Gcm,
            shared_secret: None,
        }
    }
    
    /// Create a secure production builder with minimal configuration
    pub fn production_minimal() -> Self {
        // Generate cryptographically secure random shared secret
        use rand::RngCore;
        let mut shared_secret = vec![0u8; 32]; // 256-bit secret
        rand::rng().fill_bytes(&mut shared_secret);
        
        Self {
            max_message_size: 65536, // 64KB
            retain_messages: false,
            delivery_timeout: Duration::from_secs(10),
            default_compression: CompressionAlgorithm::Zstd, // Enable compression for production
            compression_level: 6, // Balanced compression level
            default_encryption: EncryptionAlgorithm::ChaCha20Poly1305,
            shared_secret: Some(shared_secret),
        }
    }
    
    /// Create a testing builder with deterministic configuration for tests only
    /// WARNING: This method uses a fixed key and should NEVER be used in production
    #[cfg(test)]
    pub fn testing() -> Self {
        Self {
            max_message_size: 65536, // 64KB
            retain_messages: false,
            delivery_timeout: Duration::from_secs(10),
            default_compression: CompressionAlgorithm::None,
            compression_level: 1,
            default_encryption: EncryptionAlgorithm::ChaCha20Poly1305,
            shared_secret: Some(vec![42u8; 32]), // Fixed key for testing only
        }
    }

    /// Set maximum message size in bytes
    pub fn with_max_message_size(mut self, size: usize) -> Self {
        self.max_message_size = size;
        self
    }

    /// Enable or disable message retention on server
    pub fn with_message_retention(mut self, retain: bool) -> Self {
        self.retain_messages = retain;
        self
    }

    /// Set delivery timeout for message acknowledgments
    pub fn with_delivery_timeout(mut self, timeout: Duration) -> Self {
        self.delivery_timeout = timeout;
        self
    }

    /// Configure compression algorithm and level
    pub fn with_compression(mut self, algorithm: CompressionAlgorithm, level: u8) -> Self {
        self.default_compression = algorithm;
        self.compression_level = level;
        self
    }

    /// Configure encryption algorithm
    pub fn with_encryption(mut self, algorithm: EncryptionAlgorithm) -> Self {
        self.default_encryption = algorithm;
        self
    }

    /// Set shared secret for connection key derivation
    pub fn with_shared_secret(mut self, secret: Vec<u8>) -> Self {
        self.shared_secret = Some(secret);
        self
    }

    /// Disable compression (use CompressionAlgorithm::None)
    pub fn disable_compression(mut self) -> Self {
        self.default_compression = CompressionAlgorithm::None;
        self
    }

    /// Disable encryption (use EncryptionAlgorithm::None)
    pub fn disable_encryption(mut self) -> Self {
        self.default_encryption = EncryptionAlgorithm::None;
        self
    }

    /// Start listening on the specified address using working implementation
    pub fn listen(self, addr: &str) -> impl Future<Output = crate::Result<MessagingServer>> + Send {
        
        // Generate secure random shared secret if not provided
        let shared_secret = self.shared_secret.unwrap_or_else(|| {
            use rand::RngCore;
            let mut secret = vec![0u8; 32]; // 256-bit secret
            rand::rng().fill_bytes(&mut secret);
            secret
        });
        
        let addr_string = addr.to_string();
        let max_message_size = if self.max_message_size == 0 { 1024 * 1024 } else { self.max_message_size };
        let retain_messages = self.retain_messages;
        let delivery_timeout = if self.delivery_timeout.is_zero() { Duration::from_secs(30) } else { self.delivery_timeout };
        let default_compression = self.default_compression;
        let compression_level = self.compression_level;
        let default_encryption = self.default_encryption;
        
        async move {
            // Use development configuration with proper TLS integration
            let cert_dir = std::path::PathBuf::from("./certs");
            let mut config = MessagingServerConfig::development(cert_dir).await?;
            
            // Override with user settings
            config.max_message_size = max_message_size;
            config.retain_messages = retain_messages;
            config.delivery_timeout = delivery_timeout;
            config.default_compression = default_compression;
            config.compression_level = compression_level;
            config.default_encryption = default_encryption;
            config.shared_secret = shared_secret;
            // Parse the address
            let socket_addr = addr_string.parse().map_err(|e| {
                crate::error::CryptoTransportError::Internal(format!("Invalid address {}: {}", addr_string, e))
            })?;
            
            // Create messaging server with working implementation
            let messaging_server = MessagingServer::new(socket_addr, config).await?;
            
            println!("🚀 QUIC messaging server created on {}", addr_string);
            
            // Return the server - user can call .run().await to start it
            Ok(messaging_server)
        }
    }
}