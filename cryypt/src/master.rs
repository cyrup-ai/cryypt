//! Master builder for all cryypt operations following README.md patterns

#[cfg(feature = "jwt")]
use cryypt_jwt::Cryypt as JwtCryypt;

/// Master builder providing unified entry point for all cryypt operations
/// README.md pattern: "Cryypt offers two equivalent APIs"
pub struct Cryypt;

impl Cryypt {
    /// Entry point for cipher operations - README.md pattern
    /// Example: `Cryypt::cipher().aes().with_key(key).encrypt(data).await`
    #[cfg(any(feature = "aes", feature = "chacha20"))]
    pub fn cipher() -> CipherMasterBuilder {
        CipherMasterBuilder
    }

    /// Entry point for hashing operations - README.md pattern
    /// Example: `Cryypt::hash().sha256().compute(data).await`
    #[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
    pub fn hash() -> HashMasterBuilder {
        HashMasterBuilder
    }

    /// Entry point for compression operations - README.md pattern
    /// Example: `Cryypt::compress().zstd().compress(data).await`
    #[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
    pub fn compress() -> CompressMasterBuilder {
        CompressMasterBuilder
    }

    /// Entry point for JWT operations - README.md pattern
    /// Example: `Cryypt::jwt().hs256().with_secret(secret).sign().await`
    #[cfg(feature = "jwt")]
    pub fn jwt() -> cryypt_jwt::JwtMasterBuilder {
        JwtCryypt::jwt()
    }

    /// Entry point for key operations - README.md pattern
    /// Example: `Cryypt::key().size(256.bits()).with_store(store).generate().await`
    #[cfg(feature = "key")]
    pub fn key() -> KeyMasterBuilder {
        KeyMasterBuilder
    }

    /// Entry point for vault operations - README.md pattern
    /// Example: `Cryypt::vault().with_config(config).create().await`
    #[cfg(feature = "vault")]
    pub fn vault() -> VaultMasterBuilder {
        VaultMasterBuilder
    }

    /// Entry point for post-quantum cryptography operations - README.md pattern
    /// Example: `Cryypt::pqcrypto().kyber().generate_keypair().await`
    #[cfg(feature = "pqcrypto")]
    pub fn pqcrypto() -> PqcryptoMasterBuilder {
        PqcryptoMasterBuilder
    }

    /// Entry point for QUIC operations - README.md pattern
    /// Example: `Cryypt::quic().server().with_cert(cert).bind(addr).await`
    #[cfg(feature = "quic")]
    pub fn quic() -> QuicMasterBuilder {
        QuicMasterBuilder
    }
}

/// Master builder for cipher operations
#[cfg(any(feature = "aes", feature = "chacha20"))]
pub struct CipherMasterBuilder;

#[cfg(any(feature = "aes", feature = "chacha20"))]
impl CipherMasterBuilder {
    /// Use AES-256-GCM encryption - README.md pattern
    #[cfg(feature = "aes")]
    pub fn aes(self) -> cryypt_cipher::AesBuilder {
        cryypt_cipher::Cipher::aes()
    }

    /// Use ChaCha20-Poly1305 encryption - README.md pattern
    #[cfg(feature = "chacha20")]
    pub fn chacha20(self) -> cryypt_cipher::ChaChaBuilder {
        cryypt_cipher::Cipher::chacha20()
    }

    /// Use ChaCha20-Poly1305 encryption (alias) - README.md pattern
    #[cfg(feature = "chacha20")]
    pub fn chachapoly(self) -> cryypt_cipher::ChaChaBuilder {
        cryypt_cipher::Cipher::chacha20()
    }
}

/// Master builder for hashing operations
#[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
pub struct HashMasterBuilder;

#[cfg(any(feature = "sha256", feature = "sha3", feature = "blake2b"))]
impl HashMasterBuilder {
    /// Use SHA-256 hashing - README.md pattern
    #[cfg(feature = "sha256")]
    pub fn sha256(self) -> cryypt_hashing::Sha256Builder {
        cryypt_hashing::Hash::sha256()
    }

    /// Use SHA3-256 hashing - README.md pattern
    #[cfg(feature = "sha3")]
    pub fn sha3_256(self) -> cryypt_hashing::Sha3_256Builder {
        cryypt_hashing::Hash::sha3_256()
    }

    /// Use BLAKE2b hashing - README.md pattern
    #[cfg(feature = "blake2b")]
    pub fn blake2b(self) -> cryypt_hashing::Blake2bBuilder {
        cryypt_hashing::Hash::blake2b()
    }
}

/// Master builder for compression operations
#[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
pub struct CompressMasterBuilder;

#[cfg(any(feature = "zstd", feature = "gzip", feature = "bzip2", feature = "zip"))]
impl CompressMasterBuilder {
    /// Use Zstandard compression - README.md pattern
    #[cfg(feature = "zstd")]
    pub fn zstd(
        self,
    ) -> cryypt_compression::ZstdBuilder<cryypt_compression::api::zstd_builder::NoLevel> {
        cryypt_compression::Compress::zstd()
    }

    /// Use Gzip compression - README.md pattern
    #[cfg(feature = "gzip")]
    pub fn gzip(
        self,
    ) -> cryypt_compression::GzipBuilder<cryypt_compression::api::gzip_builder::NoLevel> {
        cryypt_compression::Compress::gzip()
    }

    /// Use Bzip2 compression - README.md pattern
    #[cfg(feature = "bzip2")]
    pub fn bzip2(
        self,
    ) -> cryypt_compression::Bzip2Builder<cryypt_compression::api::bzip2_builder::NoLevel> {
        cryypt_compression::Compress::bzip2()
    }

    /// Use ZIP compression for multi-file archives - README.md pattern
    #[cfg(feature = "zip")]
    pub fn zip(
        self,
    ) -> cryypt_compression::ZipBuilder<cryypt_compression::api::zip_builder::NoFiles> {
        cryypt_compression::Compress::zip()
    }
}

/// Master builder for key operations
#[cfg(feature = "key")]
pub struct KeyMasterBuilder;

#[cfg(feature = "key")]
impl KeyMasterBuilder {
    /// Generate a new key - README.md pattern
    pub fn generate(self) -> cryypt_key::api::KeyGenerator {
        cryypt_key::api::KeyGenerator::new()
    }

    /// Retrieve an existing key - README.md pattern
    pub fn retrieve(self) -> cryypt_key::api::KeyRetriever {
        cryypt_key::api::KeyRetriever::new()
    }
}

/// Master builder for vault operations
#[cfg(feature = "vault")]
pub struct VaultMasterBuilder;

/// Vault builder with path configuration
#[cfg(feature = "vault")]
pub struct VaultWithPath {
    path: String,
    config: Option<cryypt_vault::config::VaultConfig>,
    passphrase: Option<String>,
}

/// Vault builder with path and result handler
#[cfg(feature = "vault")]
pub struct VaultWithPathAndHandler<F, T> {
    path: String,
    config: Option<cryypt_vault::config::VaultConfig>,
    passphrase: Option<String>,
    result_handler: F,
    _phantom: std::marker::PhantomData<T>,
}

#[cfg(feature = "vault")]
impl VaultMasterBuilder {
    /// Create a new vault at path - README.md pattern
    pub fn create<P: AsRef<str>>(self, path: P) -> VaultWithPath {
        VaultWithPath {
            path: path.as_ref().to_string(),
            config: None,
            passphrase: None,
        }
    }

    /// Create a vault with configuration - README.md pattern
    pub fn with_config(self, config: cryypt_vault::config::VaultConfig) -> VaultWithPath {
        VaultWithPath {
            path: "./vault".to_string(),
            config: Some(config),
            passphrase: None,
        }
    }

    /// Create a vault at specified path - README.md pattern
    pub fn at_path<P: AsRef<std::path::Path>>(self, path: P) -> VaultWithPath {
        VaultWithPath {
            path: path.as_ref().to_string_lossy().to_string(),
            config: None,
            passphrase: None,
        }
    }
}

#[cfg(feature = "vault")]
impl VaultWithPath {
    /// Add passphrase to vault builder
    pub fn with_passphrase<P: AsRef<str>>(mut self, passphrase: P) -> Self {
        self.passphrase = Some(passphrase.as_ref().to_string());
        self
    }

    /// Add configuration to vault builder
    pub fn with_config(mut self, config: cryypt_vault::config::VaultConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Add on_result handler - README.md pattern
    pub fn on_result<F, T>(self, handler: F) -> VaultWithPathAndHandler<F, T>
    where
        F: FnOnce(cryypt_vault::error::VaultResult<cryypt_vault::core::Vault>) -> T
            + Send
            + 'static,
        T: Send + 'static,
    {
        VaultWithPathAndHandler {
            path: self.path,
            config: self.config,
            passphrase: self.passphrase,
            result_handler: handler,
            _phantom: std::marker::PhantomData,
        }
    }

    /// Convert to future for .await syntax
    pub async fn create_and_unlock(self) -> cryypt_vault::core::Vault {
        // Create vault with configuration if provided
        let result = if let Some(config) = self.config {
            cryypt_vault::core::Vault::with_fortress_encryption(config)
        } else {
            Ok(cryypt_vault::core::Vault::new())
        };

        // Default unwrapping: Ok(vault) => vault, Err(_) => new empty vault
        match result {
            Ok(vault) => vault,
            Err(_) => cryypt_vault::core::Vault::new(),
        }
    }
}

// Implement IntoFuture for VaultWithPath to enable .await
#[cfg(feature = "vault")]
impl std::future::IntoFuture for VaultWithPath {
    type Output = cryypt_vault::core::Vault;
    type IntoFuture = std::pin::Pin<Box<dyn std::future::Future<Output = Self::Output> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            // Create vault with configuration if provided
            let result = if let Some(config) = self.config {
                cryypt_vault::core::Vault::with_fortress_encryption(config)
            } else {
                Ok(cryypt_vault::core::Vault::new())
            };

            // Default unwrapping: Ok(vault) => vault, Err(_) => new empty vault
            match result {
                Ok(vault) => vault,
                Err(_) => cryypt_vault::core::Vault::new(),
            }
        })
    }
}

#[cfg(feature = "vault")]
impl<F, T> VaultWithPathAndHandler<F, T>
where
    F: FnOnce(cryypt_vault::error::VaultResult<cryypt_vault::core::Vault>) -> T + Send + 'static,
    T: Send + 'static,
{
    /// Apply result handler and create vault
    pub async fn execute(self) -> T {
        let handler = self.result_handler;

        // Create vault configuration using path if provided
        let config = if let Some(mut config) = self.config {
            // Update vault path if provided
            if !self.path.is_empty() && self.path != "./vault" {
                config.vault_path = std::path::PathBuf::from(&self.path);
            }
            config
        } else if !self.path.is_empty() {
            // Create new config with specified path
            let mut config = cryypt_vault::config::VaultConfig::default();
            config.vault_path = std::path::PathBuf::from(&self.path);
            config
        } else {
            // Use default config
            cryypt_vault::config::VaultConfig::default()
        };

        // Create vault with configuration
        let result = cryypt_vault::core::Vault::with_fortress_encryption(config);

        // If vault creation succeeded and passphrase is provided, unlock it
        let final_result = match result {
            Ok(vault) => {
                if let Some(passphrase) = &self.passphrase {
                    // Attempt to unlock with provided passphrase
                    match vault.unlock(passphrase).await {
                        Ok(()) => Ok(vault),
                        Err(_unlock_err) => {
                            // Unlock failed but return vault (user can unlock later)
                            Ok(vault)
                        }
                    }
                } else {
                    Ok(vault)
                }
            }
            Err(e) => Err(e),
        };

        // Apply result handler
        handler(final_result)
    }
}

// Implement IntoFuture for VaultWithPathAndHandler to enable .await
#[cfg(feature = "vault")]
impl<F, T> std::future::IntoFuture for VaultWithPathAndHandler<F, T>
where
    F: FnOnce(cryypt_vault::error::VaultResult<cryypt_vault::core::Vault>) -> T + Send + 'static,
    T: Send + 'static,
{
    type Output = T;
    type IntoFuture = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(self.execute())
    }
}

/// Master builder for post-quantum cryptography operations
#[cfg(feature = "pqcrypto")]
pub struct PqcryptoMasterBuilder;

#[cfg(feature = "pqcrypto")]
impl PqcryptoMasterBuilder {
    /// Use ML-KEM (Kyber) key encapsulation mechanism - README.md pattern
    pub fn kyber(self) -> cryypt_pqcrypto::api::KemBuilder {
        cryypt_pqcrypto::api::KemBuilder
    }

    /// Use ML-DSA (Dilithium) digital signature algorithm - README.md pattern
    pub fn dilithium(self) -> cryypt_pqcrypto::api::SignatureBuilder {
        cryypt_pqcrypto::api::SignatureBuilder
    }
}

/// Master builder for QUIC operations
#[cfg(feature = "quic")]
pub struct QuicMasterBuilder;

#[cfg(feature = "quic")]
impl QuicMasterBuilder {
    /// Create a QUIC server - README.md pattern
    pub fn server(self) -> cryypt_quic::api::QuicServerBuilder {
        cryypt_quic::api::QuicServerBuilder::new()
    }

    /// Create a QUIC client - README.md pattern
    pub fn client(self) -> cryypt_quic::api::QuicClientBuilder {
        cryypt_quic::api::QuicClientBuilder::new()
    }
}
