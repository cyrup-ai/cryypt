//! JWT algorithms following README.md patterns

// Re-export types for compatibility
pub use crate::types::Es256KeyPair;

/// Generate a new ES256 key pair for JWT signing
pub fn generate_es256_keypair() -> Es256KeyPair {
    // Generate a P-256 key pair (placeholder implementation)
    let private_key = vec![0u8; 32]; // 32-byte private key
    let public_key = vec![0u8; 64];  // 64-byte uncompressed public key
    
    Es256KeyPair {
        private_key,
        public_key,
    }
}

/// Validate an ES256 key pair
pub fn validate_es256_keypair(keypair: &Es256KeyPair) -> bool {
    keypair.private_key.len() == 32 && keypair.public_key.len() == 64
}