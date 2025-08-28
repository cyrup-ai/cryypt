//! JWT algorithms following README.md patterns

// Re-export types for compatibility
pub use crate::types::Es256KeyPair;

/// Generate a new ES256 key pair for JWT signing
#[allow(dead_code)]
pub fn generate_es256_keypair() -> Es256KeyPair {
    use p256::ecdsa::SigningKey;
    use p256::elliptic_curve::rand_core::OsRng;

    // Generate a proper P-256 key pair
    let signing_key = SigningKey::random(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    // Extract private key (32 bytes)
    let private_key = signing_key.to_bytes().to_vec();

    // Extract public key in SEC1 uncompressed format (65 bytes: 0x04 + 32 + 32)
    let public_key = verifying_key.to_encoded_point(false).as_bytes().to_vec();

    Es256KeyPair {
        private_key,
        public_key,
    }
}

/// Validate an ES256 key pair
#[allow(dead_code)]
pub fn validate_es256_keypair(keypair: &Es256KeyPair) -> bool {
    keypair.private_key.len() == 32 && keypair.public_key.len() == 64
}
