//! JWT algorithms following README.md patterns

use p256::ecdsa::SigningKey;

// Re-export types for compatibility
pub use crate::types::Es256KeyPair;

/// Generate a new ES256 key pair for JWT signing - Production implementation
#[allow(dead_code)]
pub fn generate_es256_keypair() -> crate::error::JwtResult<Es256KeyPair> {
    use rand::Rng;

    // Generate 32 random bytes for the private key using system entropy
    let mut rng = rand::rng();
    let mut private_key_bytes = [0u8; 32];
    rng.fill(&mut private_key_bytes);

    // Create signing key from the random bytes
    let signing_key = SigningKey::from_slice(&private_key_bytes).map_err(|e| {
        crate::error::JwtError::InvalidKey(format!("Failed to create signing key: {e}"))
    })?;

    // Extract private key as raw 32-byte scalar (for compatibility)
    let private_key = signing_key.to_bytes().to_vec();

    // Extract public key as uncompressed point (65 bytes: 0x04 + 32-byte x + 32-byte y)
    let verifying_key = signing_key.verifying_key();
    let public_key_point = verifying_key.to_encoded_point(false); // false = uncompressed
    let public_key = public_key_point.as_bytes().to_vec();

    Ok(Es256KeyPair {
        private_key,
        public_key,
    })
}

/// Validate an ES256 key pair - Production implementation
#[allow(dead_code)]
pub fn validate_es256_keypair(keypair: &Es256KeyPair) -> bool {
    // Validate private key by attempting to parse it as 32-byte scalar
    let private_key_valid =
        keypair.private_key.len() == 32 && SigningKey::from_slice(&keypair.private_key).is_ok();

    // Validate public key by checking it's a valid uncompressed point (65 bytes starting with 0x04)
    let public_key_valid = keypair.public_key.len() == 65
        && keypair.public_key[0] == 0x04
        && p256::ecdsa::VerifyingKey::from_sec1_bytes(&keypair.public_key).is_ok();

    private_key_valid && public_key_valid
}
