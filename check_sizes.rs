use pqcrypto_dilithium::dilithium2;
use pqcrypto_traits::sign::{PublicKey, SecretKey};

fn main() {
    let (pk, sk) = dilithium2::keypair();
    println!("ML-DSA-44 (Dilithium2) key sizes:");
    println!("  Public key: {} bytes", pk.as_bytes().len());
    println!("  Secret key: {} bytes", sk.as_bytes().len());
}
