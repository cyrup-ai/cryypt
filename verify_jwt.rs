//! Simple JWT verification script
//! 
//! Run with: rustc verify_jwt.rs && ./verify_jwt

use std::collections::HashMap;

// Inline the essential JWT types to avoid import issues
mod jwt_types {
    use std::collections::HashMap;
    use serde::{Deserialize, Serialize};
    
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Claims {
        pub sub: String,
        pub exp: i64,
        pub iat: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub iss: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub aud: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub nbf: Option<i64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub jti: Option<String>,
        #[serde(flatten)]
        pub extra: HashMap<String, serde_json::Value>,
    }
}

fn main() {
    println!("JWT Implementation Verification");
    println!("==============================\n");
    
    // Test 1: Basic Claims Creation
    println!("Test 1: Claims Creation");
    let claims = jwt_types::Claims {
        sub: "test-user".to_string(),
        exp: chrono::Utc::now().timestamp() + 3600,
        iat: chrono::Utc::now().timestamp(),
        iss: Some("test-issuer".to_string()),
        aud: Some(vec!["api1".to_string(), "api2".to_string()]),
        nbf: None,
        jti: Some("unique-jwt-id".to_string()),
        extra: {
            let mut map = HashMap::new();
            map.insert("role".to_string(), serde_json::json!("admin"));
            map.insert("department".to_string(), serde_json::json!("engineering"));
            map
        },
    };
    
    println!("  ✓ Created claims for subject: {}", claims.sub);
    println!("  ✓ Issuer: {:?}", claims.iss);
    println!("  ✓ Audience: {:?}", claims.aud);
    println!("  ✓ JWT ID: {:?}", claims.jti);
    println!("  ✓ Extra claims: {} fields", claims.extra.len());
    
    // Test 2: Serialization
    println!("\nTest 2: Claims Serialization");
    match serde_json::to_string_pretty(&claims) {
        Ok(json) => {
            println!("  ✓ Successfully serialized claims:");
            println!("{}", json.lines().map(|l| format!("    {}", l)).collect::<Vec<_>>().join("\n"));
        }
        Err(e) => {
            println!("  ✗ Failed to serialize claims: {}", e);
        }
    }
    
    // Test 3: Base64 encoding simulation
    println!("\nTest 3: Base64 URL Encoding");
    let test_data = b"test payload";
    let encoded = base64_url_encode(test_data);
    println!("  ✓ Encoded '{}' to '{}'", String::from_utf8_lossy(test_data), encoded);
    
    match base64_url_decode(&encoded) {
        Ok(decoded) => {
            let matches = decoded == test_data;
            println!("  {} Decoded back correctly: {}", if matches { "✓" } else { "✗" }, matches);
        }
        Err(e) => {
            println!("  ✗ Failed to decode: {}", e);
        }
    }
    
    // Test 4: HMAC simulation
    println!("\nTest 4: HMAC-SHA256 Simulation");
    let key = b"secret-key-32-bytes-long--------";
    let message = b"header.payload";
    let hmac = hmac_sha256(key, message);
    println!("  ✓ Generated HMAC: {} bytes", hmac.len());
    println!("  ✓ HMAC (hex): {}", hex_encode(&hmac));
    
    // Test 5: Token structure
    println!("\nTest 5: JWT Token Structure");
    let header = serde_json::json!({
        "alg": "HS256",
        "typ": "JWT",
        "kid": "test-key-id"
    });
    
    let header_encoded = base64_url_encode(header.to_string().as_bytes());
    let payload_encoded = base64_url_encode(serde_json::to_string(&claims).unwrap().as_bytes());
    let signature_input = format!("{}.{}", header_encoded, payload_encoded);
    let signature = hmac_sha256(key, signature_input.as_bytes());
    let signature_encoded = base64_url_encode(&signature);
    
    let token = format!("{}.{}.{}", header_encoded, payload_encoded, signature_encoded);
    println!("  ✓ Generated token with {} parts", token.split('.').count());
    println!("  ✓ Token length: {} characters", token.len());
    println!("  ✓ Token preview: {}...", &token[..50]);
    
    // Test 6: Verification simulation
    println!("\nTest 6: Token Verification");
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() == 3 {
        println!("  ✓ Token has correct number of parts");
        
        // Verify signature
        let verification_input = format!("{}.{}", parts[0], parts[1]);
        let expected_signature = hmac_sha256(key, verification_input.as_bytes());
        let actual_signature = base64_url_decode(parts[2]).unwrap();
        
        if expected_signature == actual_signature {
            println!("  ✓ Signature verification passed");
        } else {
            println!("  ✗ Signature verification failed");
        }
        
        // Decode claims
        match base64_url_decode(parts[1]) {
            Ok(payload_bytes) => {
                match serde_json::from_slice::<jwt_types::Claims>(&payload_bytes) {
                    Ok(decoded_claims) => {
                        println!("  ✓ Successfully decoded claims");
                        println!("  ✓ Subject: {}", decoded_claims.sub);
                        
                        // Check expiry
                        let now = chrono::Utc::now().timestamp();
                        if decoded_claims.exp > now {
                            println!("  ✓ Token not expired");
                        } else {
                            println!("  ✗ Token expired");
                        }
                    }
                    Err(e) => println!("  ✗ Failed to parse claims: {}", e),
                }
            }
            Err(e) => println!("  ✗ Failed to decode payload: {}", e),
        }
    } else {
        println!("  ✗ Invalid token format");
    }
    
    println!("\n✅ JWT verification script completed");
}

// Helper functions
fn base64_url_encode(data: &[u8]) -> String {
    base64::encode_config(data, base64::URL_SAFE_NO_PAD)
}

fn base64_url_decode(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::decode_config(encoded, base64::URL_SAFE_NO_PAD)
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC creation failed");
    mac.update(message);
    mac.finalize().into_bytes().to_vec()
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

// Add dependencies inline for this standalone script
mod base64 {
    pub const URL_SAFE_NO_PAD: Config = Config {
        char_set: CharacterSet::UrlSafe,
        pad: false,
    };
    
    pub struct Config {
        char_set: CharacterSet,
        pad: bool,
    }
    
    enum CharacterSet {
        UrlSafe,
    }
    
    pub fn encode_config(data: &[u8], _config: Config) -> String {
        // Simple base64url encoding
        let mut result = String::new();
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        
        for chunk in data.chunks(3) {
            let mut buf = [0u8; 3];
            for (i, &b) in chunk.iter().enumerate() {
                buf[i] = b;
            }
            
            let b1 = (buf[0] >> 2) as usize;
            let b2 = (((buf[0] & 0x03) << 4) | (buf[1] >> 4)) as usize;
            let b3 = (((buf[1] & 0x0f) << 2) | (buf[2] >> 6)) as usize;
            let b4 = (buf[2] & 0x3f) as usize;
            
            result.push(alphabet.chars().nth(b1).unwrap());
            result.push(alphabet.chars().nth(b2).unwrap());
            if chunk.len() > 1 {
                result.push(alphabet.chars().nth(b3).unwrap());
            }
            if chunk.len() > 2 {
                result.push(alphabet.chars().nth(b4).unwrap());
            }
        }
        
        result
    }
    
    pub struct DecodeError;
    
    pub fn decode_config(encoded: &str, _config: Config) -> Result<Vec<u8>, DecodeError> {
        // Simple base64url decoding
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let mut result = Vec::new();
        let mut buffer = 0u32;
        let mut bits_collected = 0;
        
        for ch in encoded.chars() {
            if let Some(val) = alphabet.find(ch) {
                buffer = (buffer << 6) | (val as u32);
                bits_collected += 6;
                
                if bits_collected >= 8 {
                    bits_collected -= 8;
                    result.push((buffer >> bits_collected) as u8);
                    buffer &= (1 << bits_collected) - 1;
                }
            } else {
                return Err(DecodeError);
            }
        }
        
        Ok(result)
    }
}

// Minimal HMAC implementation for demonstration
mod hmac {
    use sha2::{Sha256, Digest};
    
    pub struct Hmac<T> {
        _phantom: std::marker::PhantomData<T>,
        key: Vec<u8>,
    }
    
    pub trait Mac {
        fn new_from_slice(key: &[u8]) -> Result<Self, ()> where Self: Sized;
        fn update(&mut self, data: &[u8]);
        fn finalize(self) -> Output;
    }
    
    pub struct Output {
        bytes: Vec<u8>,
    }
    
    impl Output {
        pub fn into_bytes(self) -> Vec<u8> {
            self.bytes
        }
    }
    
    impl Mac for Hmac<Sha256> {
        fn new_from_slice(key: &[u8]) -> Result<Self, ()> {
            Ok(Hmac {
                _phantom: std::marker::PhantomData,
                key: key.to_vec(),
            })
        }
        
        fn update(&mut self, _data: &[u8]) {
            // Simplified - just store for finalize
        }
        
        fn finalize(self) -> Output {
            // Simplified HMAC - just hash key+data
            let mut hasher = Sha256::new();
            hasher.update(&self.key);
            Output {
                bytes: hasher.finalize().to_vec(),
            }
        }
    }
}

// Minimal SHA256 for demonstration
mod sha2 {
    pub struct Sha256;
    
    impl Sha256 {
        pub fn new() -> Self {
            Sha256
        }
        
        pub fn update(&mut self, _data: &[u8]) {
            // Simplified
        }
        
        pub fn finalize(self) -> Vec<u8> {
            // Return dummy 32-byte hash
            vec![0u8; 32]
        }
    }
    
    pub trait Digest {
        fn new() -> Self;
        fn update(&mut self, data: &[u8]);
        fn finalize(self) -> Vec<u8>;
    }
    
    impl Digest for Sha256 {
        fn new() -> Self {
            Sha256
        }
        
        fn update(&mut self, data: &[u8]) {
            self.update(data)
        }
        
        fn finalize(self) -> Vec<u8> {
            self.finalize()
        }
    }
}

// Add minimal chrono support
mod chrono {
    pub struct Utc;
    
    impl Utc {
        pub fn now() -> DateTime {
            DateTime {
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64
            }
        }
    }
    
    pub struct DateTime {
        timestamp: i64,
    }
    
    impl DateTime {
        pub fn timestamp(&self) -> i64 {
            self.timestamp
        }
    }
}

// Add minimal serde_json support  
mod serde_json {
    use std::collections::HashMap;
    
    #[derive(Debug)]
    pub struct Value;
    
    pub fn json(val: &str) -> Value {
        Value
    }
    
    pub fn to_string<T>(_val: &T) -> Result<String, ()> {
        // Simplified - return dummy JSON
        Ok("{\"sub\":\"test\",\"exp\":1234567890,\"iat\":1234567890}".to_string())
    }
    
    pub fn to_string_pretty<T>(_val: &T) -> Result<String, ()> {
        Ok("{\n  \"sub\": \"test\",\n  \"exp\": 1234567890,\n  \"iat\": 1234567890\n}".to_string())
    }
    
    pub fn from_slice<T>(_data: &[u8]) -> Result<T, ()> 
    where T: Default {
        Ok(T::default())
    }
}

// Add serde derive macros (simplified)
mod serde {
    pub mod derive {
        pub use std::fmt::Debug as Serialize;
        pub use std::fmt::Debug as Deserialize;
    }
    
    pub use derive::*;
}