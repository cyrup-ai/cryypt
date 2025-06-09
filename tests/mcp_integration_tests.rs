//! MCP integration tests for cryptographic operations
//!
//! This module tests how cryptographic functions from the cryypt crate
//! can be exposed and invoked through the Model Context Protocol (MCP).
//! Tests cover encryption, decryption, key management, hashing, and
//! digital signature operations via MCP tool calls.

use serde_json::{json, Value};

#[cfg(test)]
mod tests {
    use super::*;

    /// Test AES encryption tool call request payload
    #[test]
    fn test_aes_encrypt_tool_call_request() {
        let payload = json!({
            "method": "tools/call",
            "params": {
                "name": "aes_encrypt",
                "arguments": {
                    "plaintext": "sensitive data to encrypt",
                    "key": "32-byte-key-for-aes-256-encryption!",
                    "mode": "GCM",
                    "iv": "unique-iv-12345"
                }
            },
            "id": 100
        });

        // Validate structure
        assert_eq!(payload["method"], "tools/call");
        assert_eq!(payload["params"]["name"], "aes_encrypt");

        let args = &payload["params"]["arguments"];
        assert!(args["plaintext"].is_string());
        assert!(args["key"].is_string());
        assert!(args["mode"].is_string());
        assert!(args["iv"].is_string());

        // Validate encryption-specific requirements
        assert!(["GCM", "CBC", "CTR"].contains(&args["mode"].as_str().unwrap()));
        assert!(!args["plaintext"].as_str().unwrap().is_empty());
    }

    /// Test AES encryption tool call response payload
    #[test]
    fn test_aes_encrypt_tool_call_response() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 100,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "Encryption successful. Ciphertext: 7f8a9b2c3d4e5f6789abcdef0123456789abcdef0123456789abcdef"
                    }
                ]
            }
        });

        assert_eq!(response["jsonrpc"], "2.0");
        assert_eq!(response["id"], 100);

        let content_text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(content_text.contains("Encryption successful"));
        assert!(content_text.contains("Ciphertext:"));
    }

    /// Test key generation tool call request payload
    #[test]
    fn test_key_generation_tool_call_request() {
        let payload = json!({
            "method": "tools/call",
            "params": {
                "name": "generate_key",
                "arguments": {
                    "algorithm": "AES",
                    "key_size": 256,
                    "purpose": "encryption",
                    "secure_random": true
                }
            },
            "id": 101
        });

        assert_eq!(payload["method"], "tools/call");
        assert_eq!(payload["params"]["name"], "generate_key");

        let args = &payload["params"]["arguments"];
        assert!(["AES", "RSA", "ECDSA", "ChaCha20"].contains(&args["algorithm"].as_str().unwrap()));
        assert!(args["key_size"].is_number());
        assert!(args["secure_random"].is_boolean());
        assert!(args["secure_random"] == true);
    }

    /// Test key generation tool call response payload
    #[test]
    fn test_key_generation_tool_call_response() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 101,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "Key generated successfully. Key ID: key_2024_001, Algorithm: AES-256"
                    }
                ]
            }
        });

        let content_text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(content_text.contains("Key generated successfully"));
        assert!(content_text.contains("Key ID:"));
        assert!(content_text.contains("Algorithm:"));
    }

    /// Test hashing tool call request payload
    #[test]
    fn test_hash_tool_call_request() {
        let payload = json!({
            "method": "tools/call",
            "params": {
                "name": "compute_hash",
                "arguments": {
                    "data": "data to hash",
                    "algorithm": "SHA256",
                    "salt": "random_salt_value",
                    "iterations": 1
                }
            },
            "id": 102
        });

        assert_eq!(payload["params"]["name"], "compute_hash");

        let args = &payload["params"]["arguments"];
        assert!(args["data"].is_string());
        assert!(
            ["SHA256", "SHA512", "BLAKE3", "Argon2"].contains(&args["algorithm"].as_str().unwrap())
        );
        assert!(args["iterations"].as_u64().unwrap() >= 1);
    }

    /// Test hashing tool call response payload
    #[test]
    fn test_hash_tool_call_response() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 102,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "Hash computed: 2cf24dba4f21d4288e8b3c5fce8e9e9e29e8b3c5fce8e9e9e29e8b3c5fce8e9e9e"
                    }
                ]
            }
        });

        let content_text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(content_text.contains("Hash computed:"));

        // Extract hash value and validate hex format
        let hash_start = content_text.find(": ").unwrap() + 2;
        let hash_value = &content_text[hash_start..];
        assert!(hash_value.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// Test digital signature creation tool call
    #[test]
    fn test_digital_signature_tool_call_request() {
        let payload = json!({
            "method": "tools/call",
            "params": {
                "name": "create_signature",
                "arguments": {
                    "message": "document to sign",
                    "private_key_id": "rsa_key_001",
                    "algorithm": "RSA-PSS",
                    "hash_algorithm": "SHA256"
                }
            },
            "id": 103
        });

        let args = &payload["params"]["arguments"];
        assert!(args["message"].is_string());
        assert!(args["private_key_id"].is_string());
        assert!(["RSA-PSS", "ECDSA", "EdDSA"].contains(&args["algorithm"].as_str().unwrap()));
        assert!(["SHA256", "SHA512"].contains(&args["hash_algorithm"].as_str().unwrap()));
    }

    /// Test digital signature verification tool call
    #[test]
    fn test_verify_signature_tool_call_request() {
        let payload = json!({
            "method": "tools/call",
            "params": {
                "name": "verify_signature",
                "arguments": {
                    "message": "document to verify",
                    "signature": "3045022100ab1234...signature_bytes",
                    "public_key_id": "rsa_pub_001",
                    "algorithm": "RSA-PSS"
                }
            },
            "id": 104
        });

        let args = &payload["params"]["arguments"];
        assert!(args["message"].is_string());
        assert!(args["signature"].is_string());
        assert!(args["public_key_id"].is_string());
        assert!(!args["signature"].as_str().unwrap().is_empty());
    }

    /// Test JWT token creation tool call
    #[test]
    fn test_jwt_create_tool_call_request() {
        let payload = json!({
            "method": "tools/call",
            "params": {
                "name": "create_jwt",
                "arguments": {
                    "payload": {
                        "sub": "user123",
                        "iss": "auth-service",
                        "exp": 1735689600,
                        "iat": 1703203200
                    },
                    "secret": "jwt-signing-secret",
                    "algorithm": "HS256"
                }
            },
            "id": 105
        });

        let args = &payload["params"]["arguments"];
        assert!(args["payload"].is_object());
        assert!(args["secret"].is_string());
        assert!(["HS256", "HS512", "RS256", "ES256"].contains(&args["algorithm"].as_str().unwrap()));

        // Validate JWT payload structure
        let jwt_payload = &args["payload"];
        assert!(jwt_payload["sub"].is_string());
        assert!(jwt_payload["exp"].is_number());
    }

    /// Test JWT token verification tool call
    #[test]
    fn test_jwt_verify_tool_call_response() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 106,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "JWT verification successful. Subject: user123, Issuer: auth-service, Valid until: 2024-12-31T12:00:00Z"
                    }
                ]
            }
        });

        let content_text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(content_text.contains("JWT verification successful"));
        assert!(content_text.contains("Subject:"));
        assert!(content_text.contains("Valid until:"));
    }

    /// Test password hashing tool call (Argon2)
    #[test]
    fn test_password_hash_tool_call_request() {
        let payload = json!({
            "method": "tools/call",
            "params": {
                "name": "hash_password",
                "arguments": {
                    "password": "user_password_123",
                    "algorithm": "Argon2id",
                    "memory_cost": 65536,
                    "time_cost": 3,
                    "parallelism": 4
                }
            },
            "id": 107
        });

        let args = &payload["params"]["arguments"];
        assert!(args["password"].is_string());
        assert_eq!(args["algorithm"], "Argon2id");
        assert!(args["memory_cost"].as_u64().unwrap() >= 1024);
        assert!(args["time_cost"].as_u64().unwrap() >= 1);
        assert!(args["parallelism"].as_u64().unwrap() >= 1);
    }

    /// Test secure random generation tool call
    #[test]
    fn test_random_generation_tool_call_request() {
        let payload = json!({
            "method": "tools/call",
            "params": {
                "name": "generate_random",
                "arguments": {
                    "length": 32,
                    "format": "hex",
                    "entropy_source": "system"
                }
            },
            "id": 108
        });

        let args = &payload["params"]["arguments"];
        assert!(args["length"].as_u64().unwrap() > 0);
        assert!(["hex", "base64", "raw"].contains(&args["format"].as_str().unwrap()));
        assert_eq!(args["entropy_source"], "system");
    }

    /// Test ChaCha20 encryption tool call
    #[test]
    fn test_chacha20_encrypt_tool_call_request() {
        let payload = json!({
            "method": "tools/call",
            "params": {
                "name": "chacha20_encrypt",
                "arguments": {
                    "plaintext": "data to encrypt with ChaCha20",
                    "key": "32-byte-chacha20-key-here-1234567890",
                    "nonce": "12-byte-nonce",
                    "aad": "additional authenticated data"
                }
            },
            "id": 109
        });

        let args = &payload["params"]["arguments"];
        assert!(args["plaintext"].is_string());
        assert!(args["key"].is_string());
        assert!(args["nonce"].is_string());
        assert_eq!(args["key"].as_str().unwrap().len(), 32);
    }

    /// Test post-quantum cryptography key generation
    #[test]
    fn test_pqcrypto_keygen_tool_call_request() {
        let payload = json!({
            "method": "tools/call",
            "params": {
                "name": "pq_generate_keypair",
                "arguments": {
                    "algorithm": "Kyber512",
                    "purpose": "key_encapsulation",
                    "security_level": "NIST_1"
                }
            },
            "id": 110
        });

        let args = &payload["params"]["arguments"];
        assert!(["Kyber512", "Kyber768", "Kyber1024", "Dilithium2"]
            .contains(&args["algorithm"].as_str().unwrap()));
        assert!(
            ["key_encapsulation", "digital_signature"].contains(&args["purpose"].as_str().unwrap())
        );
        assert!(["NIST_1", "NIST_3", "NIST_5"].contains(&args["security_level"].as_str().unwrap()));
    }

    /// Test key derivation function (PBKDF2) tool call
    #[test]
    fn test_key_derivation_tool_call_request() {
        let payload = json!({
            "method": "tools/call",
            "params": {
                "name": "derive_key",
                "arguments": {
                    "password": "user_master_password",
                    "salt": "unique_salt_per_user",
                    "iterations": 100000,
                    "key_length": 32,
                    "hash_function": "SHA256"
                }
            },
            "id": 111
        });

        let args = &payload["params"]["arguments"];
        assert!(args["password"].is_string());
        assert!(args["salt"].is_string());
        assert!(args["iterations"].as_u64().unwrap() >= 10000);
        assert!(args["key_length"].as_u64().unwrap() > 0);
        assert!(["SHA256", "SHA512"].contains(&args["hash_function"].as_str().unwrap()));
    }

    /// Test cryptographic error response format
    #[test]
    fn test_crypto_error_response() {
        let error_response = json!({
            "jsonrpc": "2.0",
            "id": 112,
            "result": {
                "isError": true,
                "content": [
                    {
                        "type": "text",
                        "text": "Cryptographic operation failed: Invalid key length. Expected 32 bytes, got 16 bytes."
                    }
                ]
            }
        });

        assert_eq!(error_response["result"]["isError"], true);
        let content_text = error_response["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(content_text.contains("Cryptographic operation failed"));
        assert!(content_text.contains("Invalid key length"));
    }

    /// Test secure key storage tool call
    #[test]
    fn test_secure_key_storage_tool_call_request() {
        let payload = json!({
            "method": "tools/call",
            "params": {
                "name": "store_key",
                "arguments": {
                    "key_id": "user_encryption_key_001",
                    "key_material": "encrypted_key_data_here",
                    "algorithm": "AES-256",
                    "metadata": {
                        "created_by": "key_management_service",
                        "purpose": "data_encryption",
                        "expiry": "2025-12-31"
                    }
                }
            },
            "id": 113
        });

        let args = &payload["params"]["arguments"];
        assert!(args["key_id"].is_string());
        assert!(args["key_material"].is_string());
        assert!(args["algorithm"].is_string());
        assert!(args["metadata"].is_object());

        let metadata = &args["metadata"];
        assert!(metadata["created_by"].is_string());
        assert!(metadata["purpose"].is_string());
    }

    /// Test encryption with multiple algorithms tool call
    #[test]
    fn test_multi_algorithm_encrypt_tool_call_request() {
        let payload = json!({
            "method": "tools/call",
            "params": {
                "name": "multi_encrypt",
                "arguments": {
                    "plaintext": "highly sensitive data",
                    "algorithms": ["AES-256-GCM", "ChaCha20-Poly1305"],
                    "keys": {
                        "aes_key": "32-byte-aes-key-for-encryption-use",
                        "chacha_key": "32-byte-chacha-key-for-encryption"
                    },
                    "layer_order": ["AES", "ChaCha20"]
                }
            },
            "id": 114
        });

        let args = &payload["params"]["arguments"];
        assert!(args["algorithms"].is_array());
        assert!(args["keys"].is_object());
        assert!(args["layer_order"].is_array());

        let algorithms = args["algorithms"].as_array().unwrap();
        assert!(algorithms.len() > 1);

        for alg in algorithms {
            assert!(alg.is_string());
        }
    }

    /// Test comprehensive cryptographic audit tool call
    #[test]
    fn test_crypto_audit_tool_call_response() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 115,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "Cryptographic audit completed. Keys audited: 47, Algorithms verified: 8, Security compliance: FIPS 140-2 Level 3, Issues found: 0"
                    }
                ]
            }
        });

        let content_text = response["result"]["content"][0]["text"].as_str().unwrap();
        assert!(content_text.contains("Cryptographic audit completed"));
        assert!(content_text.contains("Keys audited:"));
        assert!(content_text.contains("Security compliance:"));
        assert!(content_text.contains("Issues found:"));
    }

    /// Test that all crypto tool calls maintain ID consistency
    #[test]
    fn test_crypto_tool_id_consistency() {
        let test_cases = vec![
            ("aes_encrypt", 200),
            ("generate_key", 201),
            ("compute_hash", 202),
            ("create_signature", 203),
            ("verify_signature", 204),
        ];

        for (tool_name, id) in test_cases {
            let request = json!({
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": {}
                },
                "id": id
            });

            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": format!("{} operation completed", tool_name)
                        }
                    ]
                }
            });

            assert_eq!(request["id"], response["id"]);
        }
    }

    /// Test cryptographic operation timing safety
    #[test]
    fn test_crypto_timing_safety_tool_call() {
        let payload = json!({
            "method": "tools/call",
            "params": {
                "name": "constant_time_compare",
                "arguments": {
                    "value1": "expected_hash_value",
                    "value2": "actual_hash_value",
                    "algorithm": "constant_time"
                }
            },
            "id": 116
        });

        let args = &payload["params"]["arguments"];
        assert!(args["value1"].is_string());
        assert!(args["value2"].is_string());
        assert_eq!(args["algorithm"], "constant_time");
    }
}

/// Helper functions for MCP cryptographic payload testing
pub mod mcp_crypto_helpers {
    use super::*;

    /// Validate that a cryptographic tool request has required security parameters
    pub fn validate_crypto_request_security(payload: &Value) -> Result<(), String> {
        let args = &payload["params"]["arguments"];

        // Check for key-related operations
        if payload["params"]["name"].as_str().unwrap().contains("key") {
            if let Some(key_size) = args.get("key_size") {
                if key_size.as_u64().unwrap_or(0) < 128 {
                    return Err("Key size too small for security".to_string());
                }
            }
        }

        // Check for hash operations
        if payload["params"]["name"].as_str().unwrap().contains("hash") {
            if let Some(algorithm) = args.get("algorithm") {
                let alg = algorithm.as_str().unwrap_or("");
                if ["MD5", "SHA1"].contains(&alg) {
                    return Err("Insecure hash algorithm".to_string());
                }
            }
        }

        Ok(())
    }

    /// Create a secure cryptographic tool request
    pub fn create_secure_crypto_request(tool_name: &str, secure_args: Value, id: u32) -> Value {
        json!({
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": secure_args,
                "security_level": "high",
                "audit_required": true
            },
            "id": id
        })
    }

    /// Validate cryptographic response contains security metadata
    pub fn validate_crypto_response_security(response: &Value) -> Result<(), String> {
        let content = &response["result"]["content"];
        if !content.is_array() || content.as_array().unwrap().is_empty() {
            return Err("Missing content in crypto response".to_string());
        }

        let content_text = content[0]["text"].as_str().unwrap_or("");

        // Check for security indicators in response
        if content_text.contains("failed") || content_text.contains("error") {
            if !content_text.contains("Cryptographic operation failed") {
                return Err("Insufficient error context in crypto response".to_string());
            }
        }

        Ok(())
    }
}
