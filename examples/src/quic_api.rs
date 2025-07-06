//! QUIC API example showing the cryypt patterns

use cryypt_quic::{quic, Quic, QuicSend, QuicRecv};
use futures::StreamExt;

/// QUIC Server and Client example from README
async fn quic_example() {
    // Example certificate and key (in real app, load from files)
    let cert = b"-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKHHIgKwErQAMA0GCSqGSIb3DQEBCwUAMBYxFDASBgNVBAMMC2V4
YW1wbGUuY29tMB4XDTE5MDEwMTAwMDAwMFoXDTI5MDEwMTAwMDAwMFowFjEUMBIG
A1UEAwwLZXhhbXBsZS5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMCW
UUm3wKbP0Fl2TQoHiYTPBLJVCUwE2n9fO3fN4WoHvj0DRKLBQlX9RhyRcmAGp1HU
Z7FruOg1c5mVN7B0K3A5pUZhiF4LcDaUCCWrY1vidAr6V0hUdJf1PsYcPWxa5Blp
qXk8qqYZEeCZKVGnQiRaQWZYABH+jF5NdAHKb2lzAgMBAAEwDQYJKoZIhvcNAQEL
BQADgYEAdm0KOmCCVQhR3MwkF7kO5VcGkrt1f8q0lYGW5qBtSXaJXTJdKjLY8Jfv
2FMVPmCwp8/bNsqyqC3bPtw7xqFyKVruUMD+NFgyS0VuON7xI7vPbR2g4tdQhhaB
3q3PITpMlpWyHZ3PpGfHCnLMXGRnFCgdK9Y+3lhPRIp1hQxAMBU=
-----END CERTIFICATE-----".to_vec();
    
    let private_key = b"-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQDAllFJt8Cmz9BZdk0KB4mEzwSyVQlMBNp/Xzt3zeFqB749A0Si
wUJV/UYckXJgBqdR1Gexa7joNXOZlTewdCtwOaVGYYheC3A2lAglq2Nb4nQK+ldI
VHSX9T7GHD1sWuQZaal5PKqmGRHgmSlRp0IkWkFmWAAR/oxeTXQBym9pcwIDAQAB
AoGAa6OYLKp3xJVrEw3KF6ynLDI65w+0aHVuqA2LqvNnTNBNyQfgPGnKc0CdFatA
VpBXwEC7D+qJxPWEoIl5vVvl0tISdXF1X0DCmVqFtBVlZ7+4v+vN5Aw8FRIbZC8I
bqPKPnPbO7xbElWNbCeKlkRHdQvCkEqB+0nEEJsU3EECQQD0p3OqiA0T7O1B7Us8
EvF9UN7Zy3vnzE/WznNXM3Typob8Bgg6pDEcPWN0GD2ti7LTKkxFYlIw1U4pUwnE
s4SzAkEAySEeTXHxGXFODMPQDt2ls9E8cNXrY1YFJd6KFfihf8V7jVYFlYTvK5se
8NYSS9ShdbkHWqJJ95qYdLEG0BToYQJBAI06eKGa3JOQVV6FWrLPOvWKRW7UGr1I
ZGlC6UPYwJaA7LdEKNgHNmqFKYCJlmF6s8alm9rXEqmKVAT0MYr1j20CQFhP1h0y
P1mkw8nJYjm1A0CqvdGj1hCYy7aiab2F8QB3dm0Zt2t3HSNT7U3N3QLhcJLigVbE
luHrOQKlVEXneIECQGXxM3hZx6EVLLPNdNNnCPPbBJQvhO3PAhGFKf1YtV4qgKrx
sMMWTh1/tBxWis1L9SdQTnn4kZHvUyfzIQ9YCXM=
-----END RSA PRIVATE KEY-----".to_vec();

    // QUIC server with retry on different port
    let mut port = 4433;
    let server = loop {
        let result = Quic::server()
            .with_cert(cert.clone())
            .with_key(private_key.clone())
            .on_result(|result| result)
            .bind(format!("127.0.0.1:{}", port))
            .await;
        
        match result {
            Ok(server) => {
                println!("✅ Server bound successfully on port {}", port);
                break server;
            }
            Err(e) => {
                log::error!("Server bind failed on port {}: {}", port, e);
                port += 1;
                if port > 4440 {
                    log::error!("Failed to bind to any port 4433-4440");
                    break Quic::server(); // Return unbound server
                }
            }
        }
    };

    // Give server time to start
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // QUIC client using direct entry point
    let client = quic()
        .client()
        .with_server_name("example.com")
        .on_result(|result| {
            match result {
                Ok(client) => {
                    println!("✅ Client connected successfully");
                    client
                }
                Err(e) => {
                    log::error!("Connection failed: {}", e);
                    cryypt_quic::QuicClient::new() // Return unconnected client
                }
            }
        })
        .connect("127.0.0.1:4433")
        .await;

    // Open bidirectional stream
    let (send, recv) = client
        .on_result(|result| {
            match result {
                Ok(streams) => {
                    println!("✅ Bidirectional stream opened");
                    streams
                }
                Err(e) => {
                    log::error!("Failed to open stream: {}", e);
                    (QuicSend::new(), QuicRecv::new()) // Empty streams
                }
            }
        })
        .open_bi()
        .await;

    // Send data
    send
        .on_result(|result| {
            match result {
                Ok(()) => {
                    println!("✅ Data sent successfully");
                }
                Err(e) => {
                    log::error!("Failed to send data: {}", e);
                }
            }
        })
        .write_all(b"Hello QUIC")
        .await;

    // Receive streamed data
    let mut data = Vec::new();
    let mut recv_stream = recv
        .on_chunk(|chunk| {
            match chunk {
                Ok(data) => {
                    println!("📦 Received chunk: {} bytes", data.len());
                    Some(data)
                }
                Err(e) => {
                    log::error!("Receive error: {}", e);
                    None
                }
            }
        })
        .stream();

    // Collect a few chunks (in real app this would be a full protocol)
    let mut chunk_count = 0;
    while let Some(chunk) = recv_stream.next().await {
        data.extend_from_slice(&chunk);
        chunk_count += 1;
        
        // For demo, just collect 3 chunks then stop
        if chunk_count >= 3 {
            break;
        }
    }
    
    println!("\n📊 Total data received: {} bytes", data.len());
    if !data.is_empty() {
        println!("📝 Data content: {:?}", String::from_utf8_lossy(&data));
    }
    
    let _ = server; // Keep server alive for demo
}


#[tokio::main]
async fn main() {
    println!("=== QUIC API Example (cryypt patterns) ===");
    println!("Starting QUIC example with cryypt patterns...\n");
    
    quic_example().await;
}