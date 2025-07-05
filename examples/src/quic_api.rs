//! QUIC API examples - EXACTLY matching quic/README.md

use cryypt::{Cryypt, on_result};

/// QUIC Server and Client example from README
async fn quic_example() -> Result<(), Box<dyn std::error::Error>> {
    // Note: In a real application, you would load real certificates
    let cert = b"fake certificate for example";
    let private_key = b"fake private key for example";
    
    // QUIC server
    let server = Cryypt::quic()
        .server()
        .with_cert(cert)
        .with_key(private_key)
        .on_connection!(|conn| {
            Ok => {
                tokio::spawn(handle_connection(conn));
                Ok(())
            },
            Err(e) => Err(e)
        })
        .bind("127.0.0.1:4433")
        .await; // Returns fully unwrapped value - no Result wrapper

    // QUIC client
    let client = Cryypt::quic()
        .client()
        .with_server_name("example.com")
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .connect("127.0.0.1:4433")
        .await; // Returns fully unwrapped value - no Result wrapper

    // Open bidirectional stream
    let (send, recv) = client
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .open_bi()
        .await; // Returns fully unwrapped value - no Result wrapper

    // Send data
    send
        .on_result!(|result| {
            result.unwrap_or_else(|e| panic!("Operation error: {}", e))
        })
        .write_all(b"Hello QUIC")
        .await; // Returns fully unwrapped value - no Result wrapper

    // Receive streamed data
    let mut data = Vec::new();
    let mut recv_stream = recv
        .on_chunk!(|chunk| {
            Ok => chunk,
            Err(e) => {
                log::error!("Receive error: {}", e);
                return;
            }
        })
        .stream();

    while let Some(chunk) = recv_stream.next().await {
        data.extend_from_slice(&chunk);
    }

    println!("Received: {:?}", String::from_utf8(data)?);
    Ok(())
}

/// Example connection handler
async fn handle_connection(conn: QuicConnection) {
    // Handle incoming streams
    while let Ok((send, recv)) = conn.accept_bi().await {
        tokio::spawn(async move {
            // Echo server - read and write back
            let mut data = Vec::new();
            let mut recv_stream = recv
                .on_chunk!(|chunk| {
                    Ok => chunk,
                    Err(e) => {
                        log::error!("Receive error: {}", e);
                        return;
                    }
                })
                .stream();

            while let Some(chunk) = recv_stream.next().await {
                data.extend_from_slice(&chunk);
            }

            // Echo back
            send
                .on_result!(|result| {
                    result.unwrap_or_else(|e| panic!("Send error: {}", e))
                })
                .write_all(&data)
                .await;
        });
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== QUIC Server and Client ===");
    // Note: This is a conceptual example. In practice, you'd run server and client
    // in separate processes or threads
    
    println!("QUIC example would run here with proper certificates");
    
    Ok(())
}