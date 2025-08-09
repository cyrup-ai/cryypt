use cryypt::{Cryypt, QuicClient, QuicRecv, QuicSend, QuicServer, BadChunk};
use futures::stream::StreamExt;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Dummy certificate and private key for QUIC server
    let cert = b"dummy_cert".to_vec();
    let private_key = b"dummy_key".to_vec();
    let port = 4433;

    // QUIC server
    let server = Cryypt::quic()
        .server()
        .with_cert(cert.clone())
        .with_key(private_key.clone())
        .on_result(|result| {
            Ok(result) => result.into(),
            Err(_e) => {
                log::error!("QUIC server bind error");
                QuicServer::new()
            }
        })
        .bind(format!("127.0.0.1:{}", port))
        .await;

    // Simulate server running (in a real app, you'd spawn a task)
    println!("QUIC server bound to: 127.0.0.1:{}", port);
    println!("Server ready: {}", server.is_bound());

    // QUIC client
    let client = Cryypt::quic()
        .client()
        .with_server_name("example.com")
        .on_result(|result| {
            Ok(result) => result.into(),
            Err(_e) => {
                log::error!("Connection failed");
                QuicClient::new()
            }
        })
        .connect("127.0.0.1:4433")
        .await;

    // Open bidirectional stream
    let (send, recv) = client
        .on_result(|result| {
            Ok(result) => result.into(),
            Err(_e) => {
                log::error!("Failed to open stream");
                (QuicSend::new(), QuicRecv::new())
            }
        })
        .open_bi()
        .await;

    // Send data
    send.on_result(|result| {
        result.map(|result| result.into()).unwrap_or_else(|_e| {
            log::error!("Failed to send data");
            ()
        })
    })
    .write_all(b"Hello QUIC")
    .await;

    // Receive streamed data
    let mut data = Vec::new();
    let mut recv_stream = recv
        .on_chunk(|chunk| {
            Ok => chunk.into(),
            Err(e) => {
                log::error!("Receive error: {}", e);
                BadChunk::from_error(e)
            }
        })
        .stream();

    while let Some(chunk) = recv_stream.next().await {
        data.extend_from_slice(&chunk);
    }

    println!("Received {} bytes via QUIC", data.len());
    println!("Data: {}", String::from_utf8_lossy(&data));

    // Test streaming QUIC operations with on_chunk
    println!("\nStreaming QUIC with on_chunk:");
    
    // Stream send with error handling
    let stream_data = b"Streaming QUIC data with proper error handling";
    let mut send_stream = send
        .on_chunk(|chunk| {
            Ok => chunk.into(), 
            Err(e) => {
                log::error!("QUIC send stream error: {}", e);
                BadChunk::from_error(e)
            }
        })
        .send_stream(stream_data);

    let mut sent_chunks = 0;
    while let Some(chunk) = send_stream.next().await {
        sent_chunks += 1;
        println!("Sent stream chunk {}: {} bytes", sent_chunks, chunk.len());
    }

    // Stream receive with error handling  
    let mut receive_stream = recv
        .on_chunk(|chunk| {
            Ok => chunk.into(),
            Err(e) => {
                log::error!("QUIC receive stream error: {}", e);
                BadChunk::from_error(e)
            }
        })
        .receive_stream();

    let mut streaming_data = Vec::new();
    let mut received_chunks = 0;
    while let Some(chunk) = receive_stream.next().await {
        streaming_data.extend_from_slice(&chunk);
        received_chunks += 1;
        println!("Received stream chunk {}: {} bytes", received_chunks, chunk.len());
    }

    println!("Streaming QUIC completed:");
    println!("  Sent {} chunks", sent_chunks);
    println!("  Received {} chunks", received_chunks);
    println!("  Total streaming data: {} bytes", streaming_data.len());
    println!("  Streaming data: {}", String::from_utf8_lossy(&streaming_data));

    Ok(())
}
