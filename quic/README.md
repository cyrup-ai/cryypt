# cryypt_quic

QUIC transport protocol with built-in encryption for the Cryypt cryptography suite.

## Installation

```toml
[dependencies]
cryypt_quic = "0.1"
```

## API Examples

### QUIC Server and Client

```rust
use cryypt::{Cryypt, on_result};

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
```