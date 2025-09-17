use cryypt::Cryypt;

let encrypted = Cryypt::cipher()
    .aes()
    .with_key(key)
    .on_result(|result| {
        result
            .map(|result| result)
            .unwrap_or_else(|e| {
                log::error!("Encryption failed: {}", e);
                Vec::new()
            })
    })
    .encrypt(b"Secret message")
    .await;