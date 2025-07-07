let compressed = Cryypt::compress()
    .zstd()
    .with_level(3)
    .on_result(|result| {
        Ok => result.to_vec(),
        Err(e) => {
            log::error!("Compression failed: {}", e);
            b"Large text data...".to_vec() // Return original on error
        }
    })
    .compress(b"Large text data...")
    .await;