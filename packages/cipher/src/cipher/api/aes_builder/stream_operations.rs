//! AES streaming operations

use super::builder_types::AesWithKeyAndChunkHandler;
use super::decrypt_operations::aes_decrypt_with_aad;
use super::encrypt_operations::aes_encrypt_with_aad;

impl<F> AesWithKeyAndChunkHandler<F>
where
    F: Fn(crate::Result<Vec<u8>>) -> Vec<u8> + Send + 'static,
{
    /// Encrypt data as stream - returns async iterator of chunks
    pub fn encrypt_stream<D: Into<Vec<u8>>>(
        self,
        data: D,
    ) -> impl futures::Stream<Item = Vec<u8>> + Send {
        let data = data.into();
        let key = self.key;
        let aad = self.aad;
        let handler = self.chunk_handler;

        futures::stream::unfold(
            (data, key, aad, handler, 0),
            move |(data, key, aad, handler, offset)| async move {
                const CHUNK_SIZE: usize = 1024;

                if offset >= data.len() {
                    return None;
                }
                let end = std::cmp::min(offset + CHUNK_SIZE, data.len());
                let chunk = data[offset..end].to_vec();

                // Encrypt the chunk
                let result = aes_encrypt_with_aad(&key, &chunk, aad.as_deref()).await;
                let processed_chunk = handler(result);

                Some((processed_chunk, (data, key, aad, handler, end)))
            },
        )
    }

    /// Decrypt data as stream - returns async iterator of chunks
    pub fn decrypt_stream<D: Into<Vec<u8>>>(
        self,
        ciphertext: D,
    ) -> impl futures::Stream<Item = Vec<u8>> + Send {
        let ciphertext = ciphertext.into();
        let key = self.key;
        let aad = self.aad;
        let handler = self.chunk_handler;

        futures::stream::unfold(
            (ciphertext, key, aad, handler, 0),
            move |(ciphertext, key, aad, handler, offset)| async move {
                const CHUNK_SIZE: usize = 1024;

                if offset >= ciphertext.len() {
                    return None;
                }
                let end = std::cmp::min(offset + CHUNK_SIZE, ciphertext.len());
                let chunk = ciphertext[offset..end].to_vec();

                // Decrypt the chunk
                let result = aes_decrypt_with_aad(&key, &chunk, aad.as_deref()).await;
                let processed_chunk = handler(result);

                Some((processed_chunk, (ciphertext, key, aad, handler, end)))
            },
        )
    }
}
