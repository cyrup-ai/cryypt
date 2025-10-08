//! Production-ready buffer management for streaming operations

use zeroize::Zeroize;

/// Production-ready buffer management for streaming operations
pub struct StreamBuffer {
    buffer: Vec<u8>,
    read_pos: usize,
    write_pos: usize,
    capacity: usize,
}

impl StreamBuffer {
    /// Create new stream buffer with specified capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: vec![0u8; capacity],
            read_pos: 0,
            write_pos: 0,
            capacity,
        }
    }

    /// Write data to buffer, returns bytes written
    pub fn write(&mut self, data: &[u8]) -> usize {
        let available = self.capacity - self.write_pos;
        let to_write = data.len().min(available);

        if to_write > 0 {
            self.buffer[self.write_pos..self.write_pos + to_write]
                .copy_from_slice(&data[..to_write]);
            self.write_pos += to_write;
        }

        to_write
    }

    /// Read data from buffer, returns bytes read
    pub fn read(&mut self, output: &mut [u8]) -> usize {
        let available = self.write_pos - self.read_pos;
        let to_read = output.len().min(available);

        if to_read > 0 {
            output[..to_read].copy_from_slice(&self.buffer[self.read_pos..self.read_pos + to_read]);
            self.read_pos += to_read;
        }

        to_read
    }

    /// Compact buffer by moving unread data to beginning
    pub fn compact(&mut self) {
        if self.read_pos > 0 {
            let unread = self.write_pos - self.read_pos;
            if unread > 0 {
                self.buffer.copy_within(self.read_pos..self.write_pos, 0);
            }
            self.write_pos = unread;
            self.read_pos = 0;
        }
    }

    /// Get available space for writing
    pub fn available_write(&self) -> usize {
        self.capacity - self.write_pos
    }

    /// Get available data for reading
    pub fn available_read(&self) -> usize {
        self.write_pos - self.read_pos
    }

    /// Check if buffer is full
    pub fn is_full(&self) -> bool {
        self.write_pos >= self.capacity
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.read_pos >= self.write_pos
    }

    /// Clear buffer
    pub fn clear(&mut self) {
        self.read_pos = 0;
        self.write_pos = 0;
    }
}

impl Drop for StreamBuffer {
    fn drop(&mut self) {
        // Zeroize buffer contents for security
        self.buffer.zeroize();
    }
}
