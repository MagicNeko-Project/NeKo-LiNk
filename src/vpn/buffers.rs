use std::sync::Mutex;

/// A simple thread-safe buffer pool to recycle allocations
/// optimized for 64KB buffers (standard max IP packet size).
pub struct BufferPool {
    pool: Mutex<Vec<Vec<u8>>>,
    buf_capacity: usize,
}

impl BufferPool {
    /// Create a new pool. 
    /// capacity_hint: internal vector capacity (number of buffers to hold).
    pub fn new(capacity_hint: usize) -> Self {
        Self {
            pool: Mutex::new(Vec::with_capacity(capacity_hint)),
            buf_capacity: 65536, // 64KB
        }
    }

    /// Acquire a buffer.
    /// If pool is empty, allocates a new Vec with 64KB capacity.
    /// Returned Vec has len=0 but capacity >= 65536.
    pub fn acquire(&self) -> Vec<u8> {
        let mut pool = self.pool.lock().unwrap();
        if let Some(mut buf) = pool.pop() {
            buf.clear();
            buf
        } else {
            Vec::with_capacity(self.buf_capacity)
        }
    }

    /// Release a buffer back to the pool.
    /// Only recycles buffers that meet the capacity requirement.
    pub fn release(&self, buf: Vec<u8>) {
        if buf.capacity() >= self.buf_capacity {
            let mut pool = self.pool.lock().unwrap();
            // TODO: Optional: Bound the pool size to prevent unbounded growth
            pool.push(buf);
        }
    }
}
