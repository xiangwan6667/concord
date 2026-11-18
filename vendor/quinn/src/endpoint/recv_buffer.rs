use std::{
    cell::RefCell,
    mem,
    ops::{Deref, DerefMut},
};

// Concord: datagrams leave poll_socket in owned BytesMuts. Retain scratch per poller thread,
// rather than per endpoint (including every endpoint still in its QUIC closing period).
thread_local! {
    static BUFFER: RefCell<Vec<u8>> = const { RefCell::new(Vec::new()) };
}

pub(super) fn get(len: usize) -> Buffer {
    let mut bytes = BUFFER
        .try_with(|cache| mem::take(&mut *cache.borrow_mut()))
        .unwrap_or_default();
    // Concord: a cold cache keeps the endpoint's original zeroed-allocation path.
    if bytes.is_empty() {
        bytes = vec![0; len];
    } else if bytes.len() < len {
        bytes.resize(len, 0);
    }
    Buffer { bytes, len }
}

pub(super) struct Buffer {
    bytes: Vec<u8>,
    len: usize,
}

impl Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl DerefMut for Buffer {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.bytes[..self.len]
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        // A custom socket may poll another endpoint reentrantly; no cache borrow spans that call.
        // During thread-local destruction the lease simply frees its allocation.
        let _ = BUFFER.try_with(|cache| {
            let previous = mem::replace(&mut *cache.borrow_mut(), mem::take(&mut self.bytes));
            drop(previous);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::get;

    #[test]
    fn a_smaller_receive_keeps_the_initialized_storage_for_the_next_larger_receive() {
        let mut first = get(128);
        first[127] = 42;
        let address = first.as_ptr();
        drop(first);
        let smaller = get(16);
        assert_eq!(smaller.len(), 16);
        assert_eq!(smaller.as_ptr(), address);
        drop(smaller);
        let larger = get(128);
        assert_eq!(larger.as_ptr(), address);
        assert_eq!(larger[127], 42);
    }

    #[test]
    fn reentrant_receives_have_independent_storage_and_return_one_buffer() {
        let mut outer = get(128);
        outer.fill(1);
        let mut inner = get(128);
        inner.fill(2);
        assert_ne!(outer.as_ptr(), inner.as_ptr());
        assert!(outer.iter().all(|byte| *byte == 1));
        drop(inner);
        let address = outer.as_ptr();
        drop(outer);
        assert_eq!(get(128).as_ptr(), address);
    }
}
