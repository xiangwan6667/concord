use std::ops::{Deref, DerefMut};
#[cfg(unix)]
use std::ptr::NonNull;

/// A zeroed buffer that is resident only in the pages that have been written, for one that
/// is large but sparsely touched. On unix it is its own anonymous mapping, so neither
/// malloc's huge-page advice nor its mmap threshold applies to it.
#[derive(Default)]
pub struct SparseBuf(Inner);

#[derive(Default)]
enum Inner {
    #[default]
    Empty,
    #[cfg(unix)]
    Mapped(NonNull<u8>, usize),
    Heap(Box<[u8]>),
}

// SAFETY: the mapping is owned exclusively, like a `Box<[u8]>`.
unsafe impl Send for SparseBuf {}
// SAFETY: shared access only reads through `&[u8]`.
unsafe impl Sync for SparseBuf {}

impl SparseBuf {
    pub fn zeroed(len: usize) -> Self {
        if len == 0 {
            return Self(Inner::Empty);
        }
        #[cfg(unix)]
        if let Some(ptr) = map(len) {
            return Self(Inner::Mapped(ptr, len));
        }
        Self(Inner::Heap(vec![0u8; len].into_boxed_slice()))
    }
}

#[cfg(unix)]
fn map(len: usize) -> Option<NonNull<u8>> {
    // SAFETY: a fresh private anonymous mapping aliases nothing.
    let addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    if addr == libc::MAP_FAILED {
        return None;
    }
    // The system may back anonymous memory with huge pages unasked, and one written byte
    // would then make a whole one resident.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    // SAFETY: the range is the mapping just made.
    unsafe {
        libc::madvise(addr, len, libc::MADV_NOHUGEPAGE);
    }
    NonNull::new(addr.cast())
}

impl Deref for SparseBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match &self.0 {
            Inner::Empty => &[],
            #[cfg(unix)]
            // SAFETY: the mapping is `len` readable bytes owned by `self`.
            Inner::Mapped(ptr, len) => unsafe { std::slice::from_raw_parts(ptr.as_ptr(), *len) },
            Inner::Heap(buf) => buf,
        }
    }
}

impl DerefMut for SparseBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        match &mut self.0 {
            Inner::Empty => &mut [],
            #[cfg(unix)]
            // SAFETY: the mapping is `len` writable bytes owned exclusively by `self`.
            Inner::Mapped(ptr, len) => unsafe {
                std::slice::from_raw_parts_mut(ptr.as_ptr(), *len)
            },
            Inner::Heap(buf) => buf,
        }
    }
}

impl Drop for SparseBuf {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Inner::Mapped(ptr, len) = self.0 {
            // SAFETY: the mapping is `self`'s, and nothing borrows it past `drop`.
            unsafe {
                libc::munmap(ptr.as_ptr().cast(), len);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sparse_buffer_starts_zeroed_and_takes_writes() {
        let mut buf = SparseBuf::zeroed(1 << 20);
        assert_eq!(buf.len(), 1 << 20);
        assert!(buf.iter().all(|&byte| byte == 0));
        buf[4096] = 7;
        assert_eq!(buf[4096], 7);
        assert!(SparseBuf::default().is_empty());
        assert!(SparseBuf::zeroed(0).is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_sparse_buffer_is_resident_only_where_written() {
        let mut buf = SparseBuf::zeroed(8 << 20);
        let at = buf.as_ptr() as usize;
        buf[4096] = 1;
        let smaps = std::fs::read_to_string("/proc/self/smaps").unwrap();
        let mut inside = false;
        let (mut huge, mut flags) = (None, None);
        for line in smaps.lines() {
            let range = line.split_whitespace().next().unwrap_or_default();
            if let Some((lo, hi)) = range.split_once('-')
                && let (Ok(lo), Ok(hi)) =
                    (usize::from_str_radix(lo, 16), usize::from_str_radix(hi, 16))
            {
                inside = (lo..hi).contains(&at);
                continue;
            }
            let kib = |key: &str| {
                line.strip_prefix(key)
                    .and_then(|rest| rest.split_whitespace().next()?.parse::<u64>().ok())
            };
            if inside {
                huge = huge.or(kib("AnonHugePages:"));
                flags = flags.or(line.strip_prefix("VmFlags:").map(str::to_owned));
            }
        }
        assert!(
            flags.is_some_and(|flags| flags.split_whitespace().any(|flag| flag == "nh")),
            "no nohugepage flag on the mapping"
        );
        assert_eq!(huge, Some(0));

        // The kernel merges the mapping with a neighbour of the same flags (glibc marks thread
        // stacks nohugepage too), so smaps' Rss can count the neighbour; read this range alone.
        // SAFETY: sysconf only reads a system constant.
        let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
        let mut resident = vec![0u8; buf.len().div_ceil(page)];
        // SAFETY: the range is the buffer's own mapping, and `resident` has a byte per page of it.
        let rc =
            unsafe { libc::mincore(buf.as_mut_ptr().cast(), buf.len(), resident.as_mut_ptr()) };
        assert_eq!(rc, 0);
        let kib = resident.iter().filter(|&&flag| flag & 1 != 0).count() * page / 1024;
        assert!(kib <= 64, "{kib} kB resident");
    }
}
