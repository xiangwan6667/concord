use std::io::{self, PipeReader, PipeWriter};
use std::mem::ManuallyDrop;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};

use concord_common::sync::lock;

const PIPE_SIZE: libc::c_int = 1024 * 1024;
/// Past `fs.pipe-user-pages-soft` new pipes get two pages and cannot grow, so a splice would move less than a copy.
const MIN_PIPE: libc::c_int = 32 * 1024;
const CHUNK: usize = 1024 * 1024;
/// Linux's default `fs.pipe-user-pages-soft`, `PIPE_DEF_BUFFERS * INR_OPEN_CUR` in `fs/pipe.c`.
const DEFAULT_PIPE_USER_PAGES_SOFT: usize = 16 * 1024;

static POOL: Mutex<Vec<Pipe>> = Mutex::new(Vec::new());
static LIVE: AtomicUsize = AtomicUsize::new(0);

struct Pipe {
    read: PipeReader,
    write: PipeWriter,
}

impl Pipe {
    fn new(read: PipeReader, write: PipeWriter) -> Self {
        LIVE.fetch_add(1, Ordering::Relaxed);
        Pipe { read, write }
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::Relaxed);
    }
}

/// How many full-size pipes the kernel's per-user quota allows; past it a new pipe gets two
/// pages and `SplicePipe::new` refuses it, so an idle pipe beyond it only holds quota.
fn full_size_pipes() -> usize {
    static FULL: OnceLock<usize> = OnceLock::new();
    *FULL.get_or_init(|| {
        let quota = std::fs::read_to_string("/proc/sys/fs/pipe-user-pages-soft")
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .unwrap_or(DEFAULT_PIPE_USER_PAGES_SOFT);
        // SAFETY: sysconf only reads a configuration value.
        let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let pages = match (usize::try_from(PIPE_SIZE), usize::try_from(page)) {
            (Ok(size), Ok(page)) if page > 0 => size.div_ceil(page),
            _ => return usize::MAX,
        };
        if quota == 0 {
            usize::MAX
        } else {
            quota / pages
        }
    })
}

/// Moves bytes between two sockets through a kernel pipe, without a user-space copy.
///
/// An empty pipe goes back to a pool when dropped, as Go's `splicePipePool` keeps pipes
/// for its next splice; one still holding bytes is closed.
pub struct SplicePipe {
    pipe: ManuallyDrop<Pipe>,
    queued: usize,
}

impl SplicePipe {
    pub const AVAILABLE: bool = true;

    pub fn new() -> io::Result<Self> {
        if let Some(pipe) = pooled() {
            return Ok(SplicePipe::from(pipe));
        }
        if crate::sigpipe::sigpipe_kills() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "a splice to a closed peer raises SIGPIPE, which would end this process",
            ));
        }
        let (read, write) = std::io::pipe()?;
        // SAFETY: plain fcntl on a descriptor owned above; a refused size leaves the pipe as it was.
        let size = unsafe {
            libc::fcntl(write.as_raw_fd(), libc::F_SETPIPE_SZ, PIPE_SIZE);
            libc::fcntl(write.as_raw_fd(), libc::F_GETPIPE_SZ)
        };
        if size < MIN_PIPE {
            return Err(io::Error::other("pipe buffer quota exhausted"));
        }
        Ok(SplicePipe::from(Pipe::new(read, write)))
    }

    fn from(pipe: Pipe) -> Self {
        SplicePipe {
            pipe: ManuallyDrop::new(pipe),
            queued: 0,
        }
    }

    pub fn queued(&self) -> usize {
        self.queued
    }

    /// Pulls what `src` has ready into the pipe. `Ok(0)` is the end of the stream.
    pub fn fill(&mut self, src: &impl AsRawFd) -> io::Result<usize> {
        let moved = splice(src.as_raw_fd(), self.pipe.write.as_raw_fd(), CHUNK)?;
        self.queued += moved;
        Ok(moved)
    }

    pub fn drain(&mut self, dst: &impl AsRawFd) -> io::Result<usize> {
        let moved = splice(self.pipe.read.as_raw_fd(), dst.as_raw_fd(), self.queued)?;
        self.queued -= moved;
        Ok(moved)
    }
}

impl Drop for SplicePipe {
    fn drop(&mut self) {
        // SAFETY: `pipe` is taken once, here, and never used again.
        let pipe = unsafe { ManuallyDrop::take(&mut self.pipe) };
        if self.queued == 0 {
            recycle(pipe);
        }
    }
}

fn pooled() -> Option<Pipe> {
    lock(&POOL).pop()
}

fn recycle(pipe: Pipe) {
    if LIVE.load(Ordering::Relaxed) <= full_size_pipes() {
        lock(&POOL).push(pipe);
    }
}

fn splice(from: libc::c_int, to: libc::c_int, len: usize) -> io::Result<usize> {
    loop {
        // SAFETY: both descriptors are open for the whole call and no offsets are passed.
        let moved = unsafe {
            libc::splice(
                from,
                std::ptr::null_mut(),
                to,
                std::ptr::null_mut(),
                len,
                libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE,
            )
        };
        if moved >= 0 {
            return Ok(moved as usize);
        }
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            return Err(err);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use concord_test_support::std_tcp_pair as pair;

    use super::*;

    /// Tests share the process's pipe pool.
    static POOL_TESTS: Mutex<()> = Mutex::new(());

    #[test]
    fn bytes_cross_two_sockets_through_the_pipe() {
        let _pool = lock(&POOL_TESTS);
        let (mut a_far, a) = pair();
        let (b, mut b_far) = pair();
        a.set_nonblocking(true).unwrap();
        b.set_nonblocking(true).unwrap();
        let mut pipe = SplicePipe::new().unwrap();

        assert_eq!(pipe.fill(&a).unwrap_err().kind(), io::ErrorKind::WouldBlock);
        a_far.write_all(b"hello splice").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(pipe.fill(&a).unwrap(), 12);
        assert_eq!(pipe.queued(), 12);
        assert_eq!(pipe.drain(&b).unwrap(), 12);
        assert_eq!(pipe.queued(), 0);

        let mut got = [0u8; 12];
        b_far.read_exact(&mut got).unwrap();
        assert_eq!(&got, b"hello splice");

        drop(a_far);
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(pipe.fill(&a).unwrap(), 0);
    }

    fn inode(pipe: &SplicePipe) -> u64 {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        // SAFETY: fstat writes the whole struct on success, checked before reading it.
        let stat = unsafe {
            assert_eq!(
                libc::fstat(pipe.pipe.read.as_raw_fd(), stat.as_mut_ptr()),
                0
            );
            stat.assume_init()
        };
        stat.st_ino as u64
    }

    #[test]
    fn an_empty_pipe_is_reused_and_one_holding_bytes_is_closed() {
        let _pool = lock(&POOL_TESTS);
        let (mut far, near) = pair();
        near.set_nonblocking(true).unwrap();
        let first = SplicePipe::new().unwrap();
        let empty = inode(&first);
        drop(first);

        let mut reused = SplicePipe::new().unwrap();
        assert_eq!(inode(&reused), empty);
        far.write_all(b"left behind").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(reused.fill(&near).unwrap(), 11);
        drop(reused);

        assert_ne!(inode(&SplicePipe::new().unwrap()), empty);
    }
}
