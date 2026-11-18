//! Several UDP datagrams in one `sendmmsg`, with runs to one destination coalesced into a
//! `UDP_SEGMENT` message, after sing-tun's `goPacketBatchIO.send`, and in one `recvmmsg`,
//! after its `goPacketBatchIO.receive` (stack_go_socket_linux.go at 611d83b7).

use concord_common::Datagram;

/// The kernel's `UDP_MAX_SEGMENTS`; sing-tun stops a run at the same count.
const MAX_SEGMENTS: usize = 64;
/// The largest IPv4 UDP payload, which sing-tun also applies to IPv6.
const MAX_MESSAGE: usize = 65_507;
pub const UDP_BATCH: usize = 64;

/// Splits `batch` into messages, writing each one's end into `ends`; returns how many.
/// A message after the first datagram takes following ones to the same destination that
/// are no longer than it, and ends after one that is shorter, as GSO cuts every segment
/// but the last to the first one's size.
#[cfg_attr(
    not(any(target_os = "linux", target_os = "android")),
    allow(dead_code, reason = "only Linux and Android send with UDP_SEGMENT")
)]
fn plan(batch: &[Datagram<'_>], coalesce: bool, ends: &mut [usize; UDP_BATCH]) -> usize {
    let batch = batch.get(..UDP_BATCH).unwrap_or(batch);
    let mut messages = 0;
    let mut start = 0;
    while start < batch.len() {
        let mut end = start + 1;
        if let Some(first) = batch.get(start)
            && coalesce
            && !first.payload.is_empty()
            && u16::try_from(first.payload.len()).is_ok()
        {
            let segment = first.payload.len();
            let mut length = segment;
            while let Some(next) = batch.get(end) {
                let len = next.payload.len();
                if end - start >= MAX_SEGMENTS
                    || next.dst != first.dst
                    || len == 0
                    || len > segment
                    || length + len > MAX_MESSAGE
                {
                    break;
                }
                length += len;
                end += 1;
                if len < segment {
                    break;
                }
            }
        }
        if let Some(slot) = ends.get_mut(messages) {
            *slot = end;
        }
        messages += 1;
        start = end;
    }
    messages
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod sys {
    use std::io;
    use std::mem::zeroed;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
    use std::os::fd::{AsRawFd, RawFd};
    use std::sync::atomic::{AtomicBool, Ordering};

    use concord_common::packet::{RECV_MAX, RECV_SLOT};
    use concord_common::{Datagram, RecvBatch};
    use tokio::io::Interest;
    use tokio::net::UdpSocket;

    use super::{UDP_BATCH, plan};

    /// Whether a socket may coalesce. A kernel that refuses `UDP_SEGMENT` is not asked
    /// again for that socket, as sing-tun does.
    #[derive(Debug)]
    pub struct UdpGso(AtomicBool);

    impl Default for UdpGso {
        fn default() -> Self {
            UdpGso(AtomicBool::new(true))
        }
    }

    impl UdpGso {
        pub fn enabled(&self) -> bool {
            self.0.load(Ordering::Relaxed)
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    union Name {
        v4: libc::sockaddr_in,
        v6: libc::sockaddr_in6,
    }

    fn name(dst: SocketAddr) -> (Name, libc::socklen_t) {
        match dst {
            SocketAddr::V4(addr) => {
                // SAFETY: `sockaddr_in` is plain data for which all zeroes is valid.
                let mut sin: libc::sockaddr_in = unsafe { zeroed() };
                sin.sin_family = libc::AF_INET as libc::sa_family_t;
                sin.sin_port = addr.port().to_be();
                sin.sin_addr.s_addr = u32::from(*addr.ip()).to_be();
                (Name { v4: sin }, size_of::<libc::sockaddr_in>() as _)
            }
            SocketAddr::V6(addr) => {
                // SAFETY: as above, for `sockaddr_in6`.
                let mut sin6: libc::sockaddr_in6 = unsafe { zeroed() };
                sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                sin6.sin6_port = addr.port().to_be();
                sin6.sin6_flowinfo = addr.flowinfo().to_be();
                sin6.sin6_addr.s6_addr = addr.ip().octets();
                sin6.sin6_scope_id = addr.scope_id();
                (Name { v6: sin6 }, size_of::<libc::sockaddr_in6>() as _)
            }
        }
    }

    pub fn send_udp_batch(
        socket: &UdpSocket,
        batch: &[Datagram<'_>],
        gso: &UdpGso,
    ) -> io::Result<usize> {
        let fd = socket.as_raw_fd();
        socket.try_io(Interest::WRITABLE, || {
            send(batch, gso, |headers| sendmmsg(fd, headers))
        })
    }

    pub fn send_udp_batch_fd(fd: RawFd, batch: &[Datagram<'_>], gso: &UdpGso) -> io::Result<usize> {
        send(batch, gso, |headers| sendmmsg(fd, headers))
    }

    pub fn recv_udp_batch_fd(fd: RawFd, batch: &mut RecvBatch) -> io::Result<()> {
        recv(batch, |headers| recvmmsg(fd, headers))
    }

    fn sendmmsg(fd: RawFd, headers: &mut [libc::mmsghdr]) -> io::Result<usize> {
        // SAFETY: each header points at a name, iovecs and a control that the caller keeps
        // alive across the call, and the iovecs at payloads it borrows.
        let sent = unsafe {
            libc::syscall(
                libc::SYS_sendmmsg,
                fd,
                headers.as_mut_ptr(),
                headers.len() as libc::c_uint,
                libc::MSG_DONTWAIT,
            )
        };
        match usize::try_from(sent) {
            Ok(0) => Err(io::Error::from_raw_os_error(libc::EIO)),
            Ok(sent) => Ok(sent),
            Err(_) => Err(io::Error::last_os_error()),
        }
    }

    pub fn recv_udp_batch(socket: &UdpSocket, batch: &mut RecvBatch) -> io::Result<()> {
        let fd = socket.as_raw_fd();
        socket.try_io(Interest::READABLE, || {
            recv(batch, |headers| recvmmsg(fd, headers))
        })
    }

    fn recvmmsg(fd: RawFd, headers: &mut [libc::mmsghdr]) -> io::Result<usize> {
        // SAFETY: each header points at a name and an iovec the caller keeps alive across
        // the call, and the iovec at a slot of `RECV_SLOT` writable bytes.
        let received = unsafe {
            libc::syscall(
                libc::SYS_recvmmsg,
                fd,
                headers.as_mut_ptr(),
                headers.len() as libc::c_uint,
                libc::MSG_DONTWAIT,
                std::ptr::null_mut::<libc::timespec>(),
            )
        };
        match usize::try_from(received) {
            Ok(0) => Err(io::Error::from(io::ErrorKind::WouldBlock)),
            Ok(received) => Ok(received),
            Err(_) => Err(io::Error::last_os_error()),
        }
    }

    fn source(name: &libc::sockaddr_storage) -> Option<SocketAddr> {
        match i32::from(name.ss_family) {
            libc::AF_INET => {
                // SAFETY: the kernel wrote a `sockaddr_in` for this family, and the storage
                // is large and aligned enough for it.
                let sin = unsafe { &*std::ptr::from_ref(name).cast::<libc::sockaddr_in>() };
                Some(SocketAddr::from((
                    Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)),
                    u16::from_be(sin.sin_port),
                )))
            }
            libc::AF_INET6 => {
                // SAFETY: as above, for `sockaddr_in6`.
                let sin6 = unsafe { &*std::ptr::from_ref(name).cast::<libc::sockaddr_in6>() };
                Some(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::from(sin6.sin6_addr.s6_addr),
                    u16::from_be(sin6.sin6_port),
                    u32::from_be(sin6.sin6_flowinfo),
                    sin6.sin6_scope_id,
                )))
            }
            _ => None,
        }
    }

    /// `call` receives into the headers it is given and returns how many it filled.
    fn recv(
        batch: &mut RecvBatch,
        mut call: impl FnMut(&mut [libc::mmsghdr]) -> io::Result<usize>,
    ) -> io::Result<()> {
        let slots = batch.prepare();
        let count = (slots.len() / RECV_SLOT).min(RECV_MAX);
        let base = slots.as_mut_ptr();
        // SAFETY: plain data for which all zeroes is valid; every entry used below is
        // filled in first.
        let (mut headers, mut iovecs, mut names): (
            [libc::mmsghdr; RECV_MAX],
            [libc::iovec; RECV_MAX],
            [libc::sockaddr_storage; RECV_MAX],
        ) = unsafe { (zeroed(), zeroed(), zeroed()) };
        for (index, iovec) in iovecs.iter_mut().enumerate().take(count) {
            iovec.iov_base = base.wrapping_add(index * RECV_SLOT).cast();
            iovec.iov_len = RECV_SLOT;
        }
        let iov = iovecs.as_mut_ptr();
        let name_at = names.as_mut_ptr();
        for (index, header) in headers.iter_mut().enumerate().take(count) {
            let msg = &mut header.msg_hdr;
            msg.msg_name = name_at.wrapping_add(index).cast();
            msg.msg_namelen = size_of::<libc::sockaddr_storage>() as _;
            msg.msg_iov = iov.wrapping_add(index);
            msg.msg_iovlen = 1;
        }
        let received = loop {
            match call(headers.get_mut(..count).unwrap_or_default()) {
                Err(err) if err.raw_os_error() == Some(libc::EINTR) => {}
                received => break received?,
            }
        };
        batch.received(received, |index| {
            let (Some(header), Some(name)) = (headers.get(index), names.get(index)) else {
                return (0, None);
            };
            if header.msg_hdr.msg_flags & libc::MSG_TRUNC != 0 {
                tracing::debug!("dropped a UDP datagram larger than a receive slot");
                return (0, None);
            }
            (header.msg_len as usize, source(name))
        });
        Ok(())
    }

    /// `call` sends the headers it is given and returns how many messages left.
    fn send(
        batch: &[Datagram<'_>],
        gso: &UdpGso,
        mut call: impl FnMut(&mut [libc::mmsghdr]) -> io::Result<usize>,
    ) -> io::Result<usize> {
        let batch = batch.get(..UDP_BATCH).unwrap_or(batch);
        if batch.is_empty() {
            return Ok(0);
        }
        let mut coalesce = gso.enabled();
        loop {
            let mut ends = [0usize; UDP_BATCH];
            let messages = plan(batch, coalesce, &mut ends);
            let ends = ends.get(..messages).unwrap_or_default();
            // SAFETY: plain data for which all zeroes is valid; every entry used below is
            // filled in first.
            let (mut headers, mut iovecs, mut names): (
                [libc::mmsghdr; UDP_BATCH],
                [libc::iovec; UDP_BATCH],
                [Name; UDP_BATCH],
            ) = unsafe { (zeroed(), zeroed(), zeroed()) };
            let mut name_lens: [libc::socklen_t; UDP_BATCH] = [0; UDP_BATCH];
            let mut controls = [[0u64; 4]; UDP_BATCH];
            for (iovec, datagram) in iovecs.iter_mut().zip(batch) {
                iovec.iov_base = datagram.payload.as_ptr().cast_mut().cast();
                iovec.iov_len = datagram.payload.len();
            }
            let mut start = 0;
            for ((slot, len), &end) in names.iter_mut().zip(&mut name_lens).zip(ends) {
                if let Some(first) = batch.get(start) {
                    (*slot, *len) = name(first.dst);
                }
                start = end;
            }
            let iov = iovecs.as_mut_ptr();
            let name_at = names.as_mut_ptr();
            let control_at = controls.as_mut_ptr();
            let mut segmented = false;
            let mut start = 0;
            for (index, ((header, &end), &name_len)) in
                headers.iter_mut().zip(ends).zip(&name_lens).enumerate()
            {
                let msg = &mut header.msg_hdr;
                msg.msg_name = name_at.wrapping_add(index).cast();
                msg.msg_namelen = name_len;
                msg.msg_iov = iov.wrapping_add(start);
                msg.msg_iovlen = (end - start) as _;
                if end - start > 1 {
                    segmented = true;
                    let segment = batch
                        .get(start)
                        .and_then(|first| u16::try_from(first.payload.len()).ok())
                        .unwrap_or(u16::MAX);
                    msg.msg_control = control_at.wrapping_add(index).cast();
                    // SAFETY: CMSG_SPACE only computes a length.
                    msg.msg_controllen = unsafe { libc::CMSG_SPACE(2) } as _;
                    // SAFETY: each control is 32 aligned bytes, more than CMSG_SPACE(2), and
                    // `msg` points at this one, so its first header and data lie inside it.
                    unsafe {
                        let cmsg = libc::CMSG_FIRSTHDR(std::ptr::from_ref(msg));
                        (*cmsg).cmsg_level = libc::SOL_UDP;
                        (*cmsg).cmsg_type = libc::UDP_SEGMENT;
                        (*cmsg).cmsg_len = libc::CMSG_LEN(2) as _;
                        std::ptr::write_unaligned(libc::CMSG_DATA(cmsg).cast::<u16>(), segment);
                    }
                }
                start = end;
            }
            let err = match call(headers.get_mut(..messages).unwrap_or_default()) {
                Ok(sent) => {
                    return Ok(sent
                        .checked_sub(1)
                        .and_then(|last| ends.get(last))
                        .copied()
                        .unwrap_or(0));
                }
                Err(err) => err,
            };
            match err.raw_os_error() {
                Some(libc::EINTR) => {}
                Some(libc::EINVAL | libc::EIO | libc::ENOPROTOOPT | libc::EOPNOTSUPP)
                    if segmented =>
                {
                    tracing::debug!("UDP_SEGMENT refused, sending datagrams one by one: {err}");
                    gso.0.store(false, Ordering::Relaxed);
                    coalesce = false;
                }
                Some(libc::EMSGSIZE) if segmented => coalesce = false,
                _ => return Err(err),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use std::net::UdpSocket as StdSocket;
        use std::time::Duration;

        use super::*;

        #[allow(clippy::disallowed_methods, reason = "a loopback test pair")]
        async fn exchange(gso: &UdpGso, payloads: &[Vec<u8>]) -> Vec<Vec<u8>> {
            let peer = StdSocket::bind("127.0.0.1:0").unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let dst = peer.local_addr().unwrap();
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let batch: Vec<_> = payloads
                .iter()
                .map(|payload| Datagram { payload, dst })
                .collect();
            let mut rest = batch.as_slice();
            while !rest.is_empty() {
                socket.writable().await.unwrap();
                match send_udp_batch(&socket, rest, gso) {
                    Ok(sent) => rest = &rest[sent..],
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                    Err(err) => panic!("{err}"),
                }
            }
            let mut buf = [0u8; 65_536];
            (0..payloads.len())
                .map(|_| {
                    let n = peer.recv(&mut buf).unwrap();
                    buf[..n].to_vec()
                })
                .collect()
        }

        fn payloads() -> Vec<Vec<u8>> {
            let mut payloads: Vec<Vec<u8>> = (0..10u8).map(|i| vec![i; 1200]).collect();
            payloads.push(vec![10; 700]);
            payloads.push(vec![11; 1300]);
            payloads.extend((12..80u8).map(|i| vec![i; 1000]));
            payloads
        }

        #[tokio::test]
        async fn coalesced_datagrams_arrive_whole_and_in_order() {
            let payloads = payloads();
            let gso = UdpGso::default();

            assert_eq!(exchange(&gso, &payloads).await, payloads);
        }

        #[tokio::test]
        async fn without_gso_each_datagram_still_arrives_whole() {
            let payloads = payloads();
            let gso = UdpGso(AtomicBool::new(false));

            assert_eq!(exchange(&gso, &payloads).await, payloads);
        }

        /// Refuses the first call with `errno` and records each call's segments per message.
        fn refused_once(errno: i32, gso: &UdpGso) -> (io::Result<usize>, Vec<Vec<usize>>) {
            let dst = "10.0.0.1:9".parse().unwrap();
            let payloads = [[0u8; 100]; 4];
            let batch: Vec<_> = payloads
                .iter()
                .map(|payload| Datagram { payload, dst })
                .collect();
            let mut calls = Vec::new();
            let sent = send(&batch, gso, |headers| {
                #[allow(clippy::unnecessary_cast, reason = "msg_iovlen is a c_int on musl")]
                let segments = headers
                    .iter()
                    .map(|header| header.msg_hdr.msg_iovlen as usize)
                    .collect();
                calls.push(segments);
                if calls.len() == 1 {
                    Err(io::Error::from_raw_os_error(errno))
                } else {
                    Ok(headers.len())
                }
            });
            (sent, calls)
        }

        #[test]
        fn a_refused_segment_size_sends_this_batch_unsegmented_and_keeps_gso() {
            let gso = UdpGso::default();
            let (sent, calls) = refused_once(libc::EMSGSIZE, &gso);

            assert_eq!(sent.unwrap(), 4);
            assert_eq!(calls, [vec![4], vec![1, 1, 1, 1]]);
            assert!(gso.enabled());
        }

        #[test]
        fn a_kernel_that_refuses_udp_segment_is_not_asked_again() {
            let gso = UdpGso::default();
            let (sent, calls) = refused_once(libc::EINVAL, &gso);

            assert_eq!(sent.unwrap(), 4);
            assert_eq!(calls, [vec![4], vec![1, 1, 1, 1]]);
            assert!(!gso.enabled());
        }

        #[test]
        fn an_error_without_segments_is_returned() {
            let gso = UdpGso(AtomicBool::new(false));
            let (sent, calls) = refused_once(libc::EINVAL, &gso);

            assert_eq!(sent.unwrap_err().raw_os_error(), Some(libc::EINVAL));
            assert_eq!(calls, [vec![1, 1, 1, 1]]);
        }

        #[test]
        fn a_partial_send_counts_the_datagrams_of_the_messages_that_left() {
            let dst = "10.0.0.1:9".parse().unwrap();
            let lens = [100, 100, 50, 100, 100];
            let payloads: Vec<Vec<u8>> = lens.iter().map(|&len| vec![0; len]).collect();
            let batch: Vec<_> = payloads
                .iter()
                .map(|payload| Datagram { payload, dst })
                .collect();

            let sent = send(&batch, &UdpGso::default(), |_| Ok(1)).unwrap();

            assert_eq!(sent, 3);
        }

        #[allow(clippy::disallowed_methods, reason = "a loopback test pair")]
        async fn receive_from(local: &str, payloads: &[Vec<u8>]) -> Vec<(Vec<u8>, SocketAddr)> {
            let socket = UdpSocket::bind(local).await.unwrap();
            let peer = StdSocket::bind(local).unwrap();
            let to = socket.local_addr().unwrap();
            for payload in payloads {
                peer.send_to(payload, to).unwrap();
            }
            let mut got = Vec::new();
            let mut batch = RecvBatch::default();
            while got.len() < payloads.len() {
                socket.readable().await.unwrap();
                match recv_udp_batch(&socket, &mut batch) {
                    Ok(()) => got.extend(batch.iter().map(|(p, from)| (p.to_vec(), from))),
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
                    Err(err) => panic!("{err}"),
                }
            }
            assert!(
                got.iter()
                    .all(|(_, from)| *from == peer.local_addr().unwrap())
            );
            got
        }

        #[tokio::test]
        async fn queued_datagrams_arrive_whole_in_order_with_their_source() {
            let payloads = payloads();

            let got = receive_from("127.0.0.1:0", &payloads).await;

            let got: Vec<_> = got.into_iter().map(|(payload, _)| payload).collect();
            assert_eq!(got, payloads);
        }

        #[allow(clippy::disallowed_methods, reason = "probes for a v6 loopback")]
        #[tokio::test]
        async fn a_v6_source_is_read_back() {
            let payloads = vec![vec![1; 10], vec![2; 1500], vec![3; 65_000]];
            if StdSocket::bind("[::1]:0").is_err() {
                return;
            }

            let got = receive_from("[::1]:0", &payloads).await;

            assert!(got.iter().all(|(_, from)| from.is_ipv6()));
            let got: Vec<_> = got.into_iter().map(|(payload, _)| payload).collect();
            assert_eq!(got, payloads);
        }

        #[test]
        fn an_interrupted_receive_is_retried_and_a_truncated_datagram_is_skipped() {
            let mut batch = RecvBatch::default();
            let mut calls = 0;
            recv(&mut batch, |headers| {
                calls += 1;
                if calls == 1 {
                    return Err(io::Error::from_raw_os_error(libc::EINTR));
                }
                for (index, header) in headers.iter_mut().take(2).enumerate() {
                    let sin = header.msg_hdr.msg_name.cast::<libc::sockaddr_in>();
                    // SAFETY: the name points at a zeroed `sockaddr_storage`, large enough.
                    unsafe {
                        (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
                        (*sin).sin_port = 53u16.to_be();
                    }
                    header.msg_len = 4;
                    if index == 0 {
                        header.msg_hdr.msg_flags = libc::MSG_TRUNC;
                    }
                }
                Ok(2)
            })
            .unwrap();

            assert_eq!(calls, 2);
            let got: Vec<_> = batch.iter().map(|(p, from)| (p.len(), from)).collect();
            assert_eq!(got, [(4, SocketAddr::from(([0, 0, 0, 0], 53)))]);
        }

        #[allow(clippy::disallowed_methods, reason = "a loopback socket")]
        #[tokio::test]
        async fn a_v6_destination_from_a_v4_socket_reports_the_error() {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let batch = [Datagram {
                payload: b"x",
                dst: "[::1]:9".parse().unwrap(),
            }];

            socket.writable().await.unwrap();
            assert!(send_udp_batch(&socket, &batch, &UdpGso::default()).is_err());
        }
    }
}

/// One socket's batched datagram I/O. Linux and Android send with `sendmmsg`, coalescing
/// runs to one destination with `UDP_SEGMENT`, and receive with `recvmmsg`; other platforms
/// have neither call, so [`SENDS`](Self::SENDS) and [`RECEIVES`](Self::RECEIVES) are false
/// there and every call returns `Unsupported`.
#[derive(Debug, Default)]
pub struct UdpBatch {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    gso: sys::UdpGso,
}

impl UdpBatch {
    /// Whether [`send`](Self::send) costs one call for several datagrams.
    pub const SENDS: bool = cfg!(any(target_os = "linux", target_os = "android"));
    /// Whether [`recv`](Self::recv) takes several datagrams in one call.
    pub const RECEIVES: bool = cfg!(any(target_os = "linux", target_os = "android"));
}

#[cfg(any(target_os = "linux", target_os = "android"))]
impl UdpBatch {
    /// Sends from the front of `batch`, at most [`UDP_BATCH`] datagrams, and returns how
    /// many left; an error means none did. `WouldBlock` clears the socket's write
    /// readiness, so the caller polls it again. A kernel that refuses `UDP_SEGMENT` is not
    /// asked again for this socket.
    pub fn send(
        &self,
        socket: &tokio::net::UdpSocket,
        batch: &[Datagram<'_>],
    ) -> std::io::Result<usize> {
        sys::send_udp_batch(socket, batch, &self.gso)
    }

    /// [`send`](Self::send) for a socket whose readiness the caller tracks itself.
    pub fn send_std(
        &self,
        socket: &std::net::UdpSocket,
        batch: &[Datagram<'_>],
    ) -> std::io::Result<usize> {
        let fd = std::os::fd::AsRawFd::as_raw_fd(socket);
        sys::send_udp_batch_fd(fd, batch, &self.gso)
    }

    /// Receives as many datagrams as `batch` asks for that are already queued, replacing
    /// what it held. `WouldBlock` clears the socket's read readiness, so the caller polls it
    /// again.
    pub fn recv(
        socket: &tokio::net::UdpSocket,
        batch: &mut concord_common::RecvBatch,
    ) -> std::io::Result<()> {
        sys::recv_udp_batch(socket, batch)
    }

    /// [`recv`](Self::recv) for a socket whose readiness the caller tracks itself.
    pub fn recv_std(
        socket: &std::net::UdpSocket,
        batch: &mut concord_common::RecvBatch,
    ) -> std::io::Result<()> {
        sys::recv_udp_batch_fd(std::os::fd::AsRawFd::as_raw_fd(socket), batch)
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
impl UdpBatch {
    pub fn send(
        &self,
        _socket: &tokio::net::UdpSocket,
        _batch: &[Datagram<'_>],
    ) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    pub fn send_std(
        &self,
        _socket: &std::net::UdpSocket,
        _batch: &[Datagram<'_>],
    ) -> std::io::Result<usize> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    pub fn recv(
        _socket: &tokio::net::UdpSocket,
        _batch: &mut concord_common::RecvBatch,
    ) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }

    pub fn recv_std(
        _socket: &std::net::UdpSocket,
        _batch: &mut concord_common::RecvBatch,
    ) -> std::io::Result<()> {
        Err(std::io::ErrorKind::Unsupported.into())
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use super::*;

    fn to(port: u16, lens: &[usize]) -> Vec<(Vec<u8>, SocketAddr)> {
        let dst = SocketAddr::from(([10, 0, 0, 1], port));
        lens.iter().map(|&len| (vec![0; len], dst)).collect()
    }

    fn messages(owned: &[(Vec<u8>, SocketAddr)], coalesce: bool) -> Vec<usize> {
        let batch: Vec<_> = owned
            .iter()
            .map(|(payload, dst)| Datagram { payload, dst: *dst })
            .collect();
        let mut ends = [0; UDP_BATCH];
        let count = plan(&batch, coalesce, &mut ends);
        ends[..count].to_vec()
    }

    #[test]
    fn equal_datagrams_to_one_destination_make_one_message() {
        assert_eq!(messages(&to(1, &[1200; 5]), true), [5]);
    }

    #[test]
    fn a_shorter_datagram_ends_its_message_and_a_longer_one_starts_the_next() {
        assert_eq!(
            messages(&to(1, &[1200, 1200, 800, 1200, 1300, 1300]), true),
            [3, 4, 6]
        );
    }

    #[test]
    fn another_destination_starts_a_new_message() {
        let mut batch = to(1, &[100, 100]);
        batch.extend(to(2, &[100, 100]));
        assert_eq!(messages(&batch, true), [2, 4]);
    }

    #[test]
    fn a_message_stops_at_the_segment_and_size_limits() {
        assert_eq!(messages(&to(1, &[10; UDP_BATCH]), true), [UDP_BATCH]);
        assert_eq!(messages(&to(1, &[30_000; 3]), true), [2, 3]);
    }

    #[test]
    fn empty_datagrams_and_disabled_coalescing_go_one_per_message() {
        assert_eq!(messages(&to(1, &[0, 0, 5]), true), [1, 2, 3]);
        assert_eq!(messages(&to(1, &[5, 5, 5]), false), [1, 2, 3]);
    }

    #[test]
    fn more_than_a_batch_plans_only_the_first_batch() {
        let batch = to(1, &[10; UDP_BATCH + 5]);
        assert_eq!(messages(&batch, false).len(), UDP_BATCH);
    }
}
