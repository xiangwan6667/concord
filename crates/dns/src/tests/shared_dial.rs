#![allow(
    clippy::disallowed_methods,
    reason = "loopback DNS servers and dialers for tests"
)]

use super::*;
use std::io;
use std::net::SocketAddr;
use std::sync::Weak;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use concord_common::{BoxStream, PacketSession};
use futures_util::{FutureExt, poll};
use tokio::net::{TcpListener, TcpStream};

use crate::shared_dial::{Got, SharedDial};

fn live(_: &usize) -> bool {
    true
}

fn pair(got: io::Result<Got<usize>>) -> (usize, bool) {
    let got = got.unwrap();
    (got.value, got.reused)
}

#[tokio::test]
async fn concurrent_callers_share_a_successful_dial() {
    let slot = SharedDial::new();
    let (send, recv) = tokio::sync::oneshot::channel();
    let first = slot.get(live, async {
        recv.await.unwrap();
        Ok(7)
    });
    tokio::pin!(first);
    assert!(poll!(&mut first).is_pending());
    let mut waiters: Vec<_> = (0..16)
        .map(|_| slot.get(live, async { panic!("duplicate dial") }).boxed())
        .collect();
    for waiter in &mut waiters {
        assert!(poll!(waiter).is_pending());
    }
    send.send(()).unwrap();
    assert_eq!(pair(first.await), (7, false));
    for waiter in waiters {
        assert_eq!(pair(waiter.await), (7, false));
    }
    assert_eq!(
        pair(slot.get(live, async { panic!("cached") }).await),
        (7, true)
    );
}

#[tokio::test]
async fn only_the_waiting_batch_shares_a_dial_error() {
    let slot = SharedDial::new();
    let (send, recv) = tokio::sync::oneshot::channel();
    let first = slot.get(live, async {
        recv.await.unwrap();
        Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "dial failed",
        ))
    });
    tokio::pin!(first);
    assert!(poll!(&mut first).is_pending());
    let mut waiters: Vec<_> = (0..16)
        .map(|_| {
            slot.get(live, async { panic!("duplicate failed dial") })
                .boxed()
        })
        .collect();
    for waiter in &mut waiters {
        assert!(poll!(waiter).is_pending());
    }
    send.send(()).unwrap();
    let first = first.await.err().unwrap();
    // A new caller can succeed before the old waiters consume their error.
    assert_eq!(pair(slot.get(live, async { Ok(9) }).await), (9, false));
    for waiter in waiters {
        let err = waiter.await.err().unwrap();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(err.to_string(), "dial failed");
        let shared = |err: &io::Error| {
            Arc::as_ptr(
                err.get_ref()
                    .unwrap()
                    .downcast_ref::<Arc<io::Error>>()
                    .unwrap(),
            )
        };
        assert_eq!(shared(&first), shared(&err));
    }
}

#[tokio::test]
async fn cancelling_the_dial_releases_waiters_and_allows_another_dial() {
    let slot = SharedDial::new();
    let mut first = slot.get(live, std::future::pending()).boxed();
    assert!(poll!(&mut first).is_pending());
    let mut waiter = slot.get(live, async { panic!("duplicate dial") }).boxed();
    assert!(poll!(&mut waiter).is_pending());
    drop(first);
    assert_eq!(
        waiter.await.err().unwrap().kind(),
        io::ErrorKind::Interrupted
    );
    assert_eq!(pair(slot.get(live, async { Ok(1) }).await), (1, false));
    assert_eq!(slot.take(), Some(1));
    assert_eq!(pair(slot.get(live, async { Ok(2) }).await), (2, false));
}

#[tokio::test]
async fn a_dead_session_is_dropped_and_dialled_again() {
    let slot = SharedDial::new();
    assert_eq!(pair(slot.get(live, async { Ok(1) }).await), (1, false));
    assert_eq!(
        pair(slot.get(|n| *n != 1, async { Ok(2) }).await),
        (2, false)
    );
    assert_eq!(slot.take(), Some(2));
}

#[tokio::test]
async fn a_reset_cancels_the_dial_in_progress_and_its_waiters_dial_again() {
    let slot = SharedDial::new();
    let (send, recv) = tokio::sync::oneshot::channel::<()>();
    let mut first = slot
        .get(live, async {
            recv.await.unwrap();
            Ok(1)
        })
        .boxed();
    assert!(poll!(&mut first).is_pending());
    let mut waiter = slot.get(live, async { Ok(2) }).boxed();
    assert!(poll!(&mut waiter).is_pending());
    assert_eq!(slot.reset(), None);
    assert_eq!(
        first.await.err().unwrap().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert!(send.is_closed(), "the overtaken dial is still running");
    assert_eq!(pair(waiter.await), (2, false));
    assert_eq!(
        pair(slot.get(live, async { panic!("cached") }).await),
        (2, true)
    );
}

#[tokio::test]
async fn a_dial_that_completes_after_a_reset_is_not_cached() {
    let slot = SharedDial::new();
    let (send, recv) = tokio::sync::oneshot::channel();
    let mut first = slot
        .get(live, async {
            recv.await.unwrap();
            slot.reset();
            Ok(1)
        })
        .boxed();
    assert!(poll!(&mut first).is_pending());
    let mut waiter = slot.get(live, async { Ok(2) }).boxed();
    assert!(poll!(&mut waiter).is_pending());
    send.send(()).unwrap();
    assert_eq!(
        first.await.err().unwrap().kind(),
        io::ErrorKind::ConnectionAborted
    );
    assert_eq!(pair(waiter.await), (2, false));
    assert_eq!(slot.take(), Some(2));
}

struct CountingDialer {
    server: SocketAddr,
    udp: Arc<UdpDialer>,
    attempts: AtomicUsize,
    fail: AtomicBool,
    stall: AtomicBool,
    barrier: Option<Arc<tokio::sync::Barrier>>,
}

impl CountingDialer {
    fn attempt(&self) -> io::Result<()> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        if self.fail.swap(false, Ordering::SeqCst) {
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "first dial failed",
            ))
        } else {
            Ok(())
        }
    }

    async fn stall(&self) {
        if self.stall.swap(false, Ordering::SeqCst) {
            std::future::pending::<()>().await;
        }
    }
}

#[async_trait::async_trait]
impl crate::UpstreamDialer for CountingDialer {
    fn knows(&self, via: &str) -> bool {
        via == "node"
    }

    async fn connect(&self, _via: &str, _target: &Address) -> io::Result<BoxStream> {
        self.attempt()?;
        if let Some(barrier) = &self.barrier {
            barrier.wait().await;
        }
        self.stall().await;
        Ok(Box::new(TcpStream::connect(self.server).await?))
    }

    async fn bind_udp(&self, via: &str, target: &Address) -> io::Result<Arc<dyn PacketSession>> {
        self.attempt()?;
        self.stall().await;
        crate::UpstreamDialer::bind_udp(&*self.udp, via, target).await
    }
}

async fn serve_https(h2: bool, handler: Handler) -> SocketAddr {
    use base64::Engine;
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![key.cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
        )
        .unwrap();
    tls.alpn_protocols = vec![if h2 {
        b"h2".to_vec()
    } else {
        b"http/1.1".to_vec()
    }];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (acceptor, handler) = (acceptor.clone(), Arc::clone(&handler));
            tokio::spawn(async move {
                let stream = acceptor.accept(stream).await.unwrap();
                let service =
                    hyper::service::service_fn(|req: http::Request<hyper::body::Incoming>| {
                        let handler = Arc::clone(&handler);
                        async move {
                            let query = req.uri().query().unwrap().strip_prefix("dns=").unwrap();
                            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                                .decode(query)
                                .unwrap();
                            let req = Message::from_vec(&bytes).unwrap();
                            let reply = handler(&req).unwrap();
                            Ok::<_, std::convert::Infallible>(http::Response::new(
                                http_body_util::Full::new(bytes::Bytes::from(
                                    reply.to_vec().unwrap(),
                                )),
                            ))
                        }
                    });
                if h2 {
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
                } else {
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                }
            });
        }
    });
    addr
}

async fn upstream(
    protocol: &str,
    fail: bool,
    barrier: Option<Arc<tokio::sync::Barrier>>,
) -> (Arc<crate::Resolver>, Arc<CountingDialer>) {
    let handler = answer_with(Ipv4Addr::new(10, 0, 2, 1));
    upstream_answering(protocol, fail, barrier, handler).await
}

async fn upstream_answering(
    protocol: &str,
    fail: bool,
    barrier: Option<Arc<tokio::sync::Barrier>>,
    handler: Handler,
) -> (Arc<crate::Resolver>, Arc<CountingDialer>) {
    let addr = match protocol {
        "doq" => serve_quic(handler).await.addr,
        "h3" => serve_h3(handler).await.addr,
        "h2" => serve_https(true, handler).await,
        "tls-h1" => serve_https(false, handler).await,
        "dot" => serve_tls(handler).await.addr,
        "h1" => serve_doh(handler).await.addr,
        _ => panic!("unknown protocol"),
    };
    let url = match protocol {
        "doq" => format!("quic://{addr}#node&skip-cert-verify=true"),
        "dot" => format!("tls://{addr}#node&skip-cert-verify=true"),
        "h1" => format!("http://{addr}/dns-query#node"),
        "h3" => format!("https://{addr}/dns-query#node&skip-cert-verify=true&h3=true"),
        _ => format!("https://{addr}/dns-query#node&skip-cert-verify=true"),
    };
    let dialer = Arc::new(CountingDialer {
        server: addr,
        udp: UdpDialer::new(&["node"]),
        attempts: AtomicUsize::new(0),
        fail: AtomicBool::new(fail),
        stall: AtomicBool::new(false),
        barrier,
    });
    let sink = Arc::new(Sink::default());
    let mut deps = deps(&sink);
    deps.dialer = Arc::downgrade(&dialer) as Weak<dyn crate::UpstreamDialer>;
    let resolver = crate::Resolver::new(&config(&[url]), &HostsConfig::default(), deps).unwrap();
    (resolver, dialer)
}

#[tokio::test]
async fn concurrent_different_names_dial_once_on_each_quic_transport() {
    for protocol in ["h3", "doq"] {
        let (resolver, dialer) = upstream(protocol, false, None).await;
        let queries = (0..16).map(|i| {
            let resolver = Arc::clone(&resolver);
            async move { lookup_v4(&resolver, &format!("name-{i}.test")).await }
        });
        for reply in futures_util::future::join_all(queries).await {
            assert_eq!(reply.unwrap(), vec![ip("10.0.2.1")], "{protocol}");
        }
        assert_eq!(dialer.attempts.load(Ordering::SeqCst), 1, "{protocol}");
    }
}

#[tokio::test]
async fn each_encrypted_transport_dials_again_after_a_failed_query() {
    for protocol in ["h2", "h3", "doq"] {
        let (resolver, dialer) = upstream(protocol, true, None).await;
        let client = resolver
            .clients
            .iter()
            .find(|client| {
                client.address().starts_with("https://") || client.address().starts_with("quic://")
            })
            .unwrap();
        let cx = crate::dialer::Cx {
            initiator: Initiator::App,
        };
        let first = crate::msg::build_query("first.test", RecordType::A).unwrap();
        let err = client.exchange(&first, cx).await.unwrap_err();
        assert!(
            err.to_string().contains("first dial failed"),
            "{protocol}: {err}"
        );
        assert_eq!(dialer.attempts.load(Ordering::SeqCst), 1, "{protocol}");
        let next = crate::msg::build_query("next.test", RecordType::A).unwrap();
        let reply = client.exchange(&next, cx).await.unwrap();
        assert_eq!(crate::msg::answer_ips(&reply), vec![ip("10.0.2.1")]);
        assert_eq!(dialer.attempts.load(Ordering::SeqCst), 2, "{protocol}");
    }
}

#[tokio::test]
async fn a_network_reset_overtakes_the_quic_dial_in_progress() {
    for protocol in ["h3", "doq"] {
        let (resolver, dialer) = upstream(protocol, false, None).await;
        dialer.stall.store(true, Ordering::SeqCst);
        let client = resolver
            .clients
            .iter()
            .find(|client| {
                client.address().starts_with("https://") || client.address().starts_with("quic://")
            })
            .unwrap();
        let cx = crate::dialer::Cx {
            initiator: Initiator::App,
        };
        let first = crate::msg::build_query("first.test", RecordType::A).unwrap();
        let mut first = client.exchange(&first, cx);
        while dialer.attempts.load(Ordering::SeqCst) == 0 {
            assert!(poll!(&mut first).is_pending(), "{protocol}");
            tokio::task::yield_now().await;
        }
        let waiting = crate::msg::build_query("waiting.test", RecordType::A).unwrap();
        let mut waiting = client.exchange(&waiting, cx);
        assert!(poll!(&mut waiting).is_pending(), "{protocol}");
        resolver.reset_connections();
        let err = first.await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted, "{protocol}");
        let reply = waiting.await.unwrap();
        assert_eq!(crate::msg::answer_ips(&reply), vec![ip("10.0.2.1")]);
        assert_eq!(dialer.attempts.load(Ordering::SeqCst), 2, "{protocol}");
        let next = crate::msg::build_query("next.test", RecordType::A).unwrap();
        client.exchange(&next, cx).await.unwrap();
        assert_eq!(dialer.attempts.load(Ordering::SeqCst), 2, "{protocol}");
    }
}

#[tokio::test]
async fn a_network_reset_overtakes_the_tcp_dial_in_progress() {
    for protocol in ["h2", "tls-h1", "dot"] {
        let (resolver, dialer) = upstream(protocol, false, None).await;
        dialer.stall.store(true, Ordering::SeqCst);
        let client = resolver
            .clients
            .iter()
            .find(|client| {
                client.address().starts_with("https://") || client.address().starts_with("tls://")
            })
            .unwrap();
        let cx = crate::dialer::Cx {
            initiator: Initiator::App,
        };
        let first = crate::msg::build_query("first.test", RecordType::A).unwrap();
        let mut first = client.exchange(&first, cx);
        while dialer.attempts.load(Ordering::SeqCst) == 0 {
            assert!(poll!(&mut first).is_pending(), "{protocol}");
            tokio::task::yield_now().await;
        }
        resolver.reset_connections();
        let err = first.await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted, "{protocol}");
        for name in ["next.test", "again.test"] {
            let query = crate::msg::build_query(name, RecordType::A).unwrap();
            client.exchange(&query, cx).await.unwrap();
        }
        assert_eq!(dialer.attempts.load(Ordering::SeqCst), 2, "{protocol}");
    }
}

#[tokio::test]
async fn a_connection_in_use_across_a_network_reset_is_not_kept() {
    for protocol in ["tls-h1", "dot"] {
        let resolver = Arc::new(std::sync::OnceLock::<Weak<crate::Resolver>>::new());
        let answer = answer_with(Ipv4Addr::new(10, 0, 2, 1));
        let first = AtomicBool::new(true);
        let handler: Handler = Arc::new({
            let resolver = Arc::clone(&resolver);
            move |req| {
                if first.swap(false, Ordering::SeqCst) {
                    resolver
                        .get()
                        .and_then(Weak::upgrade)
                        .unwrap()
                        .reset_connections();
                }
                answer(req)
            }
        });
        let (upstream, dialer) = upstream_answering(protocol, false, None, handler).await;
        resolver.set(Arc::downgrade(&upstream)).unwrap();
        for (name, attempts) in [("one.test", 1), ("two.test", 2), ("three.test", 2)] {
            assert_eq!(
                lookup_v4(&upstream, name).await.unwrap(),
                vec![ip("10.0.2.1")],
                "{protocol}"
            );
            assert_eq!(
                dialer.attempts.load(Ordering::SeqCst),
                attempts,
                "{protocol} {name}"
            );
        }
    }
}

#[tokio::test]
async fn concurrent_http1_queries_keep_independent_senders() {
    for protocol in ["tls-h1", "h1"] {
        let barrier = Arc::new(tokio::sync::Barrier::new(16));
        let (resolver, dialer) = upstream(protocol, false, Some(barrier)).await;
        let queries = (0..16).map(|i| {
            let resolver = Arc::clone(&resolver);
            async move { lookup_v4(&resolver, &format!("name-{i}.test")).await }
        });
        let replies = tokio::time::timeout(
            Duration::from_secs(10),
            futures_util::future::join_all(queries),
        )
        .await
        .expect("HTTP/1 queries waited for another query's dial");
        for reply in replies {
            assert_eq!(reply.unwrap(), vec![ip("10.0.2.1")], "{protocol}");
        }
        assert_eq!(dialer.attempts.load(Ordering::SeqCst), 16, "{protocol}");
    }
}

#[tokio::test]
async fn concurrent_queries_reuse_an_established_http2_connection() {
    let (resolver, dialer) = upstream("h2", false, None).await;
    assert_eq!(
        lookup_v4(&resolver, "warmup.test").await.unwrap(),
        vec![ip("10.0.2.1")]
    );
    let queries = (0..16).map(|i| {
        let resolver = Arc::clone(&resolver);
        async move { lookup_v4(&resolver, &format!("name-{i}.test")).await }
    });
    for reply in futures_util::future::join_all(queries).await {
        assert_eq!(reply.unwrap(), vec![ip("10.0.2.1")]);
    }
    assert_eq!(dialer.attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn sequential_http1_queries_reuse_an_idle_sender() {
    let (resolver, dialer) = upstream("tls-h1", false, None).await;
    for name in ["one.test", "two.test", "three.test"] {
        assert_eq!(
            lookup_v4(&resolver, name).await.unwrap(),
            vec![ip("10.0.2.1")]
        );
    }
    assert_eq!(dialer.attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn concurrent_cold_http2_dials_leave_a_usable_cached_sender() {
    let barrier = Arc::new(tokio::sync::Barrier::new(16));
    let (resolver, dialer) = upstream("h2", false, Some(barrier)).await;
    let queries = (0..16).map(|i| {
        let resolver = Arc::clone(&resolver);
        async move { lookup_v4(&resolver, &format!("cold-{i}.test")).await }
    });
    for reply in futures_util::future::join_all(queries).await {
        assert_eq!(reply.unwrap(), vec![ip("10.0.2.1")]);
    }
    assert_eq!(
        lookup_v4(&resolver, "cached.test").await.unwrap(),
        vec![ip("10.0.2.1")]
    );
    assert_eq!(dialer.attempts.load(Ordering::SeqCst), 16);
}
