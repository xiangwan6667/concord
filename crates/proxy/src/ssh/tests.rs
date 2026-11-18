#![allow(
    clippy::disallowed_methods,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    reason = "tests talk to loopback sockets and run the system sshd"
)]

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use concord_common::{Address, DialCx, Initiator, Outbound};
use concord_config::proxy::ProxyKind;
use concord_config::{Capabilities, ProxyParse, parse_proxy};
use concord_tls::TrustStore;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::ctx::{BuildCtx, BuildError};
use crate::testing::{HeldLookup, test_env};

fn client(port: u16, extra: Value) -> Result<Arc<dyn Outbound>, BuildError> {
    let mut proxy = json!({
        "name": "ssh", "type": "ssh", "server": "127.0.0.1", "port": port,
        "username": "tester",
    });
    if let (Some(base), Some(more)) = (proxy.as_object_mut(), extra.as_object()) {
        base.extend(more.clone());
    }
    let ProxyParse::Ok(def) =
        parse_proxy(proxy.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        unreachable!()
    };
    let ProxyKind::Ssh(opts) = &def.kind else {
        unreachable!()
    };
    super::build(&def, opts, &BuildCtx::new(TrustStore::new(b"", Vec::new())))
}

fn tracked_client(port: u16, tracked: &crate::testing::Tracked) -> Arc<dyn Outbound> {
    let proxy = json!({
        "name": "ssh", "type": "ssh", "server": "127.0.0.1", "port": port,
        "username": "tester", "password": "hunter2",
    });
    let ProxyParse::Ok(def) =
        parse_proxy(proxy.as_object().unwrap(), &Capabilities::full()).unwrap()
    else {
        unreachable!()
    };
    let ProxyKind::Ssh(opts) = &def.kind else {
        unreachable!()
    };
    super::build(&def, opts, &tracked.ctx()).unwrap()
}

async fn echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut read, mut write) = socket.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    port
}

async fn echo_through(outbound: &dyn Outbound, port: u16, size: usize) -> std::io::Result<()> {
    let env = test_env();
    let cx = DialCx::new(&env, Initiator::Direct, None);
    let mut stream = tokio::time::timeout(
        Duration::from_secs(10),
        outbound.connect(&cx, &Address::new("127.0.0.1", port)),
    )
    .await
    .map_err(|_| std::io::Error::other("connect timed out"))??;
    let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
    let (mut read, mut write) = tokio::io::split(&mut stream);
    let writer = async {
        write.write_all(&data).await.unwrap();
        write.flush().await.unwrap();
    };
    let reader = async {
        let mut got = vec![0u8; size];
        read.read_exact(&mut got).await.unwrap();
        got
    };
    let (_, got) = tokio::time::timeout(Duration::from_secs(20), async {
        tokio::join!(writer, reader)
    })
    .await
    .map_err(|_| std::io::Error::other("echo timed out"))?;
    assert_eq!(got, data);
    Ok(())
}

struct Sshd {
    child: Child,
    dir: tempfile::TempDir,
    port: u16,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn keygen(binary: &str, kind: &str, path: &Path, passphrase: &str) {
    let (kind, format) = kind.split_once(':').unwrap_or((kind, "RFC4716"));
    let status = Command::new(binary)
        .args(["-q", "-t", kind, "-m", format, "-N", passphrase, "-f"])
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}

fn keygen_sized(binary: &str, bits: u32, path: &Path) {
    let status = Command::new(binary)
        .args(["-q", "-t", "rsa", "-b", &bits.to_string(), "-N", "", "-f"])
        .arg(path)
        .status()
        .unwrap();
    assert!(status.success());
}

async fn start_sshd(sshd: &str, keygen_binary: &str, accepted: &str) -> Sshd {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    keygen(keygen_binary, "ed25519", &path.join("host_ed25519"), "");
    keygen(keygen_binary, "ecdsa", &path.join("host_ecdsa"), "");
    for (name, kind, pass) in [
        ("user_ed25519", "ed25519", ""),
        ("user_ecdsa", "ecdsa", ""),
        ("user_locked", "ed25519", "secret"),
        ("user_rsa", "rsa", ""),
        ("user_rsa_pem", "rsa:PEM", ""),
        ("user_rsa_pem_locked", "rsa:PEM", "secret"),
        ("user_rsa_pkcs8", "rsa:PKCS8", ""),
        ("user_rsa_locked", "rsa", "secret"),
    ] {
        keygen(keygen_binary, kind, &path.join(name), pass);
    }
    let mut authorized = String::new();
    for name in [
        "user_ed25519",
        "user_ecdsa",
        "user_locked",
        "user_rsa",
        "user_rsa_pem",
        "user_rsa_pem_locked",
        "user_rsa_pkcs8",
        "user_rsa_locked",
    ] {
        authorized.push_str(&std::fs::read_to_string(path.join(format!("{name}.pub"))).unwrap());
    }
    std::fs::write(path.join("authorized_keys"), authorized).unwrap();
    let port = {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let config = format!(
        "Port {port}\nListenAddress 127.0.0.1\nHostKey {d}/host_ed25519\nHostKey {d}/host_ecdsa\n\
         PidFile {d}/sshd.pid\nAuthorizedKeysFile {d}/authorized_keys\nPasswordAuthentication no\n\
         KbdInteractiveAuthentication no\nPubkeyAuthentication yes\nUsePAM no\nStrictModes no\n\
         AllowTcpForwarding yes\nLogLevel ERROR\nPubkeyAcceptedAlgorithms {accepted}\n",
        d = path.display()
    );
    std::fs::write(path.join("sshd_config"), config).unwrap();
    let child = Command::new(sshd)
        .args(["-D", "-e", "-f"])
        .arg(path.join("sshd_config"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Sshd { child, dir, port }
}

fn user() -> String {
    std::env::var("USER").unwrap()
}

#[tokio::test]
#[ignore = "needs CONCORD_SSHD and CONCORD_SSH_KEYGEN, the system OpenSSH binaries"]
async fn talks_to_openssh() {
    let sshd = std::env::var("CONCORD_SSHD").expect("CONCORD_SSHD is not set");
    let keygen_binary = std::env::var("CONCORD_SSH_KEYGEN").expect("CONCORD_SSH_KEYGEN is not set");
    let server = start_sshd(&sshd, &keygen_binary, "+ssh-rsa").await;
    let target = echo_server().await;
    let path = server.dir.path();
    let read = |name: &str| std::fs::read_to_string(path.join(name)).unwrap();
    let user = user();

    for (label, key, passphrase) in [
        ("ed25519", "user_ed25519", ""),
        ("ecdsa", "user_ecdsa", ""),
        ("passphrase", "user_locked", "secret"),
    ] {
        let outbound = client(
            server.port,
            json!({"username": user, "private-key": read(key), "private-key-passphrase": passphrase}),
        )
        .unwrap();
        echo_through(&*outbound, target, 5)
            .await
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        echo_through(&*outbound, target, 300_000)
            .await
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        println!("openssh {label}: ok");
    }

    for (label, key, passphrase) in [
        ("rsa openssh", "user_rsa", ""),
        ("rsa openssh passphrase", "user_rsa_locked", "secret"),
        ("rsa pem", "user_rsa_pem", ""),
        ("rsa pem passphrase", "user_rsa_pem_locked", "secret"),
        ("rsa pkcs8", "user_rsa_pkcs8", ""),
    ] {
        let outbound = client(
            server.port,
            json!({"username": user, "private-key": read(key), "private-key-passphrase": passphrase}),
        )
        .unwrap_or_else(|e| panic!("{label}: {e}"));
        echo_through(&*outbound, target, 5)
            .await
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        echo_through(&*outbound, target, 300_000)
            .await
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        println!("openssh {label}: ok");
    }
    for accepted in ["rsa-sha2-256", "rsa-sha2-512"] {
        let only = start_sshd(&sshd, &keygen_binary, accepted).await;
        let read = |name: &str| std::fs::read_to_string(only.dir.path().join(name)).unwrap();
        let outbound = client(
            only.port,
            json!({"username": user, "private-key": read("user_rsa")}),
        )
        .unwrap();
        echo_through(&*outbound, target, 64)
            .await
            .unwrap_or_else(|e| panic!("{accepted}: {e}"));
        println!("openssh {accepted}: ok");
    }
    let sha1_only = start_sshd(&sshd, &keygen_binary, "ssh-rsa").await;
    let outbound = client(
        sha1_only.port,
        json!({"username": user, "private-key": read("user_rsa")}),
    )
    .unwrap();
    assert!(echo_through(&*outbound, target, 64).await.is_err());
    keygen_sized(&keygen_binary, 1024, &path.join("user_rsa_1024"));
    let small = client(server.port, json!({"private-key": read("user_rsa_1024")}));
    assert!(
        small
            .err()
            .is_some_and(|err| err.to_string().contains("2048 to 8192"))
    );
    for (label, key, passphrase) in [
        ("rsa pem without passphrase", "user_rsa_pem_locked", ""),
        ("rsa pem wrong passphrase", "user_rsa_pem_locked", "nope"),
        ("rsa pem unneeded passphrase", "user_rsa_pem", "secret"),
        ("rsa openssh without passphrase", "user_rsa_locked", ""),
    ] {
        let built = client(
            server.port,
            json!({"private-key": read(key), "private-key-passphrase": passphrase}),
        );
        assert!(built.is_err(), "{label}");
    }
    let rsa_algorithm = client(
        server.port,
        json!({"host-key-algorithms": ["rsa-sha2-256"]}),
    );
    assert!(rsa_algorithm.err().is_some_and(|err| err.is_unsupported()));

    let by_path = client(
        server.port,
        json!({"username": user, "private-key": path.join("user_ed25519").display().to_string()}),
    )
    .unwrap();
    echo_through(&*by_path, target, 64).await.unwrap();

    let host_ed = read("host_ed25519.pub");
    let host_ecdsa = read("host_ecdsa.pub");
    let key = read("user_ed25519");
    let pinned = client(
        server.port,
        json!({"username": user, "private-key": key, "host-key": [host_ed.trim()],
               "host-key-algorithms": ["ssh-ed25519"]}),
    )
    .unwrap();
    echo_through(&*pinned, target, 64).await.unwrap();

    let ecdsa_only = client(
        server.port,
        json!({"username": user, "private-key": key, "host-key": [host_ecdsa.trim()],
               "host-key-algorithms": ["ecdsa-sha2-nistp256"]}),
    )
    .unwrap();
    echo_through(&*ecdsa_only, target, 64).await.unwrap();

    let wrong = client(
        server.port,
        json!({"username": user, "private-key": key, "host-key": [host_ecdsa.trim()],
               "host-key-algorithms": ["ssh-ed25519"]}),
    )
    .unwrap();
    assert!(echo_through(&*wrong, target, 64).await.is_err());

    let stranger = client(
        server.port,
        json!({"username": "nobody-here", "private-key": key}),
    )
    .unwrap();
    assert!(echo_through(&*stranger, target, 64).await.is_err());

    let password_only = client(server.port, json!({"username": user, "password": "x"})).unwrap();
    assert!(echo_through(&*password_only, target, 64).await.is_err());

    let password_port = start_password_server(&read("host_ed25519")).await;
    let good = client(password_port, json!({"password": "hunter2"})).unwrap();
    echo_through(&*good, target, 5).await.unwrap();
    echo_through(&*good, target, 100_000).await.unwrap();
    let bad = client(password_port, json!({"password": "wrong"})).unwrap();
    assert!(echo_through(&*bad, target, 5).await.is_err());
    let key_then_password = client(
        password_port,
        json!({"private-key": key, "password": "hunter2"}),
    )
    .unwrap();
    echo_through(&*key_then_password, target, 64).await.unwrap();
}

struct PasswordServer(Arc<AtomicUsize>);

struct PasswordSession;

impl russh::server::Server for PasswordServer {
    type Handler = PasswordSession;

    fn new_client(&mut self, _peer: Option<std::net::SocketAddr>) -> PasswordSession {
        self.0.fetch_add(1, Ordering::SeqCst);
        PasswordSession
    }
}

impl russh::server::Handler for PasswordSession {
    type Error = russh::Error;

    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<russh::server::Auth, Self::Error> {
        if user == "tester" && password == "hunter2" {
            Ok(russh::server::Auth::Accept)
        } else {
            Ok(russh::server::Auth::reject())
        }
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: russh::Channel<russh::server::Msg>,
        host: &str,
        port: u32,
        _originator: &str,
        _originator_port: u32,
        reply: russh::server::ChannelOpenHandle,
        _session: &mut russh::server::Session,
    ) -> Result<(), Self::Error> {
        let Ok(mut upstream) =
            tokio::net::TcpStream::connect((host, u16::try_from(port).unwrap())).await
        else {
            reply.reject(russh::ChannelOpenFailure::ConnectFailed).await;
            return Ok(());
        };
        reply.accept().await;
        tokio::spawn(async move {
            let mut stream = channel.into_stream();
            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
        });
        Ok(())
    }
}

async fn start_password_server(host_key: &str) -> u16 {
    let key = russh::keys::decode_secret_key(host_key, None).unwrap();
    serve_passwords(key, Arc::default()).await
}

async fn serve_passwords(key: russh::keys::PrivateKey, accepted: Arc<AtomicUsize>) -> u16 {
    let config = russh::server::Config {
        keys: vec![key],
        auth_rejection_time: Duration::from_millis(10),
        auth_rejection_time_initial: Some(Duration::from_millis(10)),
        ..russh::server::Config::default()
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let config = Arc::new(config);
    tokio::spawn(async move {
        use russh::server::Server as _;
        let _ = PasswordServer(accepted)
            .run_on_socket(config, &listener)
            .await;
    });
    port
}

#[tokio::test]
async fn a_session_made_across_a_reset_is_not_kept() {
    let key = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[7; 32]);
    let accepted = Arc::new(AtomicUsize::new(0));
    let port = serve_passwords(key.into(), accepted.clone()).await;
    let target = echo_server().await;
    let outbound = client(port, json!({"server": "localhost", "password": "hunter2"})).unwrap();
    let held = HeldLookup::new();
    let straddling = {
        let (outbound, env) = (outbound.clone(), held.env());
        tokio::spawn(async move {
            let cx = DialCx::new(&env, Initiator::Direct, None);
            outbound
                .connect(&cx, &Address::new("127.0.0.1", target))
                .await
                .map(drop)
        })
    };
    held.entered().await;
    outbound.reset_sessions();
    held.release();
    let outcome = crate::testing::settled(straddling).await;
    echo_through(&*outbound, target, 5).await.unwrap();
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        2,
        "the next request went over the session made before the reset"
    );
    assert!(outcome.is_err());
}

/// Serves password sessions and reports how each ended: `Ok` when the client sent
/// SSH_MSG_DISCONNECT, an error when its connection just closed.
async fn serve_reporting() -> (u16, mpsc::UnboundedReceiver<Result<(), russh::Error>>) {
    let key = russh::keys::ssh_key::private::Ed25519Keypair::from_seed(&[9; 32]);
    let config = Arc::new(russh::server::Config {
        keys: vec![key.into()],
        ..russh::server::Config::default()
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (ended, report) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let (config, ended) = (config.clone(), ended.clone());
            tokio::spawn(async move {
                let outcome = match russh::server::run_stream(config, socket, PasswordSession).await
                {
                    Ok(session) => session.await,
                    Err(err) => Err(err),
                };
                let _ = ended.send(outcome);
            });
        }
    });
    (port, report)
}

#[tokio::test]
async fn a_session_a_reset_overtook_is_disconnected() {
    let (port, mut ended) = serve_reporting().await;
    let target = echo_server().await;
    let outbound = client(port, json!({"server": "localhost", "password": "hunter2"})).unwrap();
    let held = HeldLookup::new();
    let straddling = {
        let (outbound, env) = (outbound.clone(), held.env());
        tokio::spawn(async move {
            let cx = DialCx::new(&env, Initiator::Direct, None);
            outbound
                .connect(&cx, &Address::new("127.0.0.1", target))
                .await
                .map(drop)
        })
    };
    held.entered().await;
    outbound.reset_sessions();
    held.release();
    assert!(crate::testing::settled(straddling).await.is_err());
    let overtaken = tokio::time::timeout(Duration::from_secs(5), ended.recv()).await;
    assert!(overtaken.unwrap().unwrap().is_ok(), "no DISCONNECT arrived");
    echo_through(&*outbound, target, 5).await.unwrap();
    drop(outbound);
    let dropped = tokio::time::timeout(Duration::from_secs(5), ended.recv()).await;
    assert!(
        dropped.unwrap().unwrap().is_err(),
        "a session ended without DISCONNECT reads as one that sent it"
    );
}

#[tokio::test(start_paused = true)]
async fn a_disconnect_the_session_never_takes_ends_at_its_bound() {
    let started = tokio::time::Instant::now();
    super::bounded(std::future::pending()).await;
    assert_eq!(started.elapsed(), super::DISCONNECT_TIMEOUT);
}

#[test]
fn bad_key_material_is_reported_at_build_time() {
    assert!(client(1, json!({"private-key": "/no/such/key"})).is_err());
    assert!(
        client(1, json!({"private-key": "-----BEGIN OPENSSH PRIVATE KEY-----\nnope\n-----END OPENSSH PRIVATE KEY-----"}))
            .is_err()
    );
    assert!(client(1, json!({"host-key": ["not a key"]})).is_err());
    assert!(client(1, json!({"host-key-algorithms": ["no-such-algorithm"]})).is_err());
    assert!(client(1, json!({"password": "x"})).is_ok());
}

#[tokio::test]
async fn a_session_s_task_ends_when_its_outbound_is_dropped() {
    let (port, _ended) = serve_reporting().await;
    let target = echo_server().await;
    let tracked = crate::testing::Tracked::new();
    let outbound = tracked_client(port, &tracked);
    echo_through(&*outbound, target, 5).await.unwrap();
    assert!(tracked.running() > 0, "the session is not tracked");
    drop(outbound);
    assert!(tracked.ended_within(Duration::from_secs(5)).await);
}

#[tokio::test]
async fn a_disconnect_still_pending_ends_at_a_stop() {
    let tracked = crate::testing::Tracked::new();
    tracked
        .tasks
        .spawn_detached(super::bounded(std::future::pending()));
    tracked.stop();
    assert!(tracked.ended_within(Duration::from_secs(1)).await);
}
