mod conn;
mod frames;
mod tap;

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;

use concord_common::BoxStream;
use concord_common::sync::lock;
use concord_tls::{DecoyHandshake, TlsConnector, TlsOptions, TrustStore};
use rand::Rng;
use tokio::io::{AsyncRead, ReadBuf};

use self::conn::{HMAC_SIZE, new_hmac, v2_conn, v3_conn};
use self::tap::{HashingRead, Lent, V3State, V3Tap};
use crate::http1::invalid;

pub const DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];
pub const WS_ALPN: [&str; 1] = ["http/1.1"];

const SESSION_ID_OFFSET: usize = 39;
const SESSION_ID_LEN: usize = 32;

#[derive(Clone, Debug)]
pub struct ShadowTlsOptions {
    pub password: String,
    /// 0 selects version 2, as mihomo does.
    pub version: u8,
    /// `server_name` is the decoy host and `alpn` defaults to [`DEFAULT_ALPN`].
    pub tls: TlsOptions,
}

enum Handshake {
    V1(TlsConnector),
    Decoy(DecoyHandshake),
}

pub struct ShadowTlsClient {
    password: String,
    version: u8,
    handshake: Handshake,
}

impl ShadowTlsClient {
    pub fn new(options: ShadowTlsOptions, trust: Arc<TrustStore>) -> io::Result<Self> {
        let version = if options.version == 0 {
            2
        } else {
            options.version
        };
        if !(1..=3).contains(&version) {
            return Err(invalid(format!(
                "shadow-tls: unknown protocol version: {version}"
            )));
        }
        let mut tls = options.tls;
        if tls.alpn.is_empty() {
            tls.alpn = DEFAULT_ALPN.iter().map(|alpn| (*alpn).to_owned()).collect();
        }
        let handshake = if version == 1 {
            Handshake::V1(TlsConnector::tls12_only(tls, trust).map_err(io::Error::other)?)
        } else {
            // mihomo strips X25519MLKEM768 from v2's hello only; v2 does not work with it.
            Handshake::Decoy(
                DecoyHandshake::new(&tls, trust, version == 3).map_err(io::Error::other)?,
            )
        };
        Ok(ShadowTlsClient {
            password: options.password,
            version,
            handshake,
        })
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub async fn connect(&self, io: BoxStream, target_host: &str) -> io::Result<BoxStream> {
        let lent = Lent::new(io);
        match (&self.handshake, self.version) {
            (Handshake::V1(connector), _) => {
                let conn = connector
                    .connect(Box::new(lent.clone()), target_host)
                    .await?;
                drop(conn);
                lent.take()
            }
            (Handshake::Decoy(decoy), 2) => {
                let mac = Arc::new(Mutex::new(new_hmac(self.password.as_bytes())));
                let tap = HashingRead::new(lent.clone(), mac.clone());
                let (mut stream, _) = decoy
                    .run(Box::new(tap), target_host, &|_: &[u8]| random_session_id())
                    .await?;
                read_ready(&mut stream).await;
                drop(stream);
                let mut prefix = [0u8; 8];
                let digest = lock(&mac).sum();
                prefix.copy_from_slice(
                    digest
                        .get(..8)
                        .ok_or_else(|| invalid("shadow-tls: short digest"))?,
                );
                Ok(v2_conn(lent.take()?, prefix))
            }
            (Handshake::Decoy(decoy), _) => {
                let state = Arc::new(Mutex::new(V3State::default()));
                let tap = V3Tap::new(lent.clone(), &self.password, state.clone());
                let password = self.password.clone();
                let sealer = move |hello: &[u8]| seal_session_id(password.as_bytes(), hello);
                let (stream, _) = decoy.run(Box::new(tap), target_host, &sealer).await?;
                drop(stream);
                let (server_random, read_mac, authorized, leftover) = {
                    let state = lock(&state);
                    (
                        state.server_random,
                        state.read_mac.clone(),
                        state.authorized,
                        state.leftover,
                    )
                };
                if !authorized || leftover != 0 {
                    return Err(invalid("shadow-tls: traffic hijacked"));
                }
                let server_random =
                    server_random.ok_or_else(|| invalid("shadow-tls: no server random"))?;
                let mut add = new_hmac(self.password.as_bytes());
                add.update(&server_random);
                add.update(b"C");
                let mut verify = new_hmac(self.password.as_bytes());
                verify.update(&server_random);
                verify.update(b"S");
                Ok(v3_conn(lent.take()?, add, verify, read_mac))
            }
        }
    }
}

/// The server hashes every byte it wrote, session tickets included, and mihomo's own client
/// hashes whatever one socket read returned; a client that stops at the last record it parsed
/// would hash less than the server expects.
async fn read_ready(stream: &mut BoxStream) {
    let mut scratch = [0u8; 4096];
    std::future::poll_fn(|cx| {
        loop {
            let mut buf = ReadBuf::new(&mut scratch);
            match Pin::new(&mut *stream).poll_read(cx, &mut buf) {
                Poll::Ready(Ok(())) if !buf.filled().is_empty() => {}
                _ => return Poll::Ready(()),
            }
        }
    })
    .await;
}

fn random_session_id() -> io::Result<[u8; SESSION_ID_LEN]> {
    let mut id = [0u8; SESSION_ID_LEN];
    rand::rng().fill(&mut id);
    Ok(id)
}

fn seal_session_id(password: &[u8], hello: &[u8]) -> io::Result<[u8; SESSION_ID_LEN]> {
    let (Some(head), Some(tail)) = (
        hello.get(..SESSION_ID_OFFSET),
        hello.get(SESSION_ID_OFFSET + SESSION_ID_LEN..),
    ) else {
        return Err(invalid("shadow-tls: unexpected ClientHello length"));
    };
    let mut id = [0u8; SESSION_ID_LEN];
    let (random, zeros) = id.split_at_mut(SESSION_ID_LEN - HMAC_SIZE);
    rand::rng().fill(random);
    zeros.fill(0);
    let mut mac = new_hmac(password);
    mac.update(head);
    mac.update(random);
    mac.update(zeros);
    mac.update(tail);
    let digest = mac.sum();
    let tag = digest
        .get(..HMAC_SIZE)
        .ok_or_else(|| invalid("shadow-tls: short digest"))?;
    zeros.copy_from_slice(tag);
    Ok(id)
}
