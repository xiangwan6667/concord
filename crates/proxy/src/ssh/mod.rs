mod rsa_key;
#[cfg(test)]
mod tests;

use std::borrow::Cow;
use std::future::Future;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use base64::Engine;
use concord_common::{
    Address, BoxStream, CoreError, DialCx, Outbound, OutboundInfo, OutboundKind, PacketSession,
    Tasks,
};
use concord_config::proxy::{ProxyDef, SshOpts};
use russh::client::{self, Handle, Handler};
use russh::keys::ssh_key::EcdsaCurve;
use russh::keys::ssh_key::HashAlg;
use russh::keys::ssh_key::private::KeypairData;
use russh::keys::{
    Algorithm, PrivateKey, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate,
    decode_secret_key,
};
use russh::{Preferred, SshId};
use tokio::sync::{Mutex, oneshot};

use self::rsa_key::{RsaSigner, Sign};
use crate::ctx::{BuildCtx, BuildError};
use crate::node::{Link, info_for};
use crate::session_slot::SessionSlot;

enum Key {
    Plain(Arc<PrivateKey>),
    Rsa(Box<RsaSigner>),
}

/// russh runs the session in a task of its own and drops the handler when that task ends, so
/// `ended` closing is how the engine waits for it.
struct HostKeys {
    keys: Vec<Vec<u8>>,
    _ended: oneshot::Sender<()>,
}

impl Handler for HostKeys {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        if self.keys.is_empty() {
            return Ok(true);
        }
        let (algorithm, offered) = match key {
            PublicKeyOrCertificate::PublicKey { key, .. } => (key.algorithm(), key.to_bytes()),
            PublicKeyOrCertificate::Certificate(cert) => (cert.algorithm(), cert.to_bytes()),
        };
        let offered = offered.unwrap_or_default();
        if self.keys.contains(&offered) {
            return Ok(true);
        }
        Err(russh::Error::IO(io::Error::other(format!(
            "host key mismatch, server send :{} {}",
            algorithm.as_str(),
            base64::engine::general_purpose::STANDARD.encode(&offered),
        ))))
    }
}

struct Ssh {
    info: OutboundInfo,
    link: Link,
    username: String,
    password: String,
    key: Option<Key>,
    host_keys: Vec<Vec<u8>>,
    config: Arc<client::Config>,
    session: SessionSlot<Handle<HostKeys>>,
    connecting: Mutex<()>,
    tasks: Tasks,
}

fn auth_error(err: russh::Error) -> io::Error {
    io::Error::other(format!("ssh: {err}"))
}

/// mihomo dials a node, SSH's session included, under the tunnel's DefaultTCPTimeout; a
/// DISCONNECT that cannot be queued in that time is dropped with the session.
const DISCONNECT_TIMEOUT: Duration = Duration::from_secs(5);

async fn bounded(teardown: impl Future<Output = ()>) {
    let _ = tokio::time::timeout(DISCONNECT_TIMEOUT, teardown).await;
}

impl Ssh {
    fn disconnect_later(&self, handle: Arc<Handle<HostKeys>>) {
        self.tasks.spawn_detached(bounded(async move {
            let _ = handle
                .disconnect(russh::Disconnect::ByApplication, "", "")
                .await;
        }));
    }

    async fn handle(&self, cx: &DialCx<'_>) -> io::Result<Arc<Handle<HostKeys>>> {
        self.session
            .offer(
                &self.connecting,
                |handle| !handle.is_closed(),
                || self.establish(cx),
                |handle| self.disconnect_later(handle),
            )
            .await
    }

    async fn establish(&self, cx: &DialCx<'_>) -> io::Result<Arc<Handle<HostKeys>>> {
        let raw = self.link.open(cx).await?;
        let (ended, session_ended) = oneshot::channel();
        self.tasks.spawn_to_end(async move {
            let _ = session_ended.await;
        });
        let keys = HostKeys {
            keys: self.host_keys.clone(),
            _ended: ended,
        };
        let mut handle = client::connect_stream(self.config.clone(), raw, keys)
            .await
            .map_err(auth_error)?;
        // Go's client opens with a "none" request, so a server that needs no credentials
        // lets a mihomo node in without a key or password.
        let mut authenticated = handle
            .authenticate_none(self.username.clone())
            .await
            .map_err(auth_error)?
            .success();
        match self.key.as_ref().filter(|_| !authenticated) {
            Some(Key::Plain(key)) => {
                let result = handle
                    .authenticate_publickey(
                        self.username.clone(),
                        PrivateKeyWithHashAlg::new(key.clone(), None),
                    )
                    .await
                    .map_err(auth_error)?;
                authenticated = result.success();
            }
            Some(Key::Rsa(key)) => {
                let hash = match handle.best_supported_rsa_hash().await.map_err(auth_error)? {
                    Some(Some(hash)) => hash,
                    None => HashAlg::Sha256,
                    Some(None) => {
                        return Err(io::Error::other(
                            "ssh: the server accepts only SHA-1 RSA signatures, which are not supported",
                        ));
                    }
                };
                let result = handle
                    .authenticate_publickey_with(
                        self.username.clone(),
                        key.public(),
                        Some(hash),
                        &mut Sign { key, hash },
                    )
                    .await
                    .map_err(|err| io::Error::other(format!("ssh: {err}")))?;
                authenticated = result.success();
            }
            None => {}
        }
        if !authenticated && !self.password.is_empty() {
            let result = handle
                .authenticate_password(self.username.clone(), self.password.clone())
                .await
                .map_err(auth_error)?;
            authenticated = result.success();
        }
        if !authenticated {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "ssh: unable to authenticate",
            ));
        }
        Ok(Arc::new(handle))
    }
}

#[async_trait]
impl Outbound for Ssh {
    fn info(&self) -> &OutboundInfo {
        &self.info
    }

    async fn connect(&self, cx: &DialCx<'_>, dst: &Address) -> io::Result<BoxStream> {
        let handle = self.handle(cx).await?;
        let host = match dst {
            Address::Domain(host, _) => host.to_string(),
            Address::Socket(addr) => addr.ip().to_string(),
        };
        let channel = handle
            .channel_open_direct_tcpip(host, u32::from(dst.port()), "127.0.0.1", 0)
            .await
            .map_err(|err| io::Error::other(format!("ssh: {err}")))?;
        Ok(Box::new(Forwarded {
            stream: channel.into_stream(),
        }))
    }

    async fn associate(
        &self,
        _cx: &DialCx<'_>,
        _hint: &Address,
    ) -> io::Result<Arc<dyn PacketSession>> {
        Err(CoreError::UdpUnsupported(self.info.name.to_string()).into())
    }

    fn reset_sessions(&self) {
        self.session.reset();
    }
}

struct Forwarded<S> {
    stream: S,
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Forwarded<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Forwarded<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, data)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>
    concord_common::Stream for Forwarded<S>
{
}

fn load_key(opts: &SshOpts, ctx: &BuildCtx) -> Result<Key, BuildError> {
    let text = if opts.private_key.contains("PRIVATE KEY") {
        opts.private_key.clone()
    } else {
        std::fs::read_to_string(ctx.resolve_file(&opts.private_key)?).map_err(|err| {
            BuildError::invalid(format!("ssh private-key {}: {err}", opts.private_key))
        })?
    };
    let passphrase =
        (!opts.private_key_passphrase.is_empty()).then_some(opts.private_key_passphrase.as_str());
    let invalid = |err: String| BuildError::invalid(format!("ssh private-key: {err}"));
    if let Some(rsa) = rsa_key::from_pem(&text, passphrase).map_err(invalid)? {
        return Ok(Key::Rsa(Box::new(rsa)));
    }
    let key = decode_secret_key(&text, passphrase).map_err(|err| invalid(err.to_string()))?;
    if let KeypairData::Rsa(pair) = key.key_data() {
        return RsaSigner::from_openssh(pair)
            .map(|signer| Key::Rsa(Box::new(signer)))
            .map_err(invalid);
    }
    Ok(Key::Plain(Arc::new(key)))
}

fn host_keys(opts: &SshOpts) -> Result<Vec<Vec<u8>>, BuildError> {
    opts.host_key
        .iter()
        .map(|text| {
            let key = PublicKey::from_openssh(text.trim())
                .map_err(|err| BuildError::invalid(format!("parse host key: {err}")))?;
            if key.algorithm().is_rsa() {
                return Err(BuildError::unsupported(
                    "ssh RSA host keys are not implemented yet",
                ));
            }
            key.to_bytes()
                .map_err(|err| BuildError::invalid(format!("parse host key: {err}")))
        })
        .collect()
}

fn algorithms(names: &[String]) -> Result<Vec<Algorithm>, BuildError> {
    names
        .iter()
        .map(|name| {
            let algorithm = Algorithm::new(name).map_err(|_| {
                BuildError::invalid(format!("ssh: unknown host key algorithm {name}"))
            })?;
            if algorithm.clone().is_rsa() {
                return Err(BuildError::unsupported(
                    "ssh RSA host keys are not implemented yet",
                ));
            }
            Ok(algorithm)
        })
        .collect()
}

/// Go's `defaultHostKeyAlgos`, which mihomo leaves in place: ECDSA before Ed25519, so a
/// server with both shows the key a mihomo user pinned. RSA is left out until its host
/// keys can be verified.
/// Go's `defaultKexAlgos`, `defaultCiphers` and `defaultMACs`, so a server mihomo reaches
/// with group14-sha1, ECDH or AES-GCM is reached here too. The extension names are not
/// algorithms; russh announces ext-info-c and strict kex through them.
const KEX_ORDER: &[russh::kex::Name] = &[
    russh::kex::MLKEM768X25519_SHA256,
    russh::kex::CURVE25519,
    russh::kex::ECDH_SHA2_NISTP256,
    russh::kex::ECDH_SHA2_NISTP384,
    russh::kex::ECDH_SHA2_NISTP521,
    russh::kex::DH_G14_SHA256,
    russh::kex::DH_G14_SHA1,
    russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
    russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
];

const CIPHER_ORDER: &[russh::cipher::Name] = &[
    russh::cipher::AES_128_GCM,
    russh::cipher::AES_256_GCM,
    russh::cipher::CHACHA20_POLY1305,
    russh::cipher::AES_128_CTR,
    russh::cipher::AES_192_CTR,
    russh::cipher::AES_256_CTR,
];

const MAC_ORDER: &[russh::mac::Name] = &[
    russh::mac::HMAC_SHA256_ETM,
    russh::mac::HMAC_SHA512_ETM,
    russh::mac::HMAC_SHA256,
    russh::mac::HMAC_SHA512,
    russh::mac::HMAC_SHA1,
];

const HOST_KEY_ORDER: &[Algorithm] = &[
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP256,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP384,
    },
    Algorithm::Ecdsa {
        curve: EcdsaCurve::NistP521,
    },
    Algorithm::Ed25519,
];

fn client_id() -> SshId {
    let minor = if rand::random_range(0..2) == 0 {
        format!("7.{}", rand::random_range(0..10))
    } else {
        format!("8.{}", rand::random_range(0..9))
    };
    SshId::Standard(format!("SSH-2.0-OpenSSH_{minor}").into())
}

pub(crate) fn build(
    def: &ProxyDef,
    opts: &SshOpts,
    ctx: &BuildCtx,
) -> Result<Arc<dyn Outbound>, BuildError> {
    let key = if opts.private_key.is_empty() {
        None
    } else {
        Some(load_key(opts, ctx)?)
    };
    let preferred = Preferred {
        key: if opts.host_key_algorithms.is_empty() {
            Cow::Borrowed(HOST_KEY_ORDER)
        } else {
            Cow::Owned(algorithms(&opts.host_key_algorithms)?)
        },
        kex: Cow::Borrowed(KEX_ORDER),
        cipher: Cow::Borrowed(CIPHER_ORDER),
        mac: Cow::Borrowed(MAC_ORDER),
        ..Preferred::default()
    };
    let config = client::Config {
        client_id: client_id(),
        preferred,
        nodelay: true,
        ..client::Config::default()
    };
    let link = Link::plain(def, &opts.server, opts.port, &ctx.tasks);
    Ok(Arc::new(Ssh {
        info: info_for(def, OutboundKind::Ssh, &opts.server, opts.port, false),
        link,
        username: opts.username.clone(),
        password: opts.password.clone(),
        key,
        host_keys: host_keys(opts)?,
        config: Arc::new(config),
        session: SessionSlot::default(),
        connecting: Mutex::new(()),
        tasks: ctx.tasks.clone(),
    }))
}
