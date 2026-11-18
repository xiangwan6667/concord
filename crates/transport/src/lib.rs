#![deny(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

mod gost_plugin;
mod gun;
mod h2_transport;
pub mod h2io;
mod http1;
mod http_obfs;
mod outgoing;
mod session_socket;
mod shadowtls;
mod simple_obfs;
mod singmux;
mod v2ray_plugin;
pub mod ws;
mod xhttp;

use std::io;
use std::sync::Arc;

use concord_common::{BoxStream, Tasks};
use concord_tls::TlsConnector;
use futures_util::future::BoxFuture;

pub use gun::{GrpcOptions, GunClient};
pub use h2_transport::H2Options;
pub use http_obfs::HttpOptions;
pub use session_socket::SessionSocket;
pub use shadowtls::{DEFAULT_ALPN, ShadowTlsClient, ShadowTlsOptions, WS_ALPN};
pub use simple_obfs::{ObfsMode, ObfsOptions};
pub use singmux::{
    Brutal, MuxDialFn, MuxProtocol, PacketReader, PacketWriter, SingMuxClient, SingMuxOptions,
};
pub use v2ray_plugin::V2rayPluginOptions;
pub use ws::WsOptions;
pub use xhttp::{QuicDialFn, XhttpClient, XhttpDial, XhttpDownload, XhttpOptions, XhttpReuse};

pub type DialFn = Arc<dyn Fn() -> BoxFuture<'static, io::Result<BoxStream>> + Send + Sync>;

/// For layers that dial for themselves (`Grpc`, `Xhttp`): each stream from
/// `dial` goes through TLS, held whole by the layer's HTTP client, and
/// `required_alpn` rejects a server that picked another protocol than the layer
/// speaks.
pub fn tls_dial(
    dial: DialFn,
    connector: Arc<TlsConnector>,
    host: String,
    required_alpn: Option<&'static str>,
) -> DialFn {
    Arc::new(move || {
        let dial = dial.clone();
        let connector = connector.clone();
        let host = host.clone();
        Box::pin(async move {
            let conn = connector.connect_whole_dialing(|| dial(), &host).await?;
            if let Some(required) = required_alpn
                && conn.negotiated_alpn() != Some(required.as_bytes())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("server did not negotiate ALPN {required}"),
                ));
            }
            Ok(Box::new(conn) as BoxStream)
        })
    })
}

/// `dial` with the ShadowTLS handshake run on each new connection.
pub fn shadow_tls_dial(dial: DialFn, client: Arc<ShadowTlsClient>, host: String) -> DialFn {
    Arc::new(move || {
        let dial = dial.clone();
        let client = client.clone();
        let host = host.clone();
        Box::pin(async move { client.connect(dial().await?, &host).await })
    })
}

#[derive(Clone)]
pub enum Layer {
    Ws(WsOptions),
    /// Dials for itself, so it ignores any stream handed to `apply`.
    Grpc(Arc<GunClient>),
    H2(H2Options),
    /// Dials for itself, like `Grpc`.
    Xhttp(Arc<XhttpClient>),
    Http(HttpOptions),
    SimpleObfs(ObfsOptions),
    V2rayPlugin(V2rayPluginOptions),
    GostPlugin(V2rayPluginOptions),
    /// One smux v1 stream with its own session.
    Smux,
    Tls(Arc<TlsConnector>),
    ShadowTls(Arc<ShadowTlsClient>),
}

#[derive(Clone)]
pub struct TransportStack {
    layers: Vec<Layer>,
    tasks: Tasks,
}

impl TransportStack {
    pub fn new(layers: Vec<Layer>, tasks: Tasks) -> Self {
        TransportStack { layers, tasks }
    }

    pub fn layers(&self) -> &[Layer] {
        &self.layers
    }

    pub fn tasks(&self) -> &Tasks {
        &self.tasks
    }

    /// The stack with `layer` first, under the others.
    pub fn under(self, layer: Layer) -> Self {
        let mut layers = Vec::with_capacity(self.layers.len() + 1);
        layers.push(layer);
        layers.extend(self.layers);
        TransportStack {
            layers,
            tasks: self.tasks,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    pub fn owns_dial(&self) -> bool {
        matches!(self.layers.first(), Some(Layer::Grpc(_) | Layer::Xhttp(_)))
    }

    pub async fn apply(&self, io: BoxStream, target_host: &str) -> io::Result<BoxStream> {
        self.run(Some(io), target_host).await
    }

    pub async fn apply_owned(&self, target_host: &str) -> io::Result<BoxStream> {
        self.run(None, target_host).await
    }

    async fn run(&self, mut io: Option<BoxStream>, target_host: &str) -> io::Result<BoxStream> {
        for layer in &self.layers {
            let stream = match (layer, io.take()) {
                (Layer::Grpc(client), _) => client.dial().await?,
                (Layer::Xhttp(client), _) => client.dial().await?,
                (_, None) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "the stack has no stream to build on",
                    ));
                }
                (Layer::Ws(opts), Some(stream)) => {
                    ws::apply(stream, opts, target_host, &self.tasks).await?
                }
                (Layer::H2(opts), Some(stream)) => {
                    h2_transport::connect(stream, opts, &self.tasks).await?
                }
                (Layer::Http(opts), Some(stream)) => http_obfs::wrap(stream, opts, target_host),
                (Layer::SimpleObfs(opts), Some(stream)) => simple_obfs::wrap(stream, opts),
                (Layer::V2rayPlugin(opts), Some(stream)) => {
                    v2ray_plugin::apply(stream, opts, &self.tasks).await?
                }
                (Layer::GostPlugin(opts), Some(stream)) => {
                    gost_plugin::apply(stream, opts, &self.tasks).await?
                }
                (Layer::Smux, Some(stream)) => singmux::smux_stream(stream, &self.tasks).await?,
                (Layer::Tls(connector), Some(stream)) => {
                    Box::new(connector.connect_unaligned(stream, target_host).await?)
                }
                (Layer::ShadowTls(client), Some(stream)) => {
                    client.connect(stream, target_host).await?
                }
            };
            io = Some(stream);
        }
        io.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "the stack has no stream to return",
            )
        })
    }
}
