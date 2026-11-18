//! The Clash REST and WebSocket API (the "external controller") for dashboards.
//! Every route calls the same `concord_api::Control` a host calls and converts
//! the answer to the JSON mihomo's controller writes; the controller keeps no
//! state beyond its listener and the sessions on it.

mod http;
mod routes;
mod shapes;
mod stream;

use std::convert::Infallible;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use concord_api::{Control, ControllerCors, ControllerSettings};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use crate::routes::Routes;

/// After an accept error that is not about one connection, such as running out of file
/// descriptors, the wait starts here and doubles up to the cap.
const FIRST_ACCEPT_BACKOFF: Duration = Duration::from_millis(5);
const MAX_ACCEPT_BACKOFF: Duration = Duration::from_secs(1);

/// Serves the controller wherever `Control::external_controller` says, and
/// moves it when that changes. With no address it opens nothing.
pub async fn serve(control: Arc<Control>) {
    let mut settings = control.external_controller();
    loop {
        let current = settings.borrow_and_update().clone();
        if !current.address.is_empty() {
            match TcpListener::bind(listen_address(&current.address)).await {
                Ok(listener) => {
                    tokio::select! {
                        () = run(control.clone(), listener, &current) => {}
                        changed = settings.changed() => {
                            if changed.is_err() {
                                return;
                            }
                            continue;
                        }
                    }
                }
                Err(err) => tracing::error!("External controller listen error: {err}"),
            }
        }
        if settings.changed().await.is_err() {
            return;
        }
    }
}

/// Go reads `:9090` as every interface.
fn listen_address(address: &str) -> String {
    if address.starts_with(':') {
        format!("0.0.0.0{address}")
    } else {
        address.to_string()
    }
}

/// Runs until it is dropped, which also ends every session it started.
async fn run(control: Arc<Control>, listener: TcpListener, settings: &ControllerSettings) {
    let local = listener.local_addr().ok();
    if let Some(local) = local {
        tracing::info!("RESTful API listening at: {local}");
        if settings.secret.is_empty() && !local.ip().is_loopback() {
            tracing::warn!(
                "the external controller at {local} has no secret, so anyone who can reach it controls the core"
            );
        }
    }
    let stop = CancellationToken::new();
    let _guard = stop.clone().drop_guard();
    let routes = Arc::new(Routes {
        control,
        stop: stop.clone(),
    });
    let secret: Arc<str> = Arc::from(settings.secret.as_str());
    let cors = Arc::new(settings.cors.clone());
    let mut backoff = Duration::ZERO;
    loop {
        let (socket, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(err) if connection_error(&err) => continue,
            Err(err) => {
                backoff = (backoff * 2).clamp(FIRST_ACCEPT_BACKOFF, MAX_ACCEPT_BACKOFF);
                tracing::warn!("external controller accept: {err}; retrying in {backoff:?}");
                tokio::time::sleep(backoff).await;
                continue;
            }
        };
        backoff = Duration::ZERO;
        let (routes, secret, cors, stop) =
            (routes.clone(), secret.clone(), cors.clone(), stop.clone());
        tokio::spawn(async move {
            let service = service_fn(move |request| {
                let (routes, secret, cors) = (routes.clone(), secret.clone(), cors.clone());
                async move { Ok::<_, Infallible>(answer(&routes, &secret, &cors, request).await) }
            });
            // mihomo's and sing-box's controllers set no ReadHeaderTimeout; hyper's default is 30 s.
            let connection = http1::Builder::new()
                .header_read_timeout(None)
                .serve_connection(TokioIo::new(socket), service)
                .with_upgrades();
            tokio::select! {
                _ = connection => {}
                () = stop.cancelled() => {}
            }
        });
    }
}

fn connection_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::ConnectionRefused
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
    )
}

async fn answer(
    routes: &Routes,
    secret: &str,
    cors: &ControllerCors,
    request: ::http::Request<hyper::body::Incoming>,
) -> ::http::Response<http::Body> {
    let method = request.method().clone();
    let headers = request.headers().clone();
    if http::is_preflight(&method, &headers) {
        return http::preflight(&headers, cors);
    }
    let mut response = if http::authorized(secret, &headers, request.uri()) {
        routes.handle(request).await
    } else {
        http::unauthorized()
    };
    http::cors(&headers, &method, cors, &mut response);
    response
}
