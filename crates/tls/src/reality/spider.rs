use std::time::Duration;

use concord_common::Tasks;
use rustls_pki_types::ServerName;

use super::stream::RealityStream;

/// How a client whose peer turned out to be the cover site browses it.
#[derive(Clone)]
pub(crate) struct Browser {
    pub(crate) user_agent: &'static str,
    pub(crate) tasks: Tasks,
}

impl Browser {
    /// Browses briefly rather than hang up at once.
    pub(crate) fn spawn(&self, stream: RealityStream, host: String) {
        let browser = self.clone();
        self.tasks.spawn_detached(async move {
            let _ = browse(&browser, stream, host).await;
        });
    }

    pub(crate) async fn jls_fallback(&self, stream: RealityStream, name: &ServerName<'_>) {
        jls_fallback(stream, authority(name), self.user_agent, &self.tasks).await;
    }
}

async fn browse(browser: &Browser, stream: RealityStream, host: String) -> Option<()> {
    let user_agent = browser.user_agent;
    let (sender, connection) = h2::client::handshake(stream).await.ok()?;
    let _driver = AbortOnDrop(h2_driver(&browser.tasks, connection));
    let padding = "0".repeat(rand::random_range(30..62usize));
    let request = http::Request::builder()
        .method("GET")
        .uri(format!("https://{host}/"))
        .header("user-agent", user_agent)
        .header("cookie", format!("padding={padding}"))
        .header("accept-encoding", "gzip")
        .body(())
        .ok()?;
    let mut ready = sender.ready().await.ok()?;
    let (response, _) = ready.send_request(request, true).ok()?;
    let _ = response.await;
    tokio::time::sleep(Duration::from_secs(rand::random_range(5..15u64))).await;
    Some(())
}

async fn jls_fallback(
    mut stream: RealityStream,
    host: String,
    user_agent: &'static str,
    tasks: &Tasks,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let padding = "0".repeat(rand::random_range(30..62usize));
    if stream.negotiated_alpn() == Some(b"h2") {
        let Ok((sender, connection)) = h2::client::handshake(stream).await else {
            return;
        };
        let _driver = AbortOnDrop(h2_driver(tasks, connection));
        if let Ok(request) = http::Request::builder()
            .uri(format!("https://{host}/"))
            .header("user-agent", user_agent)
            .header("cookie", format!("padding={padding}"))
            .header("accept-encoding", "gzip")
            .body(())
            && let Ok(mut ready) = sender.ready().await
            && let Ok((response, _)) = ready.send_request(request, true)
        {
            let _ = response.await;
        }
    } else {
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {user_agent}\r\nCookie: padding={padding}\r\nAccept-Encoding: gzip\r\n\r\n"
        );
        if stream.write_all(request.as_bytes()).await.is_ok() && stream.flush().await.is_ok() {
            let mut tail = [0; 4];
            while let Ok(byte) = stream.read_u8().await {
                tail.rotate_left(1);
                tail[3] = byte;
                if tail == *b"\r\n\r\n" {
                    break;
                }
            }
        }
        let _ = stream.shutdown().await;
    }
}

fn h2_driver(
    tasks: &Tasks,
    connection: h2::client::Connection<RealityStream, bytes::Bytes>,
) -> tokio::task::JoinHandle<()> {
    tasks.spawn(async move {
        let _ = connection.await;
    })
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn authority(name: &ServerName<'_>) -> String {
    let host = name.to_str();
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.into_owned()
    }
}
