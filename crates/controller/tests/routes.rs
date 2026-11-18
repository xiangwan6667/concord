#![allow(
    clippy::disallowed_methods,
    reason = "the dashboards here are the outside world, not the core's own sockets"
)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use concord_api::sync::lock;
use concord_api::{Control, ControlOptions, ControlService, Delivery, EventBus};
use concord_engine::{Engine, EngineConfig};
use concord_platform::NativePlatform;
use concord_proto::types::*;
use concord_test_support::free_port;
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const PATIENCE: Duration = Duration::from_secs(10);

const PROFILE: &str = "mixed-port: 0
proxies:
  - {name: local, type: socks5, server: 127.0.0.1, port: 1}
proxy-groups:
  - {name: G, type: select, proxies: [DIRECT, local, REJECT]}
  - {name: auto, type: url-test, proxies: [DIRECT, local], url: 'http://127.0.0.1:1/', lazy: true}
rules:
  - DOMAIN-SUFFIX,example.test,REJECT
  - MATCH,G
";

struct Rig {
    control: Arc<Control>,
    port: u16,
    secret: &'static str,
    _dir: tempfile::TempDir,
}

impl Rig {
    async fn new(profile_controller: bool) -> Rig {
        Rig::with_profile(profile_controller, PROFILE).await
    }

    async fn with_profile(profile_controller: bool, profile: &str) -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let bus = EventBus::new();
        let engine = Engine::new(EngineConfig {
            sink: bus.clone(),
            android: false,
            platform: Arc::new(NativePlatform::new()),
        });
        let control = Control::new(
            engine,
            bus,
            ControlOptions {
                profile_controller,
                ..ControlOptions::default()
            },
        );
        control
            .core_init(CoreInitParams {
                home: dir.path().to_str().unwrap().to_string(),
                sdk_int: None,
            })
            .await
            .unwrap();
        let port = free_port();
        let secret = "s3cret";
        let mut profile = profile.to_string();
        if profile_controller {
            profile.push_str(&format!(
                "external-controller: 127.0.0.1:{port}\nsecret: {secret}\n"
            ));
        }
        std::fs::write(dir.path().join("config.yaml"), profile).unwrap();
        control
            .config_apply(ConfigApplyParams::default())
            .await
            .unwrap();
        tokio::spawn(concord_controller::serve(control.clone()));
        let rig = Rig {
            control,
            port,
            secret,
            _dir: dir,
        };
        if profile_controller {
            rig.control.adopt_profile_controller().await;
        } else {
            rig.listen(port).await;
        }
        rig.wait_open(port).await;
        rig
    }

    async fn listen(&self, port: u16) {
        self.control
            .config_patch(ConfigPatchParams {
                external_controller: Some(format!("127.0.0.1:{port}")),
                secret: Some(self.secret.to_string()),
                ..ConfigPatchParams::default()
            })
            .await
            .unwrap();
    }

    async fn wait_open(&self, port: u16) {
        for _ in 0..200 {
            if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the controller did not open {port}");
    }

    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> Reply {
        let auth = format!("Bearer {}", self.secret);
        raw(self.port, method, path, &[("Authorization", &auth)], body).await
    }
}

struct Reply {
    status: u16,
    head: String,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|_| panic!("not JSON: {}", self.body))
    }
}

async fn raw(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> Reply {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let body = body.map(|body| body.to_string()).unwrap_or_default();
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(&body);
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    timeout(PATIENCE, stream.read_to_end(&mut bytes))
        .await
        .expect("the reply did not end")
        .unwrap();
    let text = String::from_utf8(bytes).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    let status = head.split(' ').nth(1).unwrap().parse().unwrap();
    Reply {
        status,
        head: head.to_ascii_lowercase(),
        body: body.to_string(),
    }
}

/// The first JSON line of a chunked push.
async fn first_line(port: u16, path: &str, secret: &str) -> Value {
    let stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut reader = BufReader::new(stream);
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {secret}\r\n\r\n");
    reader
        .get_mut()
        .write_all(request.as_bytes())
        .await
        .unwrap();
    let mut line = String::new();
    loop {
        line.clear();
        timeout(PATIENCE, reader.read_line(&mut line))
            .await
            .expect("no line arrived")
            .unwrap();
        if line.trim_start().starts_with('{') {
            return serde_json::from_str(line.trim()).unwrap();
        }
    }
}

async fn state_events(control: &Control) -> concord_api::EventStream<CoreEvent> {
    control
        .events_watch(EventsWatchParams {
            state: true,
            ..EventsWatchParams::default()
        })
        .await
        .unwrap()
        .events
}

async fn next_change(
    events: &mut concord_api::EventStream<CoreEvent>,
) -> (ChangeOrigin, StateChangeKind) {
    loop {
        match timeout(PATIENCE, events.next()).await {
            Ok(Some(Delivery::Event {
                data: CoreEvent::StateChanged { origin, change, .. },
                ..
            })) => return (origin, change),
            Ok(Some(Delivery::Event { .. })) => {}
            other => panic!("no state change: {:?}", other.map(|item| item.is_some())),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_secret_guards_every_route_and_a_websocket_may_pass_it_as_a_token() {
    let rig = Rig::new(false).await;
    let open = raw(rig.port, "GET", "/", &[], None).await;
    assert_eq!(open.status, 401);
    assert_eq!(open.json(), json!({ "message": "Unauthorized" }));
    let hello = rig.call("GET", "/", None).await;
    assert_eq!(hello.json(), json!({ "hello": "concord" }));
    let version = rig.call("GET", "/version", None).await.json();
    assert_eq!(version["meta"], true);
    assert!(version["version"].as_str().unwrap().starts_with('v'));

    let url = format!("ws://127.0.0.1:{}/memory?token={}", rig.port, rig.secret);
    let (mut socket, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    let first = timeout(PATIENCE, socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let first: Value = serde_json::from_str(first.to_text().unwrap()).unwrap();
    assert_eq!(first, json!({ "inuse": 0, "oslimit": 0 }));
    let refused = format!("ws://127.0.0.1:{}/memory?token=wrong", rig.port);
    assert!(tokio_tungstenite::connect_async(refused).await.is_err());
    rig.control.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_preflight_needs_no_secret_and_gets_mihomos_cors() {
    let rig = Rig::new(false).await;
    let reply = raw(
        rig.port,
        "OPTIONS",
        "/proxies",
        &[
            ("Origin", "http://board"),
            ("Access-Control-Request-Method", "PUT"),
            ("Access-Control-Request-Headers", "authorization"),
        ],
        None,
    )
    .await;
    assert_eq!(reply.status, 200);
    assert!(reply.head.contains("access-control-allow-origin: *"));
    assert!(reply.head.contains("access-control-allow-methods: put"));
    let actual = raw(rig.port, "GET", "/", &[("Origin", "http://board")], None).await;
    assert!(actual.head.contains("access-control-allow-origin: *"));
    rig.control.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_host_that_lists_origins_lets_only_those_call_from_a_browser() {
    let rig = Rig::new(false).await;
    // A settings change drops the listener with every connection it accepted and binds again,
    // so once this one ends, the next connection can only reach the new listener.
    let mut held = TcpStream::connect(("127.0.0.1", rig.port)).await.unwrap();
    rig.control
        .config_patch(ConfigPatchParams {
            external_controller_cors: Some(ControllerCorsPatch {
                allow_origins: Some(vec!["http://board".into()]),
                allow_private_network: None,
            }),
            ..ConfigPatchParams::default()
        })
        .await
        .unwrap();
    let ended = timeout(PATIENCE, held.read(&mut [0; 1]))
        .await
        .expect("the old listener stayed up");
    assert!(!matches!(ended, Ok(1..)), "{ended:?}");
    rig.wait_open(rig.port).await;
    let listed = from_origin(&rig, "http://board").await;
    assert!(
        listed
            .head
            .contains("access-control-allow-origin: http://board")
    );
    let other = from_origin(&rig, "http://other").await;
    assert!(!other.head.contains("access-control-allow-origin"));
    rig.control.shutdown().await;
}

const LISTED_CORS: &str =
    "external-controller-cors: {allow-origins: ['http://board'], allow-private-network: false}\n";

async fn from_origin(rig: &Rig, origin: &str) -> Reply {
    raw(rig.port, "GET", "/", &[("Origin", origin)], None).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_core_on_its_own_takes_the_allowed_origins_from_its_profile() {
    let rig = Rig::with_profile(true, &format!("{PROFILE}{LISTED_CORS}")).await;
    let listed = from_origin(&rig, "http://board").await;
    assert!(
        listed
            .head
            .contains("access-control-allow-origin: http://board")
    );
    let other = from_origin(&rig, "http://other").await;
    assert!(!other.head.contains("access-control-allow-origin"));
    rig.control.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_embedded_core_ignores_the_profiles_allowed_origins_with_a_warning() {
    let rig = Rig::with_profile(false, &format!("{PROFILE}{LISTED_CORS}")).await;
    let applied = rig
        .control
        .config_apply(ConfigApplyParams::default())
        .await
        .unwrap();
    assert!(
        applied.warnings.iter().any(|warning| {
            warning.code.as_deref() == Some("host_owned_key")
                && warning.path == "external-controller-cors"
        }),
        "{:?}",
        applied.warnings
    );
    let other = from_origin(&rig, "http://other").await;
    assert!(other.head.contains("access-control-allow-origin: *"));
    rig.control.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxies_list_groups_and_nodes_and_a_pick_reaches_the_host_as_a_change() {
    let rig = Rig::new(false).await;
    let proxies = rig.call("GET", "/proxies", None).await.json();
    let group = &proxies["proxies"]["G"];
    assert_eq!(group["type"], "Selector");
    assert_eq!(group["now"], "DIRECT");
    assert_eq!(group["all"], json!(["DIRECT", "local", "REJECT"]));
    assert_eq!(proxies["proxies"]["local"]["type"], "Socks5");
    assert!(proxies["proxies"]["local"]["history"].is_array());
    assert!(proxies["proxies"]["GLOBAL"].is_object());
    assert_eq!(rig.call("GET", "/proxies/nope", None).await.status, 404);

    let mut events = state_events(&rig.control).await;
    let put = rig
        .call("PUT", "/proxies/G", Some(json!({ "name": "REJECT" })))
        .await;
    assert_eq!(put.status, 204);
    assert_eq!(
        next_change(&mut events).await,
        (
            ChangeOrigin::Controller,
            StateChangeKind::Selected {
                group: "G".into(),
                proxy: "REJECT".into()
            }
        )
    );
    assert_eq!(
        rig.call("GET", "/proxies/G", None).await.json()["now"],
        "REJECT"
    );
    let general = rig.control.config_general(Empty {}).await.unwrap();
    assert_eq!(
        general.selections.get("G").map(String::as_str),
        Some("REJECT")
    );

    let leaf = rig
        .call("PUT", "/proxies/local", Some(json!({ "name": "x" })))
        .await;
    assert_eq!(leaf.status, 400);
    assert_eq!(leaf.json(), json!({ "message": "Must be a Selector" }));
    let missing = rig
        .call("PUT", "/proxies/G", Some(json!({ "name": "nope" })))
        .await;
    assert_eq!(missing.status, 400);

    let groups = rig.call("GET", "/group", None).await.json();
    let names: Vec<&str> = groups["proxies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|group| group["name"].as_str().unwrap())
        .collect();
    assert!(names.contains(&"G") && names.contains(&"auto") && !names.contains(&"local"));
    assert_eq!(rig.call("GET", "/group/local", None).await.status, 404);
    rig.control.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delay_test_answers_as_mihomo_does() {
    let rig = Rig::new(false).await;
    let missing_timeout = rig
        .call("GET", "/proxies/local/delay?url=http://127.0.0.1:1/", None)
        .await;
    assert_eq!(missing_timeout.status, 400);
    let failed = rig
        .call(
            "GET",
            "/proxies/local/delay?url=http%3A%2F%2F127.0.0.1%3A1%2F&timeout=500",
            None,
        )
        .await;
    assert!(
        failed.status == 503 || failed.status == 504,
        "{}",
        failed.status
    );
    let group = rig
        .call(
            "GET",
            "/group/auto/delay?url=http://127.0.0.1:1/&timeout=500",
            None,
        )
        .await;
    assert_eq!(group.status, 504);
    assert_eq!(
        group.json(),
        json!({ "message": "get delay: all proxies timeout" })
    );
    rig.control.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_over_the_message_limit_is_refused_without_waiting_for_it() {
    let rig = Rig::new(false).await;
    let mut stream = TcpStream::connect(("127.0.0.1", rig.port)).await.unwrap();
    let request = format!(
        "PATCH /configs HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
         Authorization: Bearer {}\r\nContent-Length: {}\r\n\r\n{{}}",
        rig.secret,
        concord_proto::MAX_MESSAGE + 1
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut reply = Vec::new();
    let read = timeout(PATIENCE, stream.read_to_end(&mut reply)).await;
    assert!(
        read.is_ok(),
        "the server waited for the whole declared body"
    );
    let text = String::from_utf8_lossy(&reply);
    assert!(text.starts_with("HTTP/1.1 400"), "{text}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_patch_changes_what_concord_changes_live_and_refuses_the_rest_whole() {
    let rig = Rig::new(false).await;
    let configs = rig.call("GET", "/configs", None).await.json();
    assert_eq!(configs["mode"], "rule");
    assert_eq!(configs["log-level"], "info");
    assert!(configs["tun"].is_object());

    let mut events = state_events(&rig.control).await;
    let patch = rig
        .call("PATCH", "/configs", Some(json!({ "mode": "global" })))
        .await;
    assert_eq!(patch.status, 204);
    let (origin, change) = next_change(&mut events).await;
    assert_eq!(origin, ChangeOrigin::Controller);
    assert!(
        matches!(change, StateChangeKind::General(GeneralChange { mode: Some(ref mode), .. }) if mode == "global")
    );
    assert_eq!(
        rig.call("GET", "/configs", None).await.json()["mode"],
        "global"
    );

    let refused = rig
        .call(
            "PATCH",
            "/configs",
            Some(json!({ "mode": "direct", "port": 7890 })),
        )
        .await;
    assert_eq!(refused.status, 400);
    assert!(refused.json()["message"].as_str().unwrap().contains("port"));
    assert_eq!(
        rig.call("GET", "/configs", None).await.json()["mode"],
        "global"
    );

    let tun = rig
        .call(
            "PATCH",
            "/configs",
            Some(json!({ "tun": { "enable": true } })),
        )
        .await;
    assert_eq!(tun.status, 400);
    let reload = rig
        .call("PUT", "/configs", Some(json!({ "path": "" })))
        .await;
    assert_eq!(reload.status, 405);
    rig.control.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_core_on_its_own_takes_the_controller_from_its_profile_and_reloads_a_payload() {
    let rig = Rig::new(true).await;
    assert_eq!(rig.call("GET", "/", None).await.status, 200);
    let pick = rig
        .call("PUT", "/proxies/G", Some(json!({ "name": "REJECT" })))
        .await;
    assert_eq!(pick.status, 204, "{}", pick.body);
    let payload = format!("{PROFILE}mode: direct\n");
    let reload = rig
        .call("PUT", "/configs", Some(json!({ "payload": payload })))
        .await;
    assert_eq!(reload.status, 204, "{}", reload.body);
    let configs = rig.call("GET", "/configs", None).await.json();
    assert_eq!(configs["mode"], "direct", "{configs}");
    assert_eq!(
        rig.call("GET", "/proxies/G", None).await.json()["now"],
        "REJECT",
        "a reload keeps the picks, as mihomo's cache file does"
    );
    rig.control.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rules_connections_and_providers_have_mihomos_shape() {
    let rig = Rig::new(false).await;
    let rules = rig.call("GET", "/rules", None).await.json();
    let first = &rules["rules"][0];
    assert_eq!(first["index"], 0);
    assert_eq!(first["payload"], "example.test");
    assert_eq!(first["proxy"], "REJECT");
    assert_eq!(first["size"], -1);

    let connections = rig.call("GET", "/connections", None).await.json();
    for key in ["downloadTotal", "uploadTotal", "connections", "memory"] {
        assert!(connections.get(key).is_some(), "{key}");
    }
    assert_eq!(rig.call("DELETE", "/connections", None).await.status, 204);
    assert_eq!(
        rig.call("DELETE", "/connections/123", None).await.status,
        204
    );

    let providers = rig.call("GET", "/providers/proxies", None).await.json();
    assert_eq!(
        providers["providers"]["default"]["vehicleType"],
        "Compatible"
    );
    assert_eq!(
        rig.call("GET", "/providers/rules", None).await.json(),
        json!({ "providers": {} })
    );
    assert_eq!(
        rig.call("GET", "/providers/proxies/nope", None)
            .await
            .status,
        404
    );

    let traffic = first_line(rig.port, "/traffic", rig.secret).await;
    for key in ["up", "down", "upTotal", "downTotal"] {
        assert!(traffic.get(key).is_some(), "{key}");
    }
    assert_eq!(
        rig.call("POST", "/cache/fakeip/flush", None).await.status,
        204
    );
    assert_eq!(rig.call("POST", "/restart", None).await.status, 501);
    assert_eq!(rig.call("GET", "/nowhere", None).await.status, 404);
    rig.control.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_new_address_moves_the_controller_and_an_empty_one_closes_it() {
    let rig = Rig::new(false).await;
    let moved = free_port();
    rig.listen(moved).await;
    rig.wait_open(moved).await;
    assert!(TcpStream::connect(("127.0.0.1", rig.port)).await.is_err());
    rig.control
        .config_patch(ConfigPatchParams {
            external_controller: Some(String::new()),
            ..ConfigPatchParams::default()
        })
        .await
        .unwrap();
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", moved)).await.is_err() {
            rig.control.shutdown().await;
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the controller stayed open");
}

/// Serves whatever `body` holds at the time of each request.
async fn subscription(body: Arc<Mutex<String>>) -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let body = lock(&body).clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    head.push(byte[0]);
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

fn provider_nodes(groups: &ProxyGroups) -> Vec<&str> {
    groups
        .nodes
        .iter()
        .filter(|node| node.provider.as_deref() == Some("sub"))
        .map(|node| node.name.as_str())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_update_from_a_dashboard_reaches_the_host_through_the_proxy_feed() {
    let body = Arc::new(Mutex::new(
        "proxies:\n  - {name: one, type: socks5, server: 127.0.0.1, port: 1}\n".to_string(),
    ));
    let server = subscription(body.clone()).await;
    let rig = Rig::with_profile(
        false,
        &format!(
            "mixed-port: 0
geox-url: {{mmdb: 'http://{server}/m', asn: 'http://{server}/a', geosite: 'http://{server}/g'}}
proxy-providers:
  sub: {{type: http, url: 'http://{server}/p', path: providers/p.yaml, interval: 0}}
proxy-groups:
  - {{name: G, type: select, use: [sub]}}
rules:
  - MATCH,DIRECT
"
        ),
    )
    .await;
    for _ in 0..200 {
        let groups = rig.control.proxy_groups(Empty {}).await.unwrap();
        if provider_nodes(&groups) == ["one"] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let mut feed = rig
        .control
        .proxy_watch(ProxyWatchParams::default())
        .await
        .unwrap();
    let mut resources = rig
        .control
        .events_watch(EventsWatchParams::default())
        .await
        .unwrap()
        .events;
    assert_eq!(provider_nodes(feed.snapshot.as_ref().unwrap()), ["one"]);
    *lock(&body) =
        "proxies:\n  - {name: two, type: socks5, server: 127.0.0.1, port: 1}\n".to_string();
    let update = rig.call("PUT", "/providers/proxies/sub", None).await;
    assert_eq!(update.status, 204, "{}", update.body);

    let delta = loop {
        match timeout(PATIENCE, feed.events.next()).await {
            Ok(Some(Delivery::Event { data, .. })) if !data.nodes.is_empty() => break data,
            Ok(Some(_)) => {}
            other => panic!("no proxy delta: {:?}", other.map(|item| item.is_some())),
        }
    };
    assert!(delta.nodes.iter().any(|node| node.name == "two"));
    assert!(delta.removed.iter().any(|name| name == "one"));
    let groups = rig.control.proxy_groups(Empty {}).await.unwrap();
    assert_eq!(provider_nodes(&groups), ["two"]);
    let provider = rig.call("GET", "/providers/proxies/sub", None).await.json();
    assert_eq!(provider["proxies"][0]["name"], "two");
    while next_resource(&mut resources).await
        != (
            ResourceKind::ProxyProvider,
            "sub".into(),
            ResourcePhase::Updating,
        )
    {}
    assert_eq!(
        next_resource(&mut resources).await,
        (
            ResourceKind::ProxyProvider,
            "sub".into(),
            ResourcePhase::Updated
        )
    );

    let geo = rig.call("POST", "/configs/geo", None).await;
    assert_eq!(
        geo.status, 500,
        "the server answers with a provider, not a database"
    );
    let mut failed = Vec::new();
    while failed.len() < 3 {
        let (kind, name, phase) = next_resource(&mut resources).await;
        assert_eq!(kind, ResourceKind::Geo);
        if phase == ResourcePhase::Failed {
            failed.push(name);
        }
    }
    failed.sort();
    assert_eq!(failed, ["ASN", "GEOSITE", "MMDB"]);
    rig.control.shutdown().await;
}

async fn next_resource(
    events: &mut concord_api::EventStream<CoreEvent>,
) -> (ResourceKind, String, ResourcePhase) {
    loop {
        match timeout(PATIENCE, events.next()).await {
            Ok(Some(Delivery::Event {
                data:
                    CoreEvent::ResourceUpdate {
                        kind, name, phase, ..
                    },
                ..
            })) => return (kind, name, phase),
            Ok(Some(Delivery::Event { .. })) => {}
            other => panic!("no resource update: {:?}", other.map(|item| item.is_some())),
        }
    }
}
