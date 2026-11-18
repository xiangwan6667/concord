#![allow(
    clippy::disallowed_methods,
    reason = "the peers here stand for the outside world, not the core's own sockets"
)]

use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use concord_api::{
    Control, ControlOptions, ControlService, Delivery, EventBus, EventStream, LogBridge,
};
use concord_engine::{Engine, EngineConfig};
use concord_platform::NativePlatform;
use concord_proto::types::*;
use concord_proto::{ApiError, ErrorData};
use concord_test_support::free_port;
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tracing_subscriber::layer::SubscriberExt;

const PATIENCE: Duration = Duration::from_secs(20);

struct Rig {
    control: Arc<Control>,
    engine: Arc<Engine>,
    bus: Arc<EventBus>,
    home: PathBuf,
    _dir: tempfile::TempDir,
}

fn parts() -> (Arc<Control>, Arc<Engine>, Arc<EventBus>) {
    let bus = EventBus::new();
    let engine = Engine::new(EngineConfig {
        sink: bus.clone(),
        android: false,
        platform: Arc::new(NativePlatform::new()),
    });
    let control = Control::new(engine.clone(), bus.clone(), ControlOptions::default());
    (control, engine, bus)
}

impl Rig {
    async fn new() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_path_buf();
        let (control, engine, bus) = parts();
        control
            .core_init(CoreInitParams {
                home: home.to_str().unwrap().to_string(),
                sdk_int: None,
            })
            .await
            .unwrap();
        Rig {
            control,
            engine,
            bus,
            home,
            _dir: dir,
        }
    }

    fn write_config(&self, text: &str) {
        std::fs::write(self.home.join("config.yaml"), text).unwrap();
    }

    async fn apply(&self) -> Result<ConfigApplyResult, ApiError> {
        self.control
            .config_apply(ConfigApplyParams::default())
            .await
    }

    async fn apply_with(&self, params: ConfigApplyParams) -> Result<ConfigApplyResult, ApiError> {
        self.control.config_apply(params).await
    }

    async fn groups(&self) -> ProxyGroups {
        self.control.proxy_groups(Empty {}).await.unwrap()
    }

    fn profile(&self, name: &str) -> ProfileRef {
        ProfileRef {
            path: self.home.join(name).to_str().unwrap().to_string(),
        }
    }

    async fn finish(self) {
        self.control.shutdown().await;
    }
}

async fn next<E: Send + 'static>(events: &mut EventStream<E>) -> E {
    match timeout(PATIENCE, events.next()).await {
        Ok(Some(Delivery::Event { data, .. })) => data,
        other => panic!("no event arrived: {:?}", other.map(|item| item.is_some())),
    }
}

async fn eventually<E: Send + 'static>(
    events: &mut EventStream<E>,
    mut found: impl FnMut(&E) -> bool,
) -> E {
    for _ in 0..200 {
        let event = next(events).await;
        if found(&event) {
            return event;
        }
    }
    panic!("the event never came");
}

async fn hanging_server() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    port
}

fn rejected(error: &ApiError) -> bool {
    matches!(error.data, ErrorData::Rejected { .. })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_profile_is_rejected_with_a_fallback_and_the_core_keeps_running() {
    let rig = Rig::new().await;
    rig.write_config("rules:\n  - NOT-A-RULE,x,DIRECT\n");
    rig.control.engine_start(Empty::default()).await.unwrap();

    let error = rig.apply().await.unwrap_err();

    assert!(rejected(&error), "{error:?}");
    let ErrorData::Rejected {
        issues, fell_back, ..
    } = &error.data
    else {
        unreachable!()
    };
    assert_eq!(*fell_back, Some(true));
    assert!(issues[0].message.contains("NOT-A-RULE"));
    assert!(rig.engine.is_running(), "a rejected apply stopped the core");
    let groups = rig.groups().await;
    assert!(
        groups
            .nodes
            .iter()
            .any(|node| node.name == "DIRECT" && node.kind == "Direct")
    );
    let status = rig
        .control
        .engine_state(EngineStateParams::default())
        .await
        .unwrap();
    assert_eq!(status.snapshot.unwrap().state, EngineState::Running);
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn calls_that_need_an_earlier_step_answer_conflict_with_the_state_they_need() {
    let (control, engine, _bus) = parts();

    let apply = control.config_apply(ConfigApplyParams::default()).await;
    let error = apply.unwrap_err();
    assert_eq!(
        error.data,
        ErrorData::Conflict {
            state: Some("created".into())
        }
    );

    let dir = tempfile::tempdir().unwrap();
    control
        .core_init(CoreInitParams {
            home: dir.path().to_str().unwrap().into(),
            sdk_int: None,
        })
        .await
        .unwrap();
    let patch = control.config_patch(ConfigPatchParams::default()).await;
    assert_eq!(
        patch.unwrap_err().data,
        ErrorData::Conflict {
            state: Some("initialized".into())
        }
    );
    control.shutdown().await;
    drop(engine);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn options_take_effect_before_the_profile_is_read() {
    let rig = Rig::new().await;
    rig.write_config("rules:\n  - NOT-A-RULE,x,DIRECT\n");

    let error = rig
        .apply_with(ConfigApplyParams {
            options: Options {
                test_url: "http://127.0.0.1:1/probe".into(),
                delay_test_timeout: 1500,
                ..Options::default()
            },
            ..ConfigApplyParams::default()
        })
        .await
        .unwrap_err();
    assert!(rejected(&error));

    let delay = rig
        .control
        .delay_test(DelayTestParams {
            proxy: "DIRECT".into(),
            url: None,
            timeout: None,
            expected: None,
        })
        .await
        .unwrap();
    assert_eq!(delay.url, "http://127.0.0.1:1/probe");
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_apply_with_a_profile_and_a_json_overlay_leaves_a_config_that_loads_alone() {
    let rig = Rig::new().await;
    std::fs::write(
        rig.home.join("profile.yaml"),
        "&base proxies:\n  - {name: a, type: socks5, server: 127.0.0.1, port: 1}\nrules:\n  - MATCH,DIRECT\n",
    )
    .unwrap();

    rig.apply_with(ConfigApplyParams {
        profile: Some(rig.profile("profile.yaml")),
        overlay: Some(json!({"mode": "global", "rules": ["DOMAIN,first.test,DIRECT"]})),
        ..ConfigApplyParams::default()
    })
    .await
    .unwrap();

    let read = rig
        .control
        .config_read(ConfigReadParams {
            profile: rig.profile("config.yaml"),
            output: Output::default(),
        })
        .await
        .unwrap();
    let config = read.config.unwrap();
    assert_eq!(config["mode"], "global", "{config}");
    assert_eq!(config["rules"][0], "DOMAIN,first.test,DIRECT");
    assert_eq!(config["rules"][1], "MATCH,DIRECT");
    assert!(config.get("rule").is_none(), "the mihomo key is renamed");
    assert_eq!(config["proxies"][0]["name"], "a");
    let leftovers: Vec<String> = std::fs::read_dir(&rig.home)
        .unwrap()
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| name.contains("tmp") || name.starts_with('.'))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");

    let overlay_alone = rig
        .apply_with(ConfigApplyParams {
            overlay: Some(json!({})),
            ..ConfigApplyParams::default()
        })
        .await
        .unwrap_err();
    assert!(matches!(
        overlay_alone.data,
        ErrorData::InvalidParams { .. }
    ));
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_large_result_goes_to_the_file_the_caller_names_and_only_inside_the_home() {
    let rig = Rig::new().await;
    let mut text = String::from("mode: rule\nrules:\n");
    for index in 0..40_000 {
        text.push_str(&format!(
            "  - DOMAIN-SUFFIX,host-{index}.example.com,DIRECT\n"
        ));
    }
    text.push_str("  - MATCH,DIRECT\n");
    std::fs::write(rig.home.join("big.yaml"), &text).unwrap();
    let read = |output| ConfigReadParams {
        profile: rig.profile("big.yaml"),
        output,
    };

    let inline = rig
        .control
        .config_read(read(Output::default()))
        .await
        .unwrap();
    assert_eq!(
        inline.config.unwrap()["rules"].as_array().unwrap().len(),
        40_001
    );
    assert!(inline.file.is_none() && inline.size.is_none());

    let target = rig.home.join("out").join("big.json");
    let written = rig
        .control
        .config_read(read(Output::File {
            file: target.to_str().unwrap().into(),
        }))
        .await
        .unwrap();
    assert!(written.config.is_none());
    assert_eq!(written.file.as_deref(), target.to_str());
    let bytes = std::fs::read(&target).unwrap();
    assert_eq!(written.size, Some(bytes.len() as u64));
    let stored: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(stored["mode"], "rule");

    let outside = rig
        .control
        .config_read(read(Output::File {
            file: std::env::temp_dir()
                .join("concord-outside.json")
                .to_str()
                .unwrap()
                .into(),
        }))
        .await
        .unwrap_err();
    assert_eq!(
        outside.data,
        ErrorData::InvalidParams {
            path: Some("output.file".into())
        },
        "{outside:?}"
    );

    let built = rig
        .control
        .profile_build(ProfileBuildParams {
            profile: rig.profile("big.yaml"),
            overlay: json!({"mode": "global"}),
            output: Output::default(),
        })
        .await
        .unwrap();
    assert!(built.text.unwrap().contains("mode: global"));
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_missing_file_is_not_found_and_not_a_bare_message() {
    let rig = Rig::new().await;
    let error = rig
        .control
        .config_read(ConfigReadParams {
            profile: rig.profile("absent.yaml"),
            output: Output::default(),
        })
        .await
        .unwrap_err();
    assert!(matches!(error.data, ErrorData::NotFound { ref entity, .. } if entity == "file"));
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_selection_is_answered_while_an_apply_is_still_applying() {
    let rig = Rig::new().await;
    rig.write_config(
        "proxies:\n  - {name: a, type: socks5, server: 127.0.0.1, port: 1}\n\
         proxy-groups:\n  - {name: G, type: select, proxies: [DIRECT, a]}\n\
         rules:\n  - MATCH,G\n",
    );
    rig.apply().await.unwrap();

    let stuck = hanging_server().await;
    rig.write_config(&format!(
        "geox-url:\n  mmdb: http://127.0.0.1:{stuck}/Country.mmdb\n\
         proxies:\n  - {{name: a, type: socks5, server: 127.0.0.1, port: 1}}\n\
         proxy-groups:\n  - {{name: G, type: select, proxies: [DIRECT, a]}}\n\
         rules:\n  - GEOIP,CN,DIRECT\n  - MATCH,G\n"
    ));
    let control = rig.control.clone();
    let applying =
        tokio::spawn(async move { control.config_apply(ConfigApplyParams::default()).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!applying.is_finished(), "the apply answered early");

    let select = rig
        .control
        .proxy_select(ProxySelectParams {
            group: "G".into(),
            proxy: "a".into(),
        })
        .await
        .unwrap();

    assert!(select.changed);
    assert!(
        !applying.is_finished(),
        "the selection waited for the apply"
    );
    applying.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_selection_for_a_gone_member_is_kept_in_the_map_and_refused_as_a_pick() {
    let rig = Rig::new().await;
    rig.write_config(
        "proxy-groups:\n  - {name: G, type: select, proxies: [DIRECT, REJECT]}\n\
         rules:\n  - MATCH,G\n",
    );

    rig.apply_with(ConfigApplyParams {
        selection: [("G", "gone"), ("Ghost", "DIRECT")]
            .into_iter()
            .map(|(group, proxy)| (group.to_string(), proxy.to_string()))
            .collect(),
        ..ConfigApplyParams::default()
    })
    .await
    .unwrap();

    let groups = rig.groups().await;
    let group = groups
        .groups
        .iter()
        .find(|group| group.name == "G")
        .unwrap();
    assert_eq!(group.now.as_deref(), Some("DIRECT"));
    assert!(groups.groups.iter().all(|group| group.name != "Ghost"));
    let refused = rig
        .control
        .proxy_select(ProxySelectParams {
            group: "G".into(),
            proxy: "gone".into(),
        })
        .await
        .unwrap_err();
    assert_eq!(
        refused.data,
        ErrorData::NotFound {
            entity: "proxy".into(),
            name: "gone".into()
        }
    );
    let stranger = rig
        .control
        .proxy_select(ProxySelectParams {
            group: "Nope".into(),
            proxy: "DIRECT".into(),
        })
        .await
        .unwrap_err();
    assert!(matches!(stranger.data, ErrorData::NotFound { ref entity, .. } if entity == "group"));
    rig.finish().await;
}

fn loaded(event: &CoreEvent, wanted: &str) -> bool {
    matches!(
        event,
        CoreEvent::ResourceUpdate { name, phase: ResourcePhase::Updated, .. } if name == wanted
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_provider_reports_loaded_after_the_apply_has_answered() {
    let rig = Rig::new().await;
    std::fs::write(
        rig.home.join("p.yaml"),
        "proxies:\n  - {name: pn, type: socks5, server: 127.0.0.1, port: 1}\n",
    )
    .unwrap();
    rig.write_config(
        "proxy-providers:\n  one:\n    type: file\n    path: p.yaml\n\
         proxy-groups:\n  - {name: G, type: select, use: [one]}\n\
         rules:\n  - MATCH,G\n",
    );
    let mut events = rig
        .control
        .events_watch(EventsWatchParams::default())
        .await
        .unwrap()
        .events;

    rig.apply().await.unwrap();

    let started = eventually(
        &mut events,
        |event| matches!(event, CoreEvent::ResourceUpdate { name, .. } if name == "one"),
    )
    .await;
    assert!(matches!(
        started,
        CoreEvent::ResourceUpdate {
            kind: ResourceKind::ProxyProvider,
            phase: ResourcePhase::Updating,
            ..
        }
    ));
    eventually(&mut events, |event| loaded(event, "one")).await;
    let providers = rig.control.provider_list(Empty {}).await.unwrap().providers;
    assert!(
        providers
            .iter()
            .any(|provider| provider.name == "one" && provider.count == 1),
        "a host that reads on the event finds the provider in"
    );
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_start_opens_the_port_and_an_apply_alone_does_not() {
    let rig = Rig::new().await;
    let port = free_port();
    rig.write_config(&format!("mixed-port: {port}\nrules:\n  - MATCH,DIRECT\n"));
    rig.apply().await.unwrap();
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_err()
    );

    rig.control.engine_start(Empty::default()).await.unwrap();
    assert!(
        TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .is_ok()
    );

    rig.control.engine_stop(Empty::default()).await.unwrap();
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_port_that_cannot_be_bound_is_a_fault_in_the_engine_state_until_it_binds() {
    let rig = Rig::new().await;
    let taken = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = taken.local_addr().unwrap().port();
    rig.write_config(&format!(
        "mixed-port: {port}\nbind-address: 127.0.0.1\nrules:\n  - MATCH,DIRECT\n"
    ));
    rig.apply().await.unwrap();
    let mut watch = rig
        .control
        .engine_state(EngineStateParams::default())
        .await
        .unwrap();
    assert!(watch.snapshot.unwrap().faults.is_empty());

    rig.control.engine_start(Empty::default()).await.unwrap();
    let status = next(&mut watch.events).await;
    assert_eq!(status.state, EngineState::Running);
    let [fault] = status.faults.as_slice() else {
        panic!("{:?}", status.faults);
    };
    assert_eq!(fault.service, FaultService::Mixed);
    assert_eq!(fault.reason, FaultReason::AddressInUse);
    assert_eq!(fault.address, format!("127.0.0.1:{port}"));

    drop(taken);
    rig.control
        .config_patch(ConfigPatchParams {
            mixed_port: Some(free_port()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(next(&mut watch.events).await.faults.is_empty());
    rig.control.engine_stop(Empty::default()).await.unwrap();
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_engine_state_stream_reports_each_step_the_core_takes() {
    let (control, _engine, _bus) = parts();
    let dir = tempfile::tempdir().unwrap();
    let mut watch = control
        .engine_state(EngineStateParams::default())
        .await
        .unwrap();
    assert_eq!(watch.snapshot.unwrap().state, EngineState::Created);

    control
        .core_init(CoreInitParams {
            home: dir.path().to_str().unwrap().into(),
            sdk_int: None,
        })
        .await
        .unwrap();
    assert_eq!(
        next(&mut watch.events).await.state,
        EngineState::Initialized
    );
    std::fs::write(dir.path().join("config.yaml"), "rules:\n  - MATCH,DIRECT\n").unwrap();
    control
        .config_apply(ConfigApplyParams::default())
        .await
        .unwrap();
    assert_eq!(next(&mut watch.events).await.state, EngineState::Configured);
    control.engine_start(Empty::default()).await.unwrap();
    assert_eq!(next(&mut watch.events).await.state, EngineState::Running);
    control.engine_stop(Empty::default()).await.unwrap();
    assert_eq!(next(&mut watch.events).await.state, EngineState::Configured);

    std::fs::write(
        dir.path().join("config.yaml"),
        "rules:\n  - NOPE,x,DIRECT\n",
    )
    .unwrap();
    assert!(
        control
            .config_apply(ConfigApplyParams::default())
            .await
            .is_err()
    );
    control.shutdown().await;
    assert_eq!(next(&mut watch.events).await.state, EngineState::Created);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delay_test_names_its_url_and_a_watcher_that_asked_sees_it() {
    let rig = Rig::new().await;
    rig.write_config("rules:\n  - MATCH,DIRECT\n");
    rig.apply().await.unwrap();
    let url = "http://127.0.0.1:1/ui-key";
    let mut with_delays = rig
        .control
        .events_watch(EventsWatchParams {
            delays: true,
            ..EventsWatchParams::default()
        })
        .await
        .unwrap()
        .events;
    let mut without = rig
        .control
        .events_watch(EventsWatchParams::default())
        .await
        .unwrap()
        .events;

    let result = rig
        .control
        .delay_test(DelayTestParams {
            proxy: "DIRECT".into(),
            url: Some(url.into()),
            timeout: Some(1000),
            expected: None,
        })
        .await
        .unwrap();
    assert_eq!(result.url, url);

    eventually(&mut with_delays, |event| {
        matches!(event, CoreEvent::Delay { name, url: seen, .. } if name == "DIRECT" && seen == url)
    })
    .await;
    assert!(
        timeout(Duration::from_millis(200), without.next())
            .await
            .is_err(),
        "a watcher that did not ask for delays must not get them"
    );
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_apply_does_not_wait_for_a_provider_download() {
    let rig = Rig::new().await;
    let stuck = hanging_server().await;
    rig.write_config(&format!(
        "proxy-providers:\n  slow:\n    type: http\n    url: http://127.0.0.1:{stuck}/sub\n    path: providers/slow.yaml\n\
         proxy-groups:\n  - {{name: G, type: select, use: [slow], proxies: [DIRECT]}}\n\
         rules:\n  - MATCH,G\n"
    ));
    let mut events = rig
        .control
        .events_watch(EventsWatchParams::default())
        .await
        .unwrap()
        .events;

    timeout(Duration::from_secs(5), rig.apply())
        .await
        .expect("the apply waited for the provider")
        .unwrap();

    assert!(matches!(
        next(&mut events).await,
        CoreEvent::ResourceUpdate { ref name, phase: ResourcePhase::Updating, .. } if name == "slow"
    ));
    assert!(
        timeout(Duration::from_millis(200), events.next())
            .await
            .is_err(),
        "the download has no outcome yet"
    );
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn proxy_groups_have_the_order_the_shape_and_the_literal_names_dart_reads() {
    let rig = Rig::new().await;
    std::fs::write(
        rig.home.join("p.yaml"),
        "proxies:\n  - {name: from-provider, type: socks5, server: 192.0.2.30, port: 1080}\n",
    )
    .unwrap();
    rig.write_config(
        "proxies:\n\
         \x20 - {name: ss, type: ss, server: 192.0.2.1, port: 1, cipher: aes-128-gcm, password: p}\n\
         \x20 - {name: vm, type: vmess, server: 192.0.2.2, port: 1, uuid: 6a4f3bc1-2c44-4a43-a5a3-3f1a2b0e6a11, alterId: 0, cipher: auto}\n\
         \x20 - {name: so, type: socks5, server: 192.0.2.8, port: 1}\n\
         proxy-providers:\n  prov:\n    type: file\n    path: p.yaml\n\
         proxy-groups:\n\
         \x20 - {name: S, type: select, proxies: [ss, DIRECT]}\n\
         \x20 - {name: U, type: url-test, proxies: [ss, vm]}\n\
         \x20 - {name: F, type: fallback, proxies: [ss, vm]}\n\
         \x20 - {name: L, type: load-balance, proxies: [ss, vm]}\n\
         \x20 - {name: P, type: select, use: [prov]}\n\
         rules:\n  - MATCH,S\n",
    );
    let mut events = rig
        .control
        .events_watch(EventsWatchParams::default())
        .await
        .unwrap()
        .events;
    rig.apply().await.unwrap();
    eventually(&mut events, |event| loaded(event, "prov")).await;

    let groups = rig.groups().await;

    assert_eq!(groups.order, ["GLOBAL", "S", "U", "F", "L", "P"]);
    let kind_of = |name: &str| {
        groups
            .groups
            .iter()
            .map(|group| (&group.name, &group.kind))
            .chain(groups.nodes.iter().map(|node| (&node.name, &node.kind)))
            .find(|(candidate, _)| candidate.as_str() == name)
            .map(|(_, kind)| kind.as_str().to_string())
    };
    for (name, kind) in [
        ("DIRECT", "Direct"),
        ("REJECT", "Reject"),
        ("COMPATIBLE", "Compatible"),
        ("PASS", "Pass"),
        ("ss", "Shadowsocks"),
        ("vm", "Vmess"),
        ("so", "Socks5"),
        ("S", "Selector"),
        ("U", "URLTest"),
        ("F", "Fallback"),
        ("L", "LoadBalance"),
    ] {
        assert_eq!(kind_of(name).as_deref(), Some(kind), "{name}");
    }
    let provided = groups
        .nodes
        .iter()
        .find(|node| node.name == "from-provider")
        .unwrap();
    assert_eq!(provided.provider.as_deref(), Some("prov"));
    let find = |name: &str| {
        groups
            .groups
            .iter()
            .find(|group| group.name == name)
            .unwrap()
    };
    assert!(find("GLOBAL").hidden);
    assert!(!find("S").hidden);
    assert!(find("L").now.is_none());
    assert!(find("S").now.is_some());
    rig.finish().await;
}

async fn subscription_server(body: &'static str) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
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
                    "HTTP/1.1 200 OK\r\nSubscription-Userinfo: upload=1; download=2; total=3; expire=4\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    port
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_provider_has_the_subscription_numbers_and_an_update_time_in_milliseconds() {
    let port = subscription_server(
        "proxies:\n  - {name: one, type: socks5, server: 192.0.2.1, port: 1}\n",
    )
    .await;
    let rig = Rig::new().await;
    rig.write_config(&format!(
        "proxy-providers:\n  sub:\n    type: http\n    url: http://127.0.0.1:{port}/s\n    path: providers/sub.yaml\n\
         proxy-groups:\n  - {{name: G, type: select, use: [sub]}}\nrules:\n  - MATCH,G\n"
    ));
    let mut events = rig
        .control
        .events_watch(EventsWatchParams::default())
        .await
        .unwrap()
        .events;
    rig.apply().await.unwrap();
    eventually(&mut events, |event| loaded(event, "sub")).await;

    let list = rig.control.provider_list(Empty {}).await.unwrap();

    let provider = &list.providers[0];
    assert_eq!(provider.name, "sub");
    assert_eq!(provider.kind, ProviderKind::Proxy);
    let info = provider.subscription_info.as_ref().unwrap();
    assert_eq!(
        (info.upload, info.download, info.total, info.expire),
        (1, 2, 3, 4)
    );
    let updated = provider
        .updated_at
        .expect("a loaded provider has an update time");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    assert!((now - updated).abs() < 60_000, "{updated} vs {now}");
    let one = rig
        .control
        .provider_get(ProviderNameParams { name: "sub".into() })
        .await
        .unwrap();
    assert_eq!(one.count, 1);
    let missing = rig
        .control
        .provider_get(ProviderNameParams {
            name: "nope".into(),
        })
        .await
        .unwrap_err();
    assert!(matches!(missing.data, ErrorData::NotFound { .. }));
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pick_moves_the_route_and_the_watchers_hear_about_it_only_while_they_watch() {
    let rig = Rig::new().await;
    rig.write_config(
        "proxies:\n  - {name: a, type: socks5, server: 127.0.0.1, port: 1}\n\
         proxy-groups:\n  - {name: G, type: select, proxies: [DIRECT, a]}\n\
         rules:\n  - MATCH,G\n",
    );
    rig.apply().await.unwrap();
    let mut route = rig
        .control
        .route_watch(RouteWatchParams::default())
        .await
        .unwrap();
    let before = route.snapshot.clone().unwrap();
    let mut proxies = rig
        .control
        .proxy_watch(ProxyWatchParams::default())
        .await
        .unwrap();
    assert_eq!(
        rig.bus.topic_counts()[2],
        2,
        "two subscribers on the route topic"
    );

    rig.control
        .proxy_select(ProxySelectParams {
            group: "G".into(),
            proxy: "a".into(),
        })
        .await
        .unwrap();

    let moved = next(&mut route.events).await;
    assert_eq!(moved.epoch, before.epoch);
    assert!(moved.version > before.version);
    let delta = next(&mut proxies.events).await;
    assert_eq!(delta.groups.len(), 1, "only the group that changed is sent");
    assert_eq!(delta.groups[0].name, "G");
    assert_eq!(delta.groups[0].now.as_deref(), Some("a"));
    assert!(delta.nodes.is_empty() && delta.removed.is_empty() && delta.order.is_none());

    drop(route);
    drop(proxies);
    assert_eq!(rig.bus.topic_counts()[2], 0);
    assert_eq!(rig.bus.subscribers(), 0);
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_patch_that_moves_the_mode_moves_the_route_stamp() {
    let rig = Rig::new().await;
    rig.write_config("rules:\n  - MATCH,DIRECT\n");
    rig.apply().await.unwrap();
    let mut route = rig
        .control
        .route_watch(RouteWatchParams::default())
        .await
        .unwrap();
    let before = route.snapshot.clone().unwrap();

    rig.control
        .config_patch(ConfigPatchParams {
            mode: Some("global".into()),
            ..ConfigPatchParams::default()
        })
        .await
        .unwrap();

    let moved = next(&mut route.events).await;
    assert!(moved.version > before.version);
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_log_gate_follows_the_log_subscriptions() {
    let rig = Rig::new().await;
    let subscriber = tracing_subscriber::registry().with(LogBridge::new(
        rig.bus.gate().clone(),
        rig.bus.clone(),
        false,
    ));
    let _guard = tracing::subscriber::set_default(subscriber);

    tracing::info!("nobody listens");
    let mut first = rig
        .control
        .log_watch(LogWatchParams::default())
        .await
        .unwrap()
        .events;
    let mut loud = rig
        .control
        .log_watch(LogWatchParams {
            level: Some(LogLevel::Error),
            ..LogWatchParams::default()
        })
        .await
        .unwrap()
        .events;
    tracing::info!("heard");
    tracing::error!("heard loudly");

    let entry = next(&mut first).await;
    assert_eq!(
        (entry.level, entry.text.as_str()),
        (LogLevel::Info, "heard")
    );
    assert_eq!(next(&mut first).await.text, "heard loudly");
    assert_eq!(next(&mut loud).await.text, "heard loudly");

    drop(first);
    tracing::error!("one is left");
    assert_eq!(next(&mut loud).await.text, "one is left");
    drop(loud);
    assert_eq!(rig.bus.subscribers(), 0);
    tracing::error!("none is left");
    let mut late = rig
        .control
        .log_watch(LogWatchParams::default())
        .await
        .unwrap()
        .events;
    assert!(
        timeout(Duration::from_millis(100), late.next())
            .await
            .is_err(),
        "an entry written while nobody watched must not turn up later"
    );
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_traffic_stream_ticks_on_its_interval_and_totals_start_at_the_snapshot() {
    let rig = Rig::new().await;
    let mut traffic = rig
        .control
        .traffic_watch(TrafficWatchParams {
            interval_ms: Some(100),
            ..TrafficWatchParams::default()
        })
        .await
        .unwrap();
    assert_eq!(traffic.snapshot.unwrap().total_up, 0);

    let started = std::time::Instant::now();
    next(&mut traffic.events).await;
    next(&mut traffic.events).await;
    let elapsed = started.elapsed();

    assert!(elapsed >= Duration::from_millis(180), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(2), "{elapsed:?}");
    rig.finish().await;
}

async fn through_the_proxy(proxy: u16, target: u16) -> TcpStream {
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy))
        .await
        .unwrap();
    stream
        .write_all(
            format!("CONNECT 127.0.0.1:{target} HTTP/1.1\r\nHost: 127.0.0.1:{target}\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    assert!(
        head.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&head)
    );
    stream
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connections_arrive_as_a_snapshot_then_opens_counters_and_closes() {
    let rig = Rig::new().await;
    let proxy = free_port();
    rig.write_config(&format!("mixed-port: {proxy}\nrules:\n  - MATCH,DIRECT\n"));
    rig.apply().await.unwrap();
    rig.control.engine_start(Empty::default()).await.unwrap();
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = target.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 256];
                while let Ok(count) = stream.read(&mut buffer).await {
                    if count == 0 || stream.write_all(&buffer[..count]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });

    let mut first = through_the_proxy(proxy, target_port).await;
    for _ in 0..100 {
        if rig.engine.connection_count() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut watch = rig
        .control
        .connection_watch(ConnectionWatchParams::default())
        .await
        .unwrap();
    let snapshot = watch.snapshot.take().unwrap();
    assert_eq!(snapshot.connections.len(), 1, "{snapshot:?}");
    let known = &snapshot.connections[0];
    assert_eq!(known.destination_port, target_port);
    assert_eq!(known.network, Network::Tcp);
    assert_eq!(known.chains.first().map(String::as_str), Some("DIRECT"));

    let mut second = through_the_proxy(proxy, target_port).await;
    let opened = eventually(&mut watch.events, |delta| !delta.opened.is_empty()).await;
    assert_eq!(opened.opened.len(), 1);
    assert_ne!(
        opened.opened[0].id, known.id,
        "the snapshot's connection is not repeated"
    );
    assert!(opened.opened[0].id > known.id, "ids count up");

    second.write_all(b"ping").await.unwrap();
    let mut echoed = [0u8; 4];
    second.read_exact(&mut echoed).await.unwrap();
    let counted = eventually(&mut watch.events, |delta| {
        delta
            .counters
            .iter()
            .any(|counter| counter.id == opened.opened[0].id && counter.upload >= 4)
    })
    .await;
    assert!(
        counted
            .counters
            .iter()
            .all(|counter| counter.upload > 0 || counter.download > 0)
    );

    first.shutdown().await.unwrap();
    drop(first);
    let closed = eventually(&mut watch.events, |delta| delta.closed.contains(&known.id)).await;
    assert!(!closed.closed.contains(&opened.opened[0].id));

    rig.control
        .connection_close(ConnectionCloseParams {
            ids: Some(vec![opened.opened[0].id]),
            all: false,
        })
        .await
        .unwrap();
    eventually(&mut watch.events, |delta| {
        delta.closed.contains(&opened.opened[0].id)
    })
    .await;
    assert!(
        rig.control
            .connection_close(ConnectionCloseParams {
                ids: None,
                all: false,
            })
            .await
            .is_err()
    );
    drop(watch);
    assert_eq!(rig.bus.subscribers(), 0);
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delay_run_reports_each_proxy_then_done_and_stops_when_dropped() {
    let rig = Rig::new().await;
    rig.write_config("rules:\n  - MATCH,DIRECT\n");
    rig.apply().await.unwrap();

    let mut run = rig
        .control
        .delay_run(DelayRunParams {
            proxies: vec!["DIRECT".into(), "REJECT".into()],
            url: Some("http://127.0.0.1:1/x".into()),
            timeout: Some(1000),
            concurrency: Some(2),
            expected: None,
            watch: WatchOptions::default(),
        })
        .await
        .unwrap();
    assert!(run.snapshot.is_none());
    let mut seen = Vec::new();
    while let DelayRunEvent::Result { name, .. } = next(&mut run.events).await {
        seen.push(name);
    }
    seen.sort();
    assert_eq!(seen, ["DIRECT", "REJECT"]);
    assert!(run.events.next().await.is_none());

    let stuck = hanging_server().await;
    let closed = Arc::new(AtomicBool::new(false));
    let watcher = {
        let closed = closed.clone();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let closed = closed.clone();
                tokio::spawn(async move {
                    let mut buffer = [0u8; 512];
                    while let Ok(count) = stream.read(&mut buffer).await {
                        if count == 0 {
                            closed.store(true, Ordering::SeqCst);
                            return;
                        }
                    }
                    closed.store(true, Ordering::SeqCst);
                });
            }
        });
        port
    };
    let _ = stuck;
    let run = rig
        .control
        .delay_run(DelayRunParams {
            proxies: vec!["DIRECT".into()],
            url: Some(format!("http://127.0.0.1:{watcher}/slow")),
            timeout: Some(30_000),
            concurrency: None,
            expected: None,
            watch: WatchOptions::default(),
        })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(!closed.load(Ordering::SeqCst));

    drop(run);

    for _ in 0..100 {
        if closed.load(Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        closed.load(Ordering::SeqCst),
        "the test kept running after the stream was dropped"
    );
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_stateless_helpers_answer_with_indexed_issues_and_empty_results() {
    let rig = Rig::new().await;

    let filters = rig
        .control
        .validate_filters(ValidateFiltersParams {
            filters: vec!["ok".into(), "(".into()],
        })
        .await
        .unwrap();
    assert_eq!(filters.issues.len(), 1);
    assert_eq!(filters.issues[0].index, 1);

    let proxies = rig
        .control
        .validate_proxies(ValidateProxiesParams {
            proxies: vec![json!({"name": "x", "type": "nope"})],
        })
        .await
        .unwrap();
    assert_eq!(proxies.issues[0].index, 0);
    let not_a_mapping = rig
        .control
        .validate_proxies(ValidateProxiesParams {
            proxies: vec![json!("text")],
        })
        .await
        .unwrap_err();
    assert_eq!(
        not_a_mapping.data,
        ErrorData::InvalidParams {
            path: Some("proxies[0]".into())
        }
    );

    let links = rig
        .control
        .convert_decode_links(DecodeLinksParams {
            lines: vec!["not a link".into()],
        })
        .await
        .unwrap();
    assert_eq!(links.results, vec![Vec::<Value>::new()]);
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_profile_helpers_read_without_applying() {
    let rig = Rig::new().await;
    std::fs::write(
        rig.home.join("p.yaml"),
        "proxies:\n  - {name: a, type: socks5, server: 127.0.0.1, port: 1}\n\
         proxy-groups:\n  - {name: G, type: select, proxies: [a]}\nrules:\n  - MATCH,G\n",
    )
    .unwrap();

    let inspected = rig
        .control
        .profile_inspect(ProfileParams {
            profile: rig.profile("p.yaml"),
        })
        .await
        .unwrap();
    assert_eq!(
        (inspected.proxies, inspected.proxy_groups, inspected.rules),
        (1, 1, 1)
    );
    assert_eq!(inspected.match_rules, ["MATCH,G"]);
    assert_eq!(inspected.digest.len(), 64);
    let outbounds = rig
        .control
        .profile_outbounds(ProfileParams {
            profile: rig.profile("p.yaml"),
        })
        .await
        .unwrap();
    assert_eq!(outbounds.proxies[0].name, "a");
    assert_eq!(outbounds.proxy_groups[0].kind, "select");
    let invalid = rig
        .control
        .config_validate(ConfigValidateParams {
            profile: rig.profile("p.yaml"),
        })
        .await
        .unwrap();
    assert!(invalid.issues.is_empty());
    rig.write_config("rules: [");
    let broken = rig
        .control
        .config_validate(ConfigValidateParams {
            profile: rig.profile("config.yaml"),
        })
        .await
        .unwrap();
    assert_eq!(broken.issues.len(), 1);
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_service_with_a_capability_it_lacks_answers_unsupported() {
    let rig = Rig::new().await;
    let unknown_connection = rig
        .control
        .mitm_exchanges(MitmExchangesParams { connection: 4242 })
        .await
        .unwrap_err();
    assert!(matches!(
        unknown_connection.data,
        ErrorData::NotFound { .. }
    ));
    #[cfg(not(feature = "debug"))]
    {
        let crash = rig.control.debug_crash(Empty {}).await.unwrap_err();
        assert!(matches!(crash.data, ErrorData::Unsupported { .. }));
    }
    let device = rig
        .control
        .tun_start(TunStartParams {
            source: TunSource::Inherited { handle: 9 },
            stack: None,
            mtu: None,
            address: vec![],
            dns: vec![],
            congestion_controller: None,
        })
        .await
        .unwrap_err();
    #[cfg(unix)]
    assert!(matches!(device.data, ErrorData::NotFound { ref entity, .. } if entity == "handle"));
    #[cfg(not(unix))]
    assert!(matches!(device.data, ErrorData::Unsupported { .. }));
    rig.finish().await;
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_inherited_tun_that_cannot_start_tells_the_host_why() {
    let rig = Rig::new().await;
    let fd = std::fs::File::open("/dev/null").unwrap().into();
    let handle = rig.control.adopted_fds().adopt(fd);
    let error = rig
        .control
        .tun_start(TunStartParams {
            source: TunSource::Inherited { handle },
            stack: None,
            mtu: None,
            address: vec!["nonsense".to_string()],
            dns: vec![],
            congestion_controller: None,
        })
        .await
        .unwrap_err();
    assert!(
        matches!(error.data, ErrorData::Unavailable { ref target } if target.as_deref() == Some("tun"))
    );
    assert!(
        error.message.contains("invalid tun address nonsense"),
        "{}",
        error.message
    );
    assert!(rig.control.adopted_fds().is_empty());
    rig.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mitm_validate_answers_each_line_with_its_view_or_its_issue() {
    let rig = Rig::new().await;
    let resources = rig.home.join("mitm").join("resources");
    std::fs::create_dir_all(&resources).unwrap();
    std::fs::write(resources.join("a.js"), "$done({})").unwrap();
    let config = json!({
        "hostname": ["a.com, bad host", "-*.b.com:8443"],
        "client-source-address": ["10.0.0.0/8"],
        "url-rewrite": [r"^https://ad\.com _ reject", "(broken _ reject"],
        "header-rewrite": [r"^https://a\.com header-del Cookie"],
        "body-rewrite": [r"http-response-jq ^https://a\.com '.a'"],
        "map-local": [r"^https://a\.com/m data-type=text data=ok"],
        "script": ["daily = type=cron, cronexp=0 8 * * *, script-path=a.js"],
    });
    let result = rig
        .control
        .mitm_validate(MitmValidateParams { config })
        .await
        .unwrap();
    let kinds: Vec<(&str, u32, MitmIssueKind)> = result
        .issues
        .iter()
        .flat_map(|(list, issues)| {
            issues
                .iter()
                .map(move |issue| (list.as_str(), issue.index, issue.kind))
        })
        .collect();
    assert_eq!(
        kinds,
        vec![
            ("hostname", 0, MitmIssueKind::Invalid),
            ("url-rewrite", 1, MitmIssueKind::Pattern),
        ]
    );
    let view = |list: &str, index: u32| {
        result.views[list]
            .iter()
            .find(|entry| entry.index == index)
            .map(|entry| entry.view.clone())
    };
    assert_eq!(
        view("hostname", 0),
        Some(MitmLineView::Hosts(MitmHosts {
            entries: vec![MitmHostEntry {
                host: "a.com".into(),
                port: None,
                exclude: false,
            }],
        }))
    );
    assert!(matches!(
        view("hostname", 1),
        Some(MitmLineView::Hosts(MitmHosts { ref entries })) if entries[0].port == Some(8443) && entries[0].exclude
    ));
    assert!(matches!(
        view("client-source-address", 0),
        Some(MitmLineView::Sources(MitmSources { ref entries })) if entries[0].network == "10.0.0.0/8"
    ));
    assert!(matches!(
        view("url-rewrite", 0),
        Some(MitmLineView::UrlRewrite(MitmUrlRewrite {
            action: MitmUrlAction::Reject,
            replacement: None,
            ..
        }))
    ));
    assert_eq!(view("url-rewrite", 1), None);
    assert!(matches!(
        view("header-rewrite", 0),
        Some(MitmLineView::HeaderRewrite(MitmHeaderRewrite { action: MitmHeaderAction::HeaderDel, ref name, .. })) if name.as_deref() == Some("Cookie")
    ));
    assert!(matches!(
        view("body-rewrite", 0),
        Some(MitmLineView::BodyRewrite(MitmBodyRewrite { phase: MitmPhase::Response, ref jq, .. })) if jq.as_deref() == Some(".a")
    ));
    assert!(matches!(
        view("map-local", 0),
        Some(MitmLineView::MapLocal(MitmMapLocal {
            data_type: MitmDataType::Text,
            status: Some(200),
            ..
        }))
    ));
    assert!(matches!(
        view("script", 0),
        Some(MitmLineView::Script(MitmScript { kind: MitmScriptKind::Cron, ref name, .. })) if name == "daily"
    ));
    rig.finish().await;
}
