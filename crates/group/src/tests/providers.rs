use std::time::Duration;

use concord_common::sync::lock;
use tokio_util::sync::CancellationToken;

use super::*;
use crate::{ProviderError, VehicleType};

const FILE_PROVIDER: &str = "proxy-providers:
  p:
    type: file
    path: p.yaml
proxy-groups:
  - {name: g, type: select, use: [p]}
";

const HTTP_PROVIDER: &str = "proxy-providers:
  p:
    type: http
    url: http://sub.test/list
    path: sub.yaml
    interval: 3600
proxy-groups:
  - {name: g, type: select, use: [p]}
";

fn list(names: &[&str]) -> String {
    let mut text = String::from("proxies:\n");
    for name in names {
        text.push_str(&format!("  - {{name: {name}, type: direct}}\n"));
    }
    text
}

fn names(rig: &Rig, group: &str) -> Vec<String> {
    rig.out
        .group(group)
        .unwrap()
        .members()
        .nodes()
        .iter()
        .map(|node| node.name().to_string())
        .collect()
}

fn write_file(rig: &Rig, text: &str) {
    std::fs::write(rig.out.provider("p").unwrap().path(), text).unwrap();
}

#[tokio::test]
async fn a_file_provider_loads_from_the_home_directory() {
    let rig = Rig::new(FILE_PROVIDER);
    write_file(&rig, &list(&["n1", "n2"]));
    let provider = rig.out.provider("p").unwrap();
    assert_eq!(provider.vehicle_type(), VehicleType::File);
    assert!(provider.initial().await.is_ok());
    assert_eq!(names(&rig, "g"), ["n1", "n2"]);
    assert_eq!(provider.view().count, 2);
    assert_eq!(rig.leaf("g"), "n1");
}

#[tokio::test]
async fn a_path_outside_the_home_directory_is_refused() {
    let escaped = FILE_PROVIDER.replace("p.yaml", "../p.yaml");
    let built = Rig::try_with(&profile(&escaped), Arc::new(SelectionStore::new()), None);
    let message = built.err().unwrap().to_string();
    assert!(
        message.starts_with("parse proxy provider p error: path ")
            && message.ends_with(": ../p.yaml"),
        "{message}"
    );
}

fn answered() -> CancellationToken {
    let token = CancellationToken::new();
    token.cancel();
    token
}

fn phases(rig: &Rig) -> Vec<ResourcePhase> {
    rig.events
        .resources()
        .into_iter()
        .map(|(name, phase)| {
            assert_eq!(name, "p");
            phase
        })
        .collect()
}

async fn until_phases(rig: &Rig, count: usize) -> Vec<ResourcePhase> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let seen = phases(rig);
        if seen.len() >= count {
            return seen;
        }
        assert!(tokio::time::Instant::now() < deadline, "only {seen:?}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(start_paused = true)]
async fn the_first_load_reports_every_step_once_the_apply_has_answered() {
    let rig = Rig::new(FILE_PROVIDER);
    write_file(&rig, &list(&["n1"]));
    let (stop, answered) = (CancellationToken::new(), CancellationToken::new());
    rig.out.start_background(stop.clone(), answered.clone());
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(names(&rig, "g"), ["n1"]);
    assert_eq!(phases(&rig), []);
    answered.cancel();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        phases(&rig),
        [ResourcePhase::Updating, ResourcePhase::Updated]
    );
    stop.cancel();
}

#[tokio::test]
async fn a_file_provider_reloads_when_its_file_is_rewritten() {
    let rig = Rig::new(FILE_PROVIDER);
    write_file(&rig, &list(&["n1"]));
    let stop = CancellationToken::new();
    rig.out.start_background(stop.clone(), answered());
    until_phases(&rig, 2).await;
    assert_eq!(names(&rig, "g"), ["n1"]);

    write_file(&rig, &list(&["n1", "n2", "n3"]));
    let seen = until_phases(&rig, 4).await;
    assert_eq!(seen[2..], [ResourcePhase::Updating, ResourcePhase::Updated]);
    assert_eq!(names(&rig, "g").len(), 3);
    stop.cancel();
}

#[tokio::test(start_paused = true)]
async fn a_provider_that_fails_to_load_reports_the_failure() {
    let rig = Rig::new(FILE_PROVIDER);
    let stop = CancellationToken::new();
    rig.out.start_background(stop.clone(), answered());
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(matches!(
        phases(&rig).as_slice(),
        [ResourcePhase::Updating, ResourcePhase::Failed(_)]
    ));
    stop.cancel();
}

#[tokio::test(start_paused = true)]
async fn an_http_provider_reports_every_fetch_whatever_started_it() {
    let rig = Rig::new(HTTP_PROVIDER);
    let stop = CancellationToken::new();
    rig.out.start_background(stop.clone(), answered());
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(matches!(
        phases(&rig).as_slice(),
        [ResourcePhase::Updating, ResourcePhase::Failed(_)]
    ));

    rig.fetcher
        .serve_with("http://sub.test/list", 200, &[], &list(&["n1"]));
    tokio::time::sleep(Duration::from_secs(11)).await;
    assert_eq!(
        phases(&rig)[2..],
        [ResourcePhase::Updating, ResourcePhase::Updated]
    );
    assert_eq!(names(&rig, "g"), ["n1"]);

    tokio::time::sleep(Duration::from_secs(3600)).await;
    assert_eq!(
        phases(&rig)[4..],
        [ResourcePhase::Updating, ResourcePhase::Unchanged]
    );

    let provider = rig.out.provider("p").unwrap();
    rig.fetcher
        .serve_with("http://sub.test/list", 200, &[], &list(&["n2"]));
    provider.update().await.unwrap();
    assert_eq!(
        phases(&rig)[6..],
        [ResourcePhase::Updating, ResourcePhase::Updated]
    );
    provider.side_load(list(&["n2"]).as_bytes()).await.unwrap();
    assert_eq!(
        phases(&rig)[8..],
        [ResourcePhase::Updating, ResourcePhase::Unchanged]
    );
    stop.cancel();
}

#[tokio::test]
async fn an_inline_provider_is_ready_at_build_and_takes_no_side_load() {
    let rig = Rig::new(
        "proxy-providers:
  p:
    type: inline
    payload:
      - {name: n1, type: direct}
proxy-groups:
  - {name: g, type: select, use: [p]}
",
    );
    assert_eq!(names(&rig, "g"), ["n1"]);
    let provider = rig.out.provider("p").unwrap();
    assert!(matches!(
        provider.side_load(b"proxies: []").await,
        Err(ProviderError::Io(_))
    ));
    assert_eq!(provider.vehicle_type(), VehicleType::Inline);
}

#[tokio::test]
async fn an_update_swaps_the_members_the_pick_and_the_exit() {
    let rig = Rig::new(FILE_PROVIDER);
    write_file(&rig, &list(&["n1", "n2"]));
    let provider = rig.out.provider("p").unwrap();
    provider.initial().await.unwrap();
    rig.out.select("g", "n2").await;
    assert_eq!(rig.leaf("g"), "n2");
    let before = rig.out.exit_identity(&rig.resolve("g")).unwrap();
    let moved = rig.moved.count();

    provider
        .side_load(list(&["n1", "n3"]).as_bytes())
        .await
        .unwrap();

    assert_eq!(names(&rig, "g"), ["n1", "n3"]);
    assert_eq!(rig.leaf("g"), "n1");
    assert!(rig.moved.count() > moved);
    let after = rig.out.exit_identity(&rig.resolve("g")).unwrap();
    assert_ne!(before, after);
    assert!(after.starts_with("\"n1\""), "{after}");
    assert_eq!(
        std::fs::read_to_string(provider.path()).unwrap(),
        list(&["n1", "n3"])
    );
}

#[tokio::test]
async fn a_second_update_while_one_runs_is_told_it_is_updating() {
    let rig = Rig::new(FILE_PROVIDER);
    write_file(&rig, &list(&["n1"]));
    let provider = rig.out.provider("p").unwrap();
    provider.initial().await.unwrap();
    let first = list(&["n1", "n2"]);
    let second = list(&["n1", "n3"]);
    let (one, two) = tokio::join!(
        provider.side_load(first.as_bytes()),
        provider.side_load(second.as_bytes())
    );
    assert!(one.is_ok());
    assert!(matches!(two, Err(ProviderError::Updating)));
}

#[tokio::test]
async fn bad_content_is_refused_and_the_old_nodes_stay() {
    let rig = Rig::new(FILE_PROVIDER);
    write_file(&rig, &list(&["n1"]));
    let provider = rig.out.provider("p").unwrap();
    provider.initial().await.unwrap();
    let err = provider.side_load(b"proxies: []").await.unwrap_err();
    assert!(matches!(err, ProviderError::Content(_)), "{err}");
    assert_eq!(names(&rig, "g"), ["n1"]);
}

#[tokio::test]
async fn an_http_provider_keeps_the_subscription_info_and_the_file() {
    let rig = Rig::new(HTTP_PROVIDER);
    rig.fetcher.serve_with(
        "http://sub.test/list",
        200,
        &[(
            "Subscription-Userinfo",
            "upload=1; download=2; total=10; expire=7",
        )],
        &list(&["n1"]),
    );
    let provider = rig.out.provider("p").unwrap();
    provider.update().await.unwrap();
    assert_eq!(names(&rig, "g"), ["n1"]);
    let info = provider.subscription_info().unwrap();
    assert_eq!(
        (info.upload, info.download, info.total, info.expire),
        (1, 2, 10, 7)
    );
    assert!(provider.updated_at().is_some());
    assert!(std::fs::metadata(provider.path()).is_ok());
    assert!(std::fs::metadata(format!("{}.subscription-info", provider.path())).is_ok());
    assert_eq!(lock(&rig.fetcher.requests).len(), 1);
}

#[tokio::test]
async fn a_restart_reads_the_cached_file_and_info_without_the_network() {
    let first = Rig::new(HTTP_PROVIDER);
    first.fetcher.serve_with(
        "http://sub.test/list",
        200,
        &[("subscription-userinfo", "total=99")],
        &list(&["n1"]),
    );
    first.out.provider("p").unwrap().update().await.unwrap();
    let path = first.out.provider("p").unwrap().path();

    let second = Rig::new(HTTP_PROVIDER);
    let again = second.out.provider("p").unwrap();
    std::fs::copy(&path, again.path()).unwrap();
    std::fs::copy(
        format!("{path}.subscription-info"),
        format!("{}.subscription-info", again.path()),
    )
    .unwrap();
    again.initial().await.unwrap();
    assert_eq!(names(&second, "g"), ["n1"]);
    assert_eq!(again.subscription_info().unwrap().total, 99);
    assert!(lock(&second.fetcher.requests).is_empty());
}

#[tokio::test]
async fn an_http_error_status_carries_its_code() {
    let rig = Rig::new(HTTP_PROVIDER);
    rig.fetcher.serve_with("http://sub.test/list", 404, &[], "");
    let err = rig.out.provider("p").unwrap().update().await.unwrap_err();
    assert_eq!(err.status_code(), Some(404));
    assert_eq!(err.to_string(), "404 Not Found");
}

#[tokio::test]
async fn a_providers_payload_stands_in_until_a_load_succeeds() {
    let text = HTTP_PROVIDER.replace(
        "    interval: 3600\n",
        "    interval: 3600\n    payload:\n      - {name: spare, type: direct}\n",
    );
    let rig = Rig::new(&text);
    let provider = rig.out.provider("p").unwrap();
    assert_eq!(names(&rig, "g"), ["spare"]);
    assert!(provider.initial().await.is_err());
    assert_eq!(names(&rig, "g"), ["spare"]);
    rig.fetcher
        .serve_with("http://sub.test/list", 200, &[], &list(&["n1"]));
    provider.update().await.unwrap();
    assert_eq!(names(&rig, "g"), ["n1"]);
}

#[tokio::test]
async fn a_network_error_is_a_fetch_error() {
    let rig = Rig::new(HTTP_PROVIDER);
    let err = rig.out.provider("p").unwrap().update().await.unwrap_err();
    assert!(matches!(err, ProviderError::Fetch(_)), "{err}");
}

#[tokio::test]
async fn definition_returns_the_mapping_of_a_provider_node_only() {
    let rig = Rig::new(
        "proxies:
  - {name: own, type: direct}
proxy-providers:
  p:
    type: inline
    payload:
      - {name: n1, type: direct}
proxy-groups:
  - {name: g, type: select, use: [p]}
",
    );
    let map = rig.out.definition("n1").await.unwrap();
    assert_eq!(map.get("name").and_then(|name| name.as_str()), Some("n1"));
    assert!(rig.out.definition("own").await.is_none());
    assert!(rig.out.definition("g").await.is_none());
}

#[tokio::test]
async fn an_unsupported_node_in_a_provider_is_listed_nowhere_but_still_named() {
    let rig = Rig::new(
        "proxy-providers:
  p:
    type: inline
    payload:
      - {name: ok, type: direct}
      - {name: ghost, type: tailscale}
proxy-groups:
  - {name: g, type: select, use: [p]}
",
    );
    assert_eq!(names(&rig, "g"), ["ok"]);
    let group = rig.out.group("g").unwrap();
    assert_eq!(group.members().ghosts().len(), 1);
    assert!(matches!(rig.resolve("ghost"), Resolved::Rejected(_)));
}

fn extra_interval(group: &str) -> Duration {
    let rig = Rig::new(&format!(
        "proxy-providers:
  p:
    type: file
    path: p.yaml
proxy-groups:
  - {{name: g, type: url-test, proxies: [DIRECT], use: [p], url: 'http://extra.test/', {group}}}
"
    ));
    rig.out.provider("p").unwrap().check().interval()
}

#[test]
fn an_explicit_zero_interval_registers_zero_on_the_provider() {
    assert_eq!(extra_interval("interval: 0"), Duration::ZERO);
    assert_eq!(extra_interval("other: 1"), Duration::ZERO);
    assert_eq!(extra_interval("interval: 90"), Duration::from_secs(90));
}
