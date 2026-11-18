use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use concord_common::intercept::Offer;
use concord_common::sync::lock;
use serde_json::json;

use crate::limits::{PRESSURE_NO_BODIES, PRESSURE_NO_SCRIPTS, PRESSURE_RELAY};
use crate::script::testkit::{FakeRuntime, sync_program};
use crate::script::{
    EVENT_ENGINE_STARTED, EVENT_NETWORK_CHANGED, ScriptError, ScriptProgram, ScriptResponse,
    ScriptResult, ScriptRuntime,
};
use crate::task::ScriptRunError;
use crate::testing::{
    Client, Handler, Reply, Rig, TestServer, eventually, flow, offer_on, rig_for, start_server,
};

fn echo() -> Handler {
    Arc::new(|seen| {
        let text = |name: &str| {
            seen.headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string()
        };
        Reply::ok(&format!(
            "{}|{}|{}|{}",
            seen.host,
            seen.path,
            text("x-added"),
            String::from_utf8_lossy(&seen.body)
        ))
    })
}

async fn scripted(programs: Vec<(&str, Arc<dyn ScriptProgram>)>) -> (TestServer, Rig) {
    let server = start_server(true, &["http/1.1", "h2"], echo()).await;
    let mut runtime = FakeRuntime::default();
    for (name, program) in &programs {
        runtime.0.insert((*name).to_string(), program.clone());
    }
    let rig = rig_for(&server, Some(Arc::new(runtime) as Arc<dyn ScriptRuntime>));
    std::fs::create_dir_all(rig.resources()).unwrap();
    for (name, _) in &programs {
        std::fs::write(rig.resources().join(format!("{name}.js")), name).unwrap();
    }
    (server, rig)
}

fn config(scripts: serde_json::Value) -> serde_json::Value {
    json!({"enable": true, "hostname": ["example.test"], "skip-server-cert-verify": true, "script": scripts})
}

fn adds_header() -> Arc<dyn ScriptProgram> {
    sync_program(|invocation| {
        let mut header = invocation.request.as_ref().unwrap().header.clone();
        header.insert("X-Added".into(), vec!["from-script".into()]);
        Ok(ScriptResult {
            header: Some(header),
            ..ScriptResult::default()
        })
    })
}

#[tokio::test]
async fn a_request_script_rewrites_answers_and_aborts() {
    let answer = sync_program(|_| {
        Ok(ScriptResult {
            response: Some(ScriptResponse {
                status: 418,
                header: [(
                    "Content-Type".to_string(),
                    vec!["application/json".to_string()],
                )]
                .into(),
                body: Some(b"tea".to_vec()),
            }),
            ..ScriptResult::default()
        })
    });
    let abort = sync_program(|_| {
        Ok(ScriptResult {
            abort: true,
            ..ScriptResult::default()
        })
    });
    let never_ran = Arc::new(AtomicUsize::new(0));
    let never = {
        let never_ran = never_ran.clone();
        sync_program(move |_| {
            never_ran.fetch_add(1, Ordering::SeqCst);
            Ok(ScriptResult::default())
        })
    };
    let (server, rig) = scripted(vec![
        ("rewrite", adds_header()),
        ("answer", answer),
        ("abort", abort),
        ("never", never),
    ])
    .await;
    let errors = rig.config(config(json!([
        r"A = type=http-request,pattern=^https://example\.test/rewrite,script-path=rewrite.js",
        r"B = type=http-request,pattern=^https://example\.test/answer,script-path=answer.js",
        r"C = type=http-request,pattern=^https://example\.test/abort,script-path=abort.js",
        r"D = type=http-response,pattern=^https://example\.test/answer,script-path=never.js",
    ])));
    assert!(errors.is_empty(), "{errors:?}");
    rig.mitm.set_capture(true);
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    assert_eq!(
        client.get("/rewrite").await.text(),
        "example.test|/rewrite|from-script|"
    );
    let answered = client.get("/answer").await;
    assert_eq!(
        (
            answered.status.as_u16(),
            answered.text().as_str(),
            answered.header("content-type").as_str()
        ),
        (418, "tea", "application/json")
    );
    assert_eq!(
        never_ran.load(Ordering::SeqCst),
        0,
        "a response script ran on an answered request"
    );
    assert_eq!(
        server.requests().len(),
        1,
        "an answered request never reaches the server"
    );
    let mut second = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    let request = second.request("GET", "/abort", &[], "");
    assert!(
        second.send(request).await.is_err(),
        "an abort drops the connection"
    );
    assert!(
        lock(&rig.dialer.closed)
            .iter()
            .any(|(_, chain)| chain == &["SCRIPT"])
    );
}

#[tokio::test]
async fn a_response_script_rewrites_status_and_body() {
    let program = sync_program(|invocation| {
        let body = invocation
            .response
            .as_ref()
            .unwrap()
            .body
            .clone()
            .unwrap_or_default();
        let mut changed = body.clone();
        changed.extend_from_slice(b"+script");
        Ok(ScriptResult {
            status: 201,
            body: Some(changed),
            ..ScriptResult::default()
        })
    });
    let (_server, rig) = scripted(vec![("respond", program)]).await;
    rig.config(config(json!([
        r"R = type=http-response,pattern=^https://example\.test/,requires-body=1,script-path=respond.js",
    ])));
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    let answer = client.get("/p").await;
    assert_eq!(
        (answer.status.as_u16(), answer.text().as_str()),
        (201, "example.test|/p||+script")
    );
    assert_eq!(
        answer.header("content-length"),
        answer.body.len().to_string()
    );
}

#[tokio::test]
async fn a_failing_script_leaves_the_exchange_alone_and_the_first_match_runs() {
    let counted = Arc::new(AtomicUsize::new(0));
    let first = {
        let counted = counted.clone();
        sync_program(move |_| {
            counted.fetch_add(1, Ordering::SeqCst);
            Err(ScriptError("boom".into()))
        })
    };
    let (_server, rig) = scripted(vec![("first", first), ("second", adds_header())]).await;
    rig.config(config(json!([
        r"A = type=http-request,pattern=^https://example\.test/,script-path=first.js",
        r"B = type=http-request,pattern=^https://example\.test/,script-path=second.js",
    ])));
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    assert_eq!(client.get("/p").await.text(), "example.test|/p||");
    assert_eq!(counted.load(Ordering::SeqCst), 1);
}

fn appends(mark: &'static str) -> Arc<dyn ScriptProgram> {
    sync_program(move |invocation| {
        let mut body = invocation
            .response
            .as_ref()
            .unwrap()
            .body
            .clone()
            .unwrap_or_default();
        body.extend_from_slice(mark.as_bytes());
        Ok(ScriptResult {
            body: Some(body),
            ..ScriptResult::default()
        })
    })
}

#[tokio::test]
async fn a_script_runs_only_on_the_heads_its_conditions_match() {
    let (_server, rig) = scripted(vec![
        ("adds", adds_header()),
        ("missing", appends("+404")),
        ("found", appends("+found")),
    ])
    .await;
    rig.config(config(json!([
        r"A = type=http-request,pattern=^https://example\.test/,request-head=^POST,script-path=adds.js",
        r#"M = type=http-response,pattern=^https://example\.test/,response-head="^\S+ 404 ",requires-body=1,script-path=missing.js"#,
        r#"F = type=http-response,pattern=^https://example\.test/,request-head="^GET ",requires-body=1,script-path=found.js"#,
    ])));
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    assert_eq!(client.get("/p").await.text(), "example.test|/p||+found");
    let request = client.request("POST", "/p", &[], "body");
    assert_eq!(
        client.send(request).await.unwrap().text(),
        "example.test|/p|from-script|body"
    );
}

#[tokio::test]
async fn pressure_sheds_scripts_then_bodies_then_the_relay() {
    let counted = Arc::new(AtomicUsize::new(0));
    let program = {
        let counted = counted.clone();
        sync_program(move |_| {
            counted.fetch_add(1, Ordering::SeqCst);
            Ok(ScriptResult::default())
        })
    };
    let (_server, rig) = scripted(vec![("count", program)]).await;
    rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "script": [r"A = type=http-request,pattern=^https://example\.test/,script-path=count.js"],
        "body-rewrite": [r"http-response ^https://example\.test/ world there"],
    }));
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    client.get("/a").await;
    assert_eq!(counted.load(Ordering::SeqCst), 1);

    rig.mitm.set_pressure(PRESSURE_NO_SCRIPTS);
    let request = client.request("POST", "/b", &[], "hello world");
    assert!(
        client
            .send(request)
            .await
            .unwrap()
            .text()
            .ends_with("|hello there"),
        "bodies are still rewritten"
    );
    assert_eq!(counted.load(Ordering::SeqCst), 1, "scripts are paused");

    rig.mitm.set_pressure(PRESSURE_NO_BODIES);
    let request = client.request("POST", "/c", &[], "hello world");
    assert!(
        client
            .send(request)
            .await
            .unwrap()
            .text()
            .ends_with("|hello world")
    );

    rig.mitm.set_pressure(PRESSURE_RELAY);
    assert!(
        !rig.mitm
            .engine()
            .unwrap()
            .match_tcp(&flow("example.test", 443)),
        "decrypting under the relay level"
    );
    let (_near, offer) = offer_on(rig.mitm.interceptor(), flow("example.test", 443));
    drop(_near);
    match tokio::time::timeout(Duration::from_secs(10), offer)
        .await
        .unwrap()
        .unwrap()
    {
        Offer::Declined { .. } => {}
        Offer::Taken => panic!("a relay level takes no new connection"),
    }
}

#[tokio::test]
async fn sessions_past_the_limit_are_relayed() {
    let (_server, rig) = scripted(vec![]).await;
    rig.config(json!({"enable": true, "hostname": ["example.test"], "skip-server-cert-verify": true, "limits": {"max-sessions": 1}}));
    let mut first = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    first.get("/").await;
    let probe = flow("example.test", 443);
    let (mut near, offer) = offer_on(rig.mitm.interceptor(), probe);
    let hello = crate::engine_tests::hello("example.test", &["http/1.1"]);
    tokio::io::AsyncWriteExt::write_all(&mut near, &hello)
        .await
        .unwrap();
    assert!(matches!(offer.await.unwrap(), Offer::Declined { .. }));
    let engine = rig.mitm.engine().unwrap();
    assert_eq!(engine.core.open_sessions(), 1);
    drop(first);
    eventually(|| engine.core.open_sessions() == 0).await;
}

#[tokio::test]
async fn captures_file_exchanges_under_their_connection() {
    let (_server, rig) = scripted(vec![]).await;
    rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "url-rewrite": [r"^https://example\.test/ad _ reject"],
        "map-local": [r#"^https://example\.test/local data-type=text data="{}""#],
    }));
    rig.mitm.set_capture(true);
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    client.get("/p?x=1").await;
    client.get("/ad").await;
    client.get("/local").await;
    let listed = rig.mitm.exchanges("conn-1");
    assert!(listed.capturing);
    let urls: Vec<&str> = listed.exchanges.iter().map(|e| e.url.as_str()).collect();
    assert_eq!(urls, ["https://example.test/p?x=1"]);
    assert_eq!(listed.exchanges[0].status, 200);
    let closed = lock(&rig.dialer.closed).clone();
    let chains: Vec<&str> = closed.iter().map(|(_, chain)| chain[0].as_str()).collect();
    assert_eq!(chains, ["REJECT", "MAP-LOCAL"]);
    let exchange = rig.mitm.exchange(listed.exchanges[0].id).unwrap();
    assert_eq!(exchange.connection, "conn-1");
    let body = rig.mitm.body(exchange.summary.id, true).unwrap();
    assert_eq!(body.data, b"example.test|/p?x=1||");
    rig.mitm.set_capture(false);
    client.get("/q").await;
    assert!(rig.mitm.exchanges("conn-1").exchanges.len() <= 1);
}

#[tokio::test]
async fn an_unreachable_server_is_listed_with_its_error() {
    let (_server, rig) = scripted(vec![]).await;
    rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "url-rewrite": [r"^https://example\.test/(.*) https://down.test/$1"],
    }));
    rig.dialer.reject("down.test");
    rig.mitm.set_capture(true);
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    assert_eq!(client.get("/p").await.status.as_u16(), 502);
    let chains: Vec<String> = lock(&rig.dialer.closed)
        .iter()
        .map(|(_, chain)| chain.join(","))
        .collect();
    assert_eq!(chains, ["REJECT"]);
}

#[tokio::test]
async fn tasks_run_while_started_and_the_user_can_run_them() {
    let runs = Arc::new(AtomicUsize::new(0));
    let program = {
        let runs = runs.clone();
        sync_program(move |invocation| {
            runs.fetch_add(1, Ordering::SeqCst);
            if let Some(console) = &invocation.console {
                console("hello from the task");
            }
            Ok(ScriptResult {
                value: br#"{"ok":true}"#.to_vec(),
                ..ScriptResult::default()
            })
        })
    };
    let (_server, rig) = scripted(vec![("task", program)]).await;
    rig.config(config(json!([
        format!("Boot = type=event,event-name={EVENT_ENGINE_STARTED},script-path=task.js"),
        "Tool = script-path=task.js".to_string(),
    ])));
    assert_eq!(runs.load(Ordering::SeqCst), 0);
    rig.mitm.set_running(true);
    eventually(|| runs.load(Ordering::SeqCst) == 1).await;
    let output = rig.mitm.run_script("Tool").await.unwrap();
    assert_eq!(
        (output.logs.as_slice(), output.result.as_str()),
        (&["hello from the task".to_string()][..], r#"{"ok":true}"#)
    );
    assert!(matches!(
        rig.mitm.run_script("Nope").await,
        Err(ScriptRunError::NotFound(name)) if name == "Nope"
    ));
    rig.mitm.set_running(false);
    rig.mitm.notify(EVENT_ENGINE_STARTED);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(runs.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn the_plain_http_side_works_without_decrypting_tls() {
    let server = start_server(false, &[], echo()).await;
    let rig = rig_for(&server, None);
    rig.config(json!({"enable": true, "hostname": ["example.test"], "decrypt-tls": false, "url-rewrite": [r"^http://example\.test/ad _ reject"]}));
    let mut client = Client::plain(&rig, "example.test", 80).await;
    assert_eq!(client.get("/ad").await.status.as_u16(), 404);
    let hello = crate::engine_tests::hello("example.test", &["http/1.1"]);
    let (mut near, offer) = offer_on(rig.mitm.interceptor(), flow("example.test", 443));
    tokio::io::AsyncWriteExt::write_all(&mut near, &hello)
        .await
        .unwrap();
    assert!(matches!(offer.await.unwrap(), Offer::Declined { .. }));
}

#[tokio::test]
async fn only_the_expected_ca_decrypts_and_a_renewed_one_ends_sessions() {
    let server = start_server(true, &["http/1.1"], echo()).await;
    let rig = rig_for(&server, None);
    let info = rig.mitm.certificate().unwrap().unwrap();
    rig.config(json!({"enable": true, "hostname": ["example.test"], "skip-server-cert-verify": true, "ca-fingerprint": "00".repeat(32)}));
    let hello = crate::engine_tests::hello("example.test", &["http/1.1"]);
    let (mut near, offer) = offer_on(rig.mitm.interceptor(), flow("example.test", 443));
    tokio::io::AsyncWriteExt::write_all(&mut near, &hello)
        .await
        .unwrap();
    assert!(matches!(offer.await.unwrap(), Offer::Declined { .. }));

    let written = crate::ca::generate_ca(rig.mitm.authority().home()).unwrap();
    assert_ne!(written.fingerprint(), info.fingerprint);
    rig.config(json!({"enable": true, "hostname": ["example.test"], "skip-server-cert-verify": true, "ca-fingerprint": written.fingerprint()}));
    assert_eq!(
        rig.mitm.authority().current().unwrap().fingerprint(),
        written.fingerprint(),
        "the CA another process wrote was not read"
    );
    let ours = rig.mitm.certificate().unwrap().unwrap();
    let (_, pem) = x509_parser::pem::parse_x509_pem(ours.pem.as_bytes()).unwrap();
    let mut rig = rig;
    rig.root = rustls::pki_types::CertificateDer::from(pem.contents);
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    client.get("/").await;
    rig.mitm.generate_certificate().unwrap();
    let request = client.request("GET", "/again", &[], "");
    assert!(
        client.send(request).await.is_err(),
        "the renewed CA closes what the old one decrypted"
    );
}

fn header_value(header: &crate::script::HeaderList, name: &str) -> String {
    header
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .and_then(|(_, values)| values.first().cloned())
        .unwrap_or_default()
}

#[tokio::test]
async fn a_request_script_sees_the_request_and_rewrites_its_url_and_body() {
    let seen = Arc::new(std::sync::Mutex::new(String::new()));
    let program = {
        let seen = seen.clone();
        sync_program(move |invocation| {
            let request = invocation.request.as_ref().unwrap();
            *lock(&seen) = format!(
                "{} {} {} {} {} {}",
                invocation.kind,
                request.method,
                request.url,
                header_value(&request.header, "host"),
                String::from_utf8_lossy(request.body.as_deref().unwrap_or_default()),
                !request.id.is_empty()
            );
            let mut header = request.header.clone();
            header.insert("X-Script".into(), vec!["yes".into()]);
            header.insert("Content-Length".into(), vec!["1".into()]);
            Ok(ScriptResult {
                url: "https://example.test/moved".into(),
                header: Some(header),
                body: Some(b"changed".to_vec()),
                ..ScriptResult::default()
            })
        })
    };
    let (_server, rig) = scripted(vec![("req", program)]).await;
    rig.config(config(json!([
        r"req = type=http-request,pattern=^https://example\.test/post,requires-body=true,script-path=req.js",
    ])));
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    let request = client.request("POST", "/post", &[], "original");
    assert_eq!(
        client.send(request).await.unwrap().text(),
        "example.test|/moved||changed"
    );
    assert_eq!(
        *lock(&seen),
        "http-request POST https://example.test/post example.test original true"
    );
}

#[tokio::test]
async fn a_response_script_gets_a_decoded_body_and_the_request_id() {
    let ids = Arc::new(std::sync::Mutex::new((String::new(), String::new())));
    let tag = {
        let ids = ids.clone();
        sync_program(move |invocation| {
            lock(&ids).0 = invocation.request.as_ref().unwrap().id.clone();
            Ok(ScriptResult::default())
        })
    };
    let respond = {
        let ids = ids.clone();
        sync_program(move |invocation| {
            lock(&ids).1 = invocation.request.as_ref().unwrap().id.clone();
            let response = invocation.response.as_ref().unwrap();
            if !header_value(&response.header, "content-encoding").is_empty() {
                return Err(ScriptError("the script got an encoded body".into()));
            }
            let mut header = response.header.clone();
            header.insert("X-Status".into(), vec![response.status.to_string()]);
            let body = String::from_utf8(response.body.clone().unwrap_or_default())
                .unwrap()
                .replace(r#""ad":true"#, r#""ad":false"#);
            Ok(ScriptResult {
                status: 299,
                header: Some(header),
                body: Some(body.into_bytes()),
                ..ScriptResult::default()
            })
        })
    };
    let handler: Handler = Arc::new(|seen| {
        assert_eq!(seen.headers.get("accept-encoding").unwrap(), "identity");
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, br#"{"ad":true,"items":[]}"#).unwrap();
        Reply {
            status: 200,
            headers: vec![("Content-Encoding".into(), "gzip".into())],
            body: gz.finish().unwrap(),
        }
    });
    let server = start_server(true, &["h2", "http/1.1"], handler).await;
    let mut runtime = FakeRuntime::default();
    runtime.0.insert("tag".into(), tag);
    runtime.0.insert("resp".into(), respond);
    let rig = rig_for(&server, Some(Arc::new(runtime) as Arc<dyn ScriptRuntime>));
    std::fs::create_dir_all(rig.resources()).unwrap();
    for name in ["tag", "resp"] {
        std::fs::write(rig.resources().join(format!("{name}.js")), name).unwrap();
    }
    let errors = rig.config(json!({
        "enable": true,
        "hostname": ["example.test"],
        "skip-server-cert-verify": true,
        "h2": true,
        "script": [
            r"tag = type=http-request,pattern=^https://example\.test/api,script-path=tag.js",
            r"resp = type=http-response,pattern=^https://example\.test/api,requires-body=true,script-path=resp.js",
        ],
    }));
    assert!(errors.is_empty(), "{errors:?}");
    let mut client = Client::tls(&rig, "example.test", 443, &["h2"])
        .await
        .unwrap();
    let request = client.request("GET", "/api", &[("Accept-Encoding", "gzip")], "");
    let answer = client.send(request).await.unwrap();
    assert_eq!(
        (
            answer.status.as_u16(),
            answer.header("x-status").as_str(),
            answer.text().as_str()
        ),
        (299, "200", r#"{"ad":false,"items":[]}"#)
    );
    assert_eq!(answer.header("content-encoding"), "");
    let (request_id, response_id) = lock(&ids).clone();
    assert!(!request_id.is_empty() && request_id == response_id);
}

#[tokio::test]
async fn scripts_leave_what_they_fail_on_time_out_on_or_cannot_read() {
    let runs = Arc::new(AtomicUsize::new(0));
    let counted = |result: fn() -> Result<ScriptResult, ScriptError>| {
        let runs = runs.clone();
        sync_program(move |_| {
            runs.fetch_add(1, Ordering::SeqCst);
            result()
        })
    };
    let hangs: Arc<dyn ScriptProgram> = {
        let runs = runs.clone();
        Arc::new(crate::script::testkit::FakeProgram(Arc::new(move |_| {
            runs.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::pending())
        })))
    };
    fn replace(text: &str) -> Result<ScriptResult, ScriptError> {
        Ok(ScriptResult {
            body: Some(text.as_bytes().to_vec()),
            ..ScriptResult::default()
        })
    }
    let handler: Handler = Arc::new(|seen| match seen.path.as_str() {
        "/binary" => Reply {
            status: 200,
            headers: Vec::new(),
            body: vec![0xff, 0xfe, 0x00],
        },
        _ => Reply::ok("upstream body"),
    });
    let server = start_server(true, &["http/1.1"], handler).await;
    let mut runtime = FakeRuntime::default();
    for (name, program) in [
        (
            "throws",
            counted(|| Err(ScriptError("TypeError: undefined is not a function".into()))),
        ),
        ("hangs", hangs),
        ("small", counted(|| replace("small"))),
        ("text", counted(|| replace("text"))),
    ] {
        runtime.0.insert(name.into(), program);
    }
    let rig = rig_for(&server, Some(Arc::new(runtime) as Arc<dyn ScriptRuntime>));
    std::fs::create_dir_all(rig.resources()).unwrap();
    for name in ["throws", "hangs", "small", "text"] {
        std::fs::write(rig.resources().join(format!("{name}.js")), name).unwrap();
    }
    let errors = rig.config(config(json!([
        "throws = type=http-response,pattern=/throws,requires-body=1,script-path=throws.js",
        "hangs = type=http-response,pattern=/hangs,requires-body=1,timeout=0.2,script-path=hangs.js",
        "small = type=http-response,pattern=/small,requires-body=1,max-size=4,script-path=small.js",
        "text = type=http-response,pattern=/binary,requires-body=1,script-path=text.js",
    ])));
    assert!(errors.is_empty(), "{errors:?}");
    let mut client = Client::tls(&rig, "example.test", 443, &["http/1.1"])
        .await
        .unwrap();
    for path in ["/throws", "/hangs", "/small"] {
        let started = std::time::Instant::now();
        let answer = client.get(path).await;
        assert_eq!(
            (answer.status.as_u16(), answer.text().as_str()),
            (200, "upstream body"),
            "{path}"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "{path} took {:?}",
            started.elapsed()
        );
    }
    assert_eq!(client.get("/binary").await.body, [0xff, 0xfe, 0x00]);
    assert_eq!(
        runs.load(Ordering::SeqCst),
        2,
        "only the scripts whose bodies fit ran"
    );
}

#[derive(Clone, Debug, PartialEq)]
struct Run {
    name: String,
    kind: String,
    cronexp: String,
    event: String,
    trigger: String,
    argument: Option<serde_json::Value>,
}

fn recording(runs: Arc<std::sync::Mutex<Vec<Run>>>) -> Arc<dyn ScriptProgram> {
    sync_program(move |invocation| {
        lock(&runs).push(Run {
            name: invocation.name.clone(),
            kind: invocation.kind.clone(),
            cronexp: invocation.cronexp.clone(),
            event: invocation
                .event
                .as_ref()
                .map(|event| event.name.clone())
                .unwrap_or_default(),
            trigger: invocation.trigger.clone(),
            argument: invocation.argument.clone(),
        });
        Ok(ScriptResult::default())
    })
}

#[tokio::test]
async fn cron_scripts_run_while_started() {
    let runs = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (_server, rig) = scripted(vec![("tick", recording(runs.clone()))]).await;
    rig.config(config(json!([
        r#"Tick = type=cron,cronexp="* * * * * *",script-path=tick.js,argument=a"#,
    ])));
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert!(lock(&runs).is_empty(), "a cron script ran while stopped");
    rig.mitm.set_running(true);
    eventually(|| !lock(&runs).is_empty()).await;
    assert_eq!(
        lock(&runs)[0],
        Run {
            name: "Tick".into(),
            kind: "cron".into(),
            cronexp: "* * * * * *".into(),
            event: String::new(),
            trigger: String::new(),
            argument: Some(json!("a")),
        }
    );
    rig.mitm.set_running(false);
    tokio::time::sleep(Duration::from_millis(100)).await;
    let stopped = lock(&runs).len();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        lock(&runs).len(),
        stopped,
        "a cron script ran after the stop"
    );
}

#[tokio::test]
async fn event_scripts_run_on_their_event_while_started() {
    let runs = Arc::new(std::sync::Mutex::new(Vec::new()));
    let (_server, rig) = scripted(vec![("net", recording(runs.clone()))]).await;
    rig.config(config(json!([format!(
        "Net = type=event,event-name={EVENT_NETWORK_CHANGED},script-path=net.js"
    ),])));
    rig.mitm.notify(EVENT_NETWORK_CHANGED);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(lock(&runs).is_empty(), "ran while stopped");
    rig.mitm.set_running(true);
    rig.mitm.notify(EVENT_ENGINE_STARTED);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(lock(&runs).is_empty(), "ran on another event");
    rig.mitm.notify(EVENT_NETWORK_CHANGED);
    eventually(|| !lock(&runs).is_empty()).await;
    assert_eq!(lock(&runs)[0].event, EVENT_NETWORK_CHANGED);
}

#[tokio::test]
async fn the_user_runs_a_task_and_sees_what_it_wrote() {
    let tool = sync_program(|invocation| {
        if let Some(console) = &invocation.console {
            console(&format!("hello {}", invocation.trigger));
        }
        Ok(ScriptResult {
            value: br#"{"title":"IP"}"#.to_vec(),
            ..ScriptResult::default()
        })
    });
    let (release, released) = tokio::sync::watch::channel(false);
    let slow: Arc<dyn ScriptProgram> =
        Arc::new(crate::script::testkit::FakeProgram(Arc::new(move |_| {
            let mut released = released.clone();
            Box::pin(async move {
                let _ = released.wait_for(|done| *done).await;
                Ok(ScriptResult::default())
            })
        })));
    let (_server, rig) = scripted(vec![("tool", tool), ("slow", slow)]).await;
    rig.config(config(json!([
        "Tool = type=generic,script-path=tool.js",
        "Slow = type=generic,script-path=slow.js",
        "Ads = type=http-response,pattern=a,script-path=tool.js",
    ])));
    let output = rig.mitm.run_script("Tool").await.unwrap();
    assert_eq!(
        (
            output.logs.as_slice(),
            output.result.as_str(),
            output.error.as_str()
        ),
        (&["hello button".to_string()][..], r#"{"title":"IP"}"#, "")
    );
    assert!(
        matches!(
            rig.mitm.run_script("Ads").await,
            Err(ScriptRunError::NotFound(_))
        ),
        "an http script ran without a request"
    );

    let running = tokio::spawn({
        let mitm_engine = rig.mitm.engine().unwrap();
        async move { mitm_engine.run_script("Slow").await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    let second = rig.mitm.run_script("Slow").await.unwrap();
    assert_eq!(second.error, "the script is still running");
    release.send(true).unwrap();
    assert_eq!(running.await.unwrap().unwrap().error, "");

    rig.config(config(json!([
        "Tool = type=generic,script-path=tool.js",
        r#"Tool = type=cron,cronexp="0 * * * *",script-path=tool.js"#,
    ])));
    assert!(
        matches!(
            rig.mitm.run_script("Tool").await,
            Err(ScriptRunError::Ambiguous(name)) if name == "Tool"
        ),
        "one of two scripts of the same name ran"
    );
}
