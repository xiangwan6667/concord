use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use concord_common::BoxStream;
use concord_common::sync::lock;
use concord_platform::HomeDir;
use concord_tls::TrustStore;

use super::QuickJs;
use crate::script::{
    HeaderList, ScriptDial, ScriptError, ScriptEvent, ScriptInvocation, ScriptRequest,
    ScriptResponse, ScriptResult, ScriptRuntime,
};
use crate::testing::{Reply, start_server};

struct Loopback(Option<SocketAddr>);

#[async_trait]
impl ScriptDial for Loopback {
    #[allow(
        clippy::disallowed_methods,
        reason = "the test dials its own loopback server"
    )]
    async fn dial(&self, _host: &str, _port: u16) -> io::Result<BoxStream> {
        match self.0 {
            Some(addr) => Ok(Box::new(tokio::net::TcpStream::connect(addr).await?)),
            None => Err(io::Error::other("no route")),
        }
    }
}

struct Rig {
    runtime: Arc<QuickJs>,
    _home: tempfile::TempDir,
    dir: std::path::PathBuf,
}

fn rig() -> Rig {
    let home = tempfile::tempdir().unwrap();
    let dir = home.path().to_path_buf();
    let runtime = QuickJs::new(
        Arc::new(HomeDir::new(&dir)),
        Arc::new(arc_swap::ArcSwap::new(TrustStore::new(&[], Vec::new()))),
    );
    Rig {
        runtime,
        _home: home,
        dir,
    }
}

fn headers(pairs: &[(&str, &[&str])]) -> HeaderList {
    pairs
        .iter()
        .map(|(name, values)| {
            (
                name.to_string(),
                values.iter().map(ToString::to_string).collect(),
            )
        })
        .collect()
}

fn request_invocation() -> ScriptInvocation {
    let mut invocation = ScriptInvocation::base(Arc::new(Loopback(None)));
    invocation.name = "test".into();
    invocation.kind = "http-request".into();
    invocation.max_body_size = 1 << 20;
    invocation.request = Some(ScriptRequest {
        id: "id-1".into(),
        url: "https://example.test/a?b=1".into(),
        method: "POST".into(),
        header: headers(&[
            ("Host", &["example.test"]),
            ("User-Agent", &["App/1.0"]),
            ("Cookie", &["a=1"]),
        ]),
        body: Some(br#"{"ad":true}"#.to_vec()),
    });
    invocation
}

fn response_invocation() -> ScriptInvocation {
    let mut invocation = request_invocation();
    invocation.kind = "http-response".into();
    if let Some(request) = invocation.request.as_mut() {
        request.body = None;
    }
    invocation.response = Some(ScriptResponse {
        status: 200,
        header: headers(&[
            ("Content-Type", &["application/json"]),
            (
                "Set-Cookie",
                &["a=1; Path=/", "b=2; Expires=Wed, 21 Oct 2026 07:28:00 GMT"],
            ),
        ]),
        body: Some(br#"{"ad":true,"items":[1,2]}"#.to_vec()),
    });
    invocation
}

async fn run(
    rig: &Rig,
    source: &str,
    invocation: ScriptInvocation,
) -> Result<ScriptResult, ScriptError> {
    let program = rig
        .runtime
        .compile("test.js", source.as_bytes())
        .map_err(|err| ScriptError(err.0))?;
    tokio::time::timeout(Duration::from_secs(10), program.run(invocation))
        .await
        .expect("the script did not finish")
}

#[tokio::test]
async fn a_request_script_rewrites_url_headers_and_body() {
    let rig = rig();
    let result = run(
        &rig,
        r#"
        const body = JSON.parse($request.body);
        body.ad = false;
        $done({url: $request.url + '&c=2', headers: {...$request.headers, 'X-Script': $request.method + ' ' + $request.id}, body: JSON.stringify(body)});
        "#,
        request_invocation(),
    )
    .await
    .unwrap();
    assert_eq!(result.url, "https://example.test/a?b=1&c=2");
    assert_eq!(result.body.as_deref(), Some(&br#"{"ad":false}"#[..]));
    let header = result.header.unwrap();
    assert_eq!(header["X-Script"], ["POST id-1"]);
    assert_eq!(header["User-Agent"], ["App/1.0"]);
    assert!(!result.abort);
}

#[tokio::test]
async fn request_objects_carry_scheme_path_and_case_blind_headers() {
    let rig = rig();
    let result = run(
        &rig,
        r#"
        const ok = $request.scheme === 'https' && $request.path === '/a?b=1'
          && $request.headers['user-agent'] === 'App/1.0' && $request.headers['USER-AGENT'] === 'App/1.0'
          && ('cookie' in $request.headers) && $request.headers.Host === 'example.test';
        delete $request.headers['COOKIE'];
        $done({headers: $request.headers, body: String(ok)});
        "#,
        request_invocation(),
    )
    .await
    .unwrap();
    assert_eq!(result.body.as_deref(), Some(&b"true"[..]));
    assert!(!result.header.unwrap().contains_key("Cookie"));
}

#[tokio::test]
async fn a_response_script_rewrites_status_headers_and_keeps_cookies_apart() {
    let rig = rig();
    let result = run(
        &rig,
        r#"
        const body = JSON.parse($response.body);
        body.items.push(3);
        $done({status: 201, headers: $response.headers, body: JSON.stringify(body)});
        "#,
        response_invocation(),
    )
    .await
    .unwrap();
    assert_eq!(result.status, 201);
    assert_eq!(
        result.body.as_deref(),
        Some(&br#"{"ad":true,"items":[1,2,3]}"#[..])
    );
    assert_eq!(result.header.unwrap()["Set-Cookie"].len(), 2);
}

#[tokio::test]
async fn done_answers_aborts_and_takes_quantumult_shapes() {
    let rig = rig();
    let answered = run(
        &rig,
        "$done({response: {status: 403, headers: {'X-A': '1'}, body: 'denied'}})",
        request_invocation(),
    )
    .await
    .unwrap();
    let response = answered.response.unwrap();
    assert_eq!(
        (response.status, response.body.as_deref()),
        (403, Some(&b"denied"[..]))
    );
    let qx = run(
        &rig,
        "$done({status: 'HTTP/1.1 404 Not Found', body: 'gone'})",
        request_invocation(),
    )
    .await
    .unwrap();
    assert_eq!(qx.response.unwrap().status, 404);
    let aborted = run(&rig, "$done({abort: true})", request_invocation())
        .await
        .unwrap();
    assert!(aborted.abort);
    let bare = run(&rig, "$done({})", request_invocation()).await.unwrap();
    assert!(
        bare.url.is_empty()
            && bare.header.is_none()
            && bare.body.is_none()
            && bare.response.is_none()
    );
    let text = run(&rig, "$done('plain')", request_invocation())
        .await
        .unwrap();
    assert_eq!(text.body.as_deref(), Some(&b"plain"[..]));
    let moved = run(&rig, "$done({path: '/other?x=2'})", request_invocation())
        .await
        .unwrap();
    assert_eq!(moved.url, "https://example.test/other?x=2");
    let first = run(
        &rig,
        "$done({body: 'one'}); $done({body: 'two'})",
        request_invocation(),
    )
    .await
    .unwrap();
    assert_eq!(first.body.as_deref(), Some(&b"one"[..]));
}

#[tokio::test]
async fn binary_mode_hands_bytes_both_ways() {
    let rig = rig();
    let mut invocation = request_invocation();
    invocation.binary_body = true;
    invocation.request.as_mut().unwrap().body = Some(vec![0, 1, 2, 255]);
    let result = run(
        &rig,
        "const view = new Uint8Array($request.body); $done({body: new Uint8Array([view[3], view[0], view.length])})",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(result.body.as_deref(), Some(&[255u8, 0, 4][..]));
}

#[tokio::test]
async fn a_task_returns_its_value_and_logs_to_the_console() {
    let rig = rig();
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let mut invocation = ScriptInvocation::base(Arc::new(Loopback(None)));
    invocation.name = "task".into();
    invocation.kind = "event".into();
    invocation.trigger = "button".into();
    invocation.event = Some(ScriptEvent {
        name: "manually".into(),
    });
    invocation.argument = Some(serde_json::json!({"k": 1}));
    let sink = lines.clone();
    invocation.console = Some(Arc::new(move |line| lock(&sink).push(line.to_string())));
    let result = run(
        &rig,
        "console.log('hi', {a: 1}); $notification.post('t', '', 'b'); $done({event: $event.name, trigger: $trigger, k: $argument.k, env: typeof $environment.system})",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(
        String::from_utf8(result.value).unwrap(),
        r#"{"event":"manually","trigger":"button","k":1,"env":"string"}"#
    );
    assert_eq!(*lock(&lines), ["hi {\"a\":1}", "t\nb"]);
}

#[tokio::test]
async fn timers_and_promises_run_before_done() {
    let rig = rig();
    let result = run(
        &rig,
        r#"
        const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
        (async () => { await wait(20); const cancelled = setTimeout(() => $done('wrong'), 10); clearTimeout(cancelled); await wait(30); $done({ok: 1}); })();
        "#,
        ScriptInvocation::base(Arc::new(Loopback(None))),
    )
    .await
    .unwrap();
    assert_eq!(result.value, br#"{"ok":1}"#);
}

#[tokio::test]
async fn failures_name_what_went_wrong() {
    let rig = rig();
    let cases = [
        ("var x = 1;", "the script ended without calling $done"),
        (
            "new Promise(() => {})",
            "the script ended without calling $done",
        ),
        ("throw new TypeError('boom')", "TypeError: boom"),
        ("undefinedFunction()", "ReferenceError"),
        (
            "setTimeout(() => { throw new Error('late') }, 1)",
            "Error: late",
        ),
        (
            "for (let i = 0; i < 65; i++) setTimeout(() => {}, 1000);",
            "more than 64 timers",
        ),
    ];
    for (source, want) in cases {
        let err = run(&rig, source, request_invocation())
            .await
            .expect_err(source);
        assert!(err.0.contains(want), "{source}: {}", err.0);
    }
    let err = rig.runtime.compile("bad.js", b"function (").err().unwrap();
    assert!(err.0.contains("SyntaxError"), "{err}");
    assert!(
        run(&rig, "throw 1; $done({})", request_invocation())
            .await
            .is_err()
    );
    assert!(
        run(
            &rig,
            "$done({}); throw new Error('after')",
            request_invocation()
        )
        .await
        .is_ok()
    );
}

#[tokio::test]
async fn a_runaway_script_is_stopped_when_its_future_is_dropped() {
    let rig = rig();
    let program = rig.runtime.compile("loop.js", b"while (true) {}").unwrap();
    let outcome = tokio::time::timeout(
        Duration::from_millis(300),
        program.run(request_invocation()),
    )
    .await;
    assert!(outcome.is_err());
    let busy = rig
        .runtime
        .compile(
            "memory.js",
            b"const a = []; while (true) a.push(new Array(100000).fill(1));",
        )
        .unwrap();
    let mut invocation = request_invocation();
    invocation.memory_limit = 32 << 20;
    let err = tokio::time::timeout(Duration::from_secs(20), busy.run(invocation))
        .await
        .unwrap()
        .expect_err("memory");
    assert!(!err.0.is_empty());
}

#[tokio::test]
async fn text_encoding_and_base64_helpers() {
    let rig = rig();
    let result = run(
        &rig,
        r#"
        const bytes = new TextEncoder().encode('héllo \u{1F600}');
        const back = new TextDecoder().decode(bytes);
        const u = new URL('https://a.test:8443/p?x=1&y=2');
        let strict = 'ok';
        try { new TextDecoder('utf-8', {fatal: true}).decode(new Uint8Array([255])); } catch (e) { strict = e.name; }
        $done([btoa('abc'), atob('YWJj'), bytes.length, back, u.searchParams.get('y'), u.port, strict]);
        "#,
        ScriptInvocation::base(Arc::new(Loopback(None))),
    )
    .await
    .unwrap();
    assert_eq!(
        String::from_utf8(result.value).unwrap(),
        r#"["YWJj","abc",11,"héllo 😀","2","8443","TypeError"]"#
    );
}

#[tokio::test]
async fn the_persistent_store_survives_runs() {
    let rig = rig();
    let invocation = || {
        let mut invocation = ScriptInvocation::base(Arc::new(Loopback(None)));
        invocation.name = "stored".into();
        invocation
    };
    run(
        &rig,
        "$persistentStore.write('v1', 'key'); $persistentStore.write('own'); $done()",
        invocation(),
    )
    .await
    .unwrap();
    let result = run(&rig, "$done([$persistentStore.read('key'), $persistentStore.read(), $persistentStore.read('none')])", invocation()).await.unwrap();
    assert_eq!(
        String::from_utf8(result.value).unwrap(),
        r#"["v1","own",null]"#
    );
    rig.runtime.flush();
    let file = rig.dir.join("mitm/store.json");
    assert!(file.exists());
    std::fs::remove_file(&file).unwrap();
    rig.runtime.flush();
    assert!(!file.exists(), "a store with nothing new was saved again");

    let result = run(
        &rig,
        "$persistentStore.write(null, 'key'); $done([$persistentStore.read('key'), $persistentStore.write('x'.repeat(5 << 20), 'big'), $persistentStore.read('big')])",
        invocation(),
    )
    .await
    .unwrap();
    assert_eq!(
        String::from_utf8(result.value).unwrap(),
        r#"[null,false,null]"#
    );
}

#[tokio::test]
async fn http_client_requests_go_through_the_dial() {
    let server = start_server(
        false,
        &[],
        Arc::new(|seen| {
            Reply::ok(&format!(
                "{} {} {}",
                seen.method,
                seen.path,
                String::from_utf8_lossy(&seen.body)
            ))
            .with("X-Seen", "1")
        }),
    )
    .await;
    let rig = rig();
    let mut invocation = ScriptInvocation::base(Arc::new(Loopback(Some(server.addr))));
    invocation.max_body_size = 1 << 20;
    let result = run(
        &rig,
        r#"
        $httpClient.post({url: 'http://remote.test/p?q=1', headers: {'X-Mine': 'yes'}, body: {a: 1}}, (error, response, body) => {
          if (error) return $done({error});
          $httpClient.get({url: 'http://remote.test/b', 'binary-mode': true}, (e2, r2, b2) => {
            $done({status: response.status, body, seen: response.headers['x-seen'], binary: b2 instanceof Uint8Array, length: b2.length});
          });
        });
        "#,
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(
        String::from_utf8(result.value).unwrap(),
        r#"{"status":200,"body":"POST /p?q=1 {\"a\":1}","seen":"1","binary":true,"length":7}"#
    );
    let seen = server.requests();
    assert_eq!(seen[0].headers.get("x-mine").unwrap(), "yes");
    assert_eq!(
        seen[0].headers.get("content-type").unwrap(),
        "application/json"
    );
    assert_eq!(seen[0].host, "remote.test");
}

#[tokio::test]
async fn http_client_errors_reach_the_callback() {
    let rig = rig();
    let result = run(
        &rig,
        "$httpClient.get('http://nowhere.test/', (error) => $done({error: typeof error}))",
        ScriptInvocation::base(Arc::new(Loopback(None))),
    )
    .await
    .unwrap();
    assert_eq!(
        String::from_utf8(result.value).unwrap(),
        r#"{"error":"string"}"#
    );
}

#[tokio::test]
async fn quantumult_scripts_get_task_and_prefs() {
    let server = start_server(false, &[], Arc::new(|_| Reply::ok("qx body"))).await;
    let rig = rig();
    let mut invocation = ScriptInvocation::base(Arc::new(Loopback(Some(server.addr))));
    invocation.max_body_size = 1 << 20;
    let result = run(
        &rig,
        r#"
        $prefs.setValueForKey('v', 'k');
        $task.fetch({url: 'http://remote.test/'}).then((r) => $done({status: r.statusCode, body: r.body, pref: $prefs.valueForKey('k')}));
        "#,
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(
        String::from_utf8(result.value).unwrap(),
        r#"{"status":200,"body":"qx body","pref":"v"}"#
    );
}

#[tokio::test]
async fn ungzip_reads_a_gzip_view() {
    use std::io::Write;
    let rig = rig();
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(b"zipped").unwrap();
    let packed = encoder.finish().unwrap();
    let mut invocation = request_invocation();
    invocation.binary_body = true;
    invocation.request.as_mut().unwrap().body = Some(packed);
    let result = run(
        &rig,
        "const out = $utils.ungzip($request.body); $done({body: new TextDecoder().decode(out)})",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(result.body.as_deref(), Some(&b"zipped"[..]));
}

#[tokio::test]
async fn env_js_finds_surge() {
    let rig = rig();
    let result = run(
        &rig,
        r#"
        function getEnv() {
            if ('undefined' !== typeof Egern) return 'Egern';
            if ('undefined' !== typeof $environment && $environment['surge-version']) return 'Surge';
            if ('undefined' !== typeof module && !!module.exports) return 'Node.js';
            if ('undefined' !== typeof $task) return 'Quantumult X';
            if ('undefined' !== typeof $loon) return 'Loon';
        }
        function time(fmt) {
            const date = new Date(2026, 9, 25, 8, 5, 9);
            const o = {'M+': date.getMonth() + 1, 'd+': date.getDate(), 'H+': date.getHours(), 'm+': date.getMinutes(), 's+': date.getSeconds()};
            if (/(y+)/.test(fmt)) fmt = fmt.replace(RegExp.$1, (date.getFullYear() + '').substr(4 - RegExp.$1.length));
            for (let k in o) if (new RegExp('(' + k + ')').test(fmt)) fmt = fmt.replace(RegExp.$1, RegExp.$1.length == 1 ? o[k] : ('00' + o[k]).substr(('' + o[k]).length));
            return fmt;
        }
        $done({url: 'https://example.test/' + getEnv() + '/' + time('yyyy-MM-dd HH:mm:ss') + '/' + typeof require + typeof process});
        "#,
        request_invocation(),
    )
    .await
    .unwrap();
    assert_eq!(
        result.url,
        "https://example.test/Surge/2026-10-25 08:05:09/undefinedundefined"
    );
}

#[tokio::test]
async fn arguments_keep_their_type() {
    let rig = rig();
    let source = "$done({url: 'https://example.test/' + (typeof $argument === 'object' ? [$argument.region, typeof $argument.level, $argument.on === true, Object.keys($argument).length].join('/') : typeof $argument + (typeof $argument === 'string' ? '/' + $argument : ''))})";
    let cases = [
        (
            Some(serde_json::json!("a=1&b=2")),
            "https://example.test/string/a=1&b=2",
        ),
        (
            Some(serde_json::json!({"region": "CN", "level": 2.0, "on": true})),
            "https://example.test/CN/number/true/3",
        ),
        (None, "https://example.test/undefined"),
    ];
    for (argument, want) in cases {
        let mut invocation = request_invocation();
        invocation.argument = argument;
        assert_eq!(run(&rig, source, invocation).await.unwrap().url, want);
    }
}

#[tokio::test]
async fn one_program_runs_concurrently() {
    let rig = rig();
    let program = rig
        .runtime
        .compile(
            "double.js",
            b"const n = Number($request.id); setTimeout(() => $done({url: 'https://example.test/' + (n * 2)}), 5);",
        )
        .unwrap();
    let runs = (0..16).map(|i| {
        let program = program.clone();
        let id = "1".repeat(i % 3 + 1);
        async move {
            let mut invocation = request_invocation();
            invocation.request.as_mut().unwrap().id.clone_from(&id);
            let result = tokio::time::timeout(Duration::from_secs(5), program.run(invocation))
                .await
                .unwrap()
                .unwrap();
            let doubled = id.parse::<u32>().unwrap() * 2;
            assert_eq!(result.url, format!("https://example.test/{doubled}"));
        }
    });
    futures_util::future::join_all(runs.map(tokio::spawn))
        .await
        .into_iter()
        .for_each(|joined| joined.unwrap());
}

#[tokio::test]
async fn tasks_see_their_trigger_and_cron_scripts_their_expression() {
    let rig = rig();
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let mut invocation = ScriptInvocation::base(Arc::new(Loopback(None)));
    invocation.name = "task".into();
    invocation.kind = "event".into();
    invocation.trigger = "button".into();
    invocation.event = Some(ScriptEvent {
        name: "network-changed".into(),
    });
    let sink = lines.clone();
    invocation.console = Some(Arc::new(move |line| lock(&sink).push(line.to_string())));
    run(
        &rig,
        "console.log(typeof $request, typeof $response, $event.name, $trigger, typeof $cronexp); $done({})",
        invocation,
    )
    .await
    .unwrap();
    assert_eq!(
        *lock(&lines),
        ["undefined undefined network-changed button undefined"]
    );

    let mut cron = ScriptInvocation::base(Arc::new(Loopback(None)));
    cron.name = "cron".into();
    cron.kind = "cron".into();
    cron.cronexp = "0 8 * * *".into();
    let result = run(&rig, "$done($cronexp)", cron).await.unwrap();
    assert_eq!(result.value, br#""0 8 * * *""#);
}

#[tokio::test]
async fn web_globals_follow_the_whatwg_rules() {
    let rig = rig();
    let result = run(
        &rig,
        r#"
        const url = new URL('HTTPS://User:pw@Example.test:443/a/./b/../c?x=1&y=a+b#top');
        const checks = [
            url.href === 'https://User:pw@example.test/a/c?x=1&y=a+b#top',
            url.host === 'example.test' && url.port === '' && url.origin === 'https://example.test',
            url.searchParams.get('y') === 'a b',
            new URL('../d?q', 'https://example.test/a/b/c').href === 'https://example.test/a/d?q',
            new URL('//cdn.test/x', 'https://example.test/').href === 'https://cdn.test/x',
            new URLSearchParams({a: '1', b: 'x y'}).toString() === 'a=1&b=x+y',
            atob(btoa('\u00ff\u0000a')) === '\u00ff\u0000a',
            btoa('hi') === 'aGk=',
        ];
        url.searchParams.set('x', '2');
        url.searchParams.append('z', '&');
        checks.push(url.search === '?x=2&y=a+b&z=%26');
        let threw = false;
        try { new URL('not a url'); } catch (e) { threw = e instanceof TypeError; }
        checks.push(threw);
        $done({url: 'https://example.test/' + checks.map(Number).join('')});
        "#,
        request_invocation(),
    )
    .await
    .unwrap();
    assert_eq!(result.url, "https://example.test/1111111111");
}
