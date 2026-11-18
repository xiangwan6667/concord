use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::io::Read;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use concord_config::mitm::text::canonical_header;
use concord_tls::TrustStore;
use rand::RngCore;
use rquickjs::context::EvalOptions;
use rquickjs::{
    CatchResultExt, CaughtError, Context, Ctx, Exception, Function, Object, Runtime, Value,
};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender, unbounded_channel};
use tokio::task::JoinSet;
use url::Url;

use super::fetch::{Client, Fetch, Fetched};
use super::store::Store;
use crate::script::{
    ConsoleSink, HeaderList, ScriptError, ScriptInvocation, ScriptResponse, ScriptResult,
};

const POLYFILL: &str = include_str!("polyfill.js");
const PRELUDE: &str = include_str!("prelude.js");
const QUANTUMULT: &str = include_str!("quantumult.js");
const DEFAULT_REQUEST_TIMEOUT_MS: f64 = 5000.0;
const NO_DONE: &str = "the script ended without calling $done";
const CANCELLED: &str = "the script was cancelled";

enum Msg {
    Http { id: u32, json: String },
    Stop,
}

struct HttpJob {
    id: u32,
    json: String,
}

struct Cancel {
    flag: Arc<AtomicBool>,
    wake: mpsc::Sender<Msg>,
}

impl Drop for Cancel {
    fn drop(&mut self) {
        self.flag.store(true, Ordering::Relaxed);
        let _ = self.wake.send(Msg::Stop);
    }
}

struct Setup {
    source: String,
    quantumult: bool,
    input: String,
    store: Arc<Store>,
    name: String,
    console: Option<ConsoleSink>,
    memory_limit: u64,
    max_body: i64,
    jobs: UnboundedSender<HttpJob>,
    inbox: mpsc::Receiver<Msg>,
    cancel: Arc<AtomicBool>,
}

fn describe_exception(exception: &Exception<'_>) -> String {
    let message = exception.message().unwrap_or_default();
    let name = exception
        .as_object()
        .get::<_, Option<String>>("name")
        .ok()
        .flatten();
    let text = match name {
        Some(name) if !name.is_empty() => format!("{name}: {message}"),
        _ => message,
    };
    text.lines().next().unwrap_or_default().to_string()
}

pub(super) fn describe(err: &CaughtError<'_>) -> String {
    match err {
        CaughtError::Exception(exception) => describe_exception(exception),
        CaughtError::Value(value) => format!("{value:?}"),
        CaughtError::Error(err) => err.to_string(),
    }
}

fn os_name() -> &'static str {
    match std::env::consts::OS {
        "macos" => "macOS",
        "windows" => "Windows",
        "linux" => "Linux",
        "android" => "Android",
        "ios" => "iOS",
        _ => "",
    }
}

fn body_json(data: &[u8], binary: bool) -> serde_json::Value {
    if binary {
        json!({ "b": STANDARD.encode(data) })
    } else {
        json!({ "s": String::from_utf8_lossy(data) })
    }
}

fn header_json(header: &HeaderList) -> serde_json::Value {
    serde_json::to_value(header).unwrap_or_default()
}

fn build_input(invocation: &ScriptInvocation) -> String {
    let mut session = [0u8; 4];
    rand::rng().fill_bytes(&mut session);
    let started = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |elapsed| elapsed.as_secs_f64());
    let mut input = json!({
        "name": invocation.name,
        "kind": invocation.kind,
        "binary": invocation.binary_body,
        "system": os_name(),
        "started": started,
        "session": hex::encode(session),
        "cronexp": invocation.cronexp,
        "trigger": invocation.trigger,
    });
    if let Some(event) = &invocation.event {
        input["event"] = json!(event.name);
    }
    if let Some(argument) = &invocation.argument {
        input["argument"] = argument.clone();
    }
    if let Some(request) = &invocation.request {
        let mut value = json!({
            "id": request.id,
            "url": request.url,
            "method": request.method,
            "headers": header_json(&request.header),
        });
        if let Ok(target) = Url::parse(&request.url) {
            let mut path = target.path().to_string();
            if let Some(query) = target.query() {
                path.push('?');
                path.push_str(query);
            }
            value["scheme"] = json!(target.scheme());
            value["path"] = json!(path);
        }
        if let Some(body) = &request.body {
            value["body"] = body_json(body, invocation.binary_body);
        }
        input["request"] = value;
    }
    if let Some(response) = &invocation.response {
        let mut value =
            json!({ "status": response.status, "headers": header_json(&response.header) });
        if let Some(body) = &response.body {
            value["body"] = body_json(body, invocation.binary_body);
        }
        input["response"] = value;
    }
    input.to_string()
}

pub(super) async fn execute(
    source: &str,
    quantumult: bool,
    store: Arc<Store>,
    trust: Arc<TrustStore>,
    invocation: ScriptInvocation,
) -> Result<ScriptResult, ScriptError> {
    let (jobs, mut requests): (UnboundedSender<HttpJob>, UnboundedReceiver<HttpJob>) =
        unbounded_channel();
    let (wake, inbox) = mpsc::channel();
    let (finished, mut outcome) = tokio::sync::oneshot::channel();
    let cancel = Arc::new(AtomicBool::new(false));
    let _guard = Cancel {
        flag: cancel.clone(),
        wake: wake.clone(),
    };
    let setup = Setup {
        source: source.to_string(),
        quantumult,
        input: build_input(&invocation),
        store,
        name: invocation.name.clone(),
        console: invocation.console.clone(),
        memory_limit: invocation.memory_limit,
        max_body: invocation.max_body_size,
        jobs,
        inbox,
        cancel,
    };
    std::thread::Builder::new()
        .name("mitm-script".to_string())
        .spawn(move || {
            let _ = finished.send(run_thread(setup));
        })
        .map_err(|err| ScriptError(err.to_string()))?;
    let client = Arc::new(Client {
        dial: invocation.dial.clone(),
        trust,
        max_body: invocation.max_body_size,
    });
    let mut fetches = JoinSet::new();
    loop {
        tokio::select! {
            result = &mut outcome => {
                return result.unwrap_or_else(|_| Err(ScriptError(CANCELLED.to_string())));
            }
            Some(job) = requests.recv() => {
                let (client, wake) = (client.clone(), wake.clone());
                fetches.spawn(async move {
                    let json = answer(&client, &job.json).await;
                    let _ = wake.send(Msg::Http { id: job.id, json });
                });
            }
        }
    }
}

#[derive(Deserialize)]
struct RequestJson {
    method: String,
    url: String,
    headers: Vec<(String, Vec<String>)>,
    body: Option<BodyJson>,
    timeout: f64,
    redirect: bool,
    insecure: bool,
}

#[derive(Deserialize, Default)]
struct BodyJson {
    s: Option<String>,
    b: Option<String>,
}

impl BodyJson {
    fn bytes(&self) -> Option<Vec<u8>> {
        match (&self.b, &self.s) {
            (Some(encoded), _) => STANDARD.decode(encoded).ok(),
            (None, Some(text)) => Some(text.clone().into_bytes()),
            (None, None) => None,
        }
    }
}

async fn answer(client: &Client, json: &str) -> String {
    let failed = |message: String| json!({ "error": message }).to_string();
    let request: RequestJson = match serde_json::from_str(json) {
        Ok(request) => request,
        Err(err) => return failed(err.to_string()),
    };
    let timeout = if request.timeout > 0.0 {
        request.timeout
    } else {
        DEFAULT_REQUEST_TIMEOUT_MS
    };
    let fetch = Fetch {
        method: request.method,
        url: request.url,
        headers: request.headers,
        body: request.body.as_ref().and_then(BodyJson::bytes),
        timeout: Duration::from_secs_f64(timeout / 1000.0),
        redirect: request.redirect,
        insecure: request.insecure,
    };
    match client.fetch(fetch).await {
        Ok(Fetched {
            status,
            headers,
            body,
        }) => json!({
            "status": status,
            "headers": headers,
            "body": { "b": STANDARD.encode(&body), "s": String::from_utf8_lossy(&body) },
        })
        .to_string(),
        Err(message) => failed(message),
    }
}

struct State {
    timers: RefCell<HashMap<u32, Instant>>,
    http: Cell<usize>,
    done: RefCell<Option<String>>,
}

fn install(ctx: &Ctx<'_>, state: &Rc<State>, setup: &Rc<Setup>) -> rquickjs::Result<()> {
    let native = Object::new(ctx.clone())?;
    let input = setup.input.clone();
    native.set("input", Function::new(ctx.clone(), move || input.clone())?)?;
    let done = state.clone();
    native.set(
        "done",
        Function::new(ctx.clone(), move |json: String| {
            done.done.borrow_mut().get_or_insert(json);
        })?,
    )?;
    let timers = state.clone();
    native.set(
        "timer",
        Function::new(ctx.clone(), move |id: u32, ms: f64| {
            let delay = Duration::from_secs_f64(ms.max(0.0) / 1000.0);
            timers
                .timers
                .borrow_mut()
                .insert(id, Instant::now() + delay);
        })?,
    )?;
    let timers = state.clone();
    native.set(
        "cancel",
        Function::new(ctx.clone(), move |id: u32| {
            timers.timers.borrow_mut().remove(&id);
        })?,
    )?;
    let log = setup.clone();
    native.set(
        "log",
        Function::new(ctx.clone(), move |level: String, line: String| {
            match level.as_str() {
                "debug" => tracing::debug!("[MITM] {}: {line}", log.name),
                "warn" => tracing::warn!("[MITM] {}: {line}", log.name),
                "error" => tracing::error!("[MITM] {}: {line}", log.name),
                _ => tracing::info!("[MITM] {}: {line}", log.name),
            }
            if let Some(console) = &log.console {
                console(&line);
            }
        })?,
    )?;
    let notify = setup.clone();
    native.set(
        "notify",
        Function::new(
            ctx.clone(),
            move |title: String, subtitle: String, body: String| {
                tracing::info!(
                    "[MITM] {} notifies {title:?} {subtitle:?} {body:?}",
                    notify.name
                );
                if let Some(console) = &notify.console {
                    let parts: Vec<&str> = [title.as_str(), subtitle.as_str(), body.as_str()]
                        .into_iter()
                        .filter(|part| !part.is_empty())
                        .collect();
                    console(&parts.join("\n"));
                }
            },
        )?,
    )?;
    let store = setup.store.clone();
    native.set(
        "read",
        Function::new(ctx.clone(), move |key: String| store.read(&key))?,
    )?;
    let store = setup.store.clone();
    native.set(
        "write",
        Function::new(ctx.clone(), move |key: String, value: String| {
            store.write(&key, &value)
        })?,
    )?;
    let store = setup.store.clone();
    native.set(
        "remove",
        Function::new(ctx.clone(), move |key: String| store.remove(&key))?,
    )?;
    let limit = setup.max_body;
    native.set(
        "ungzip",
        Function::new(ctx.clone(), move |encoded: String| ungzip(&encoded, limit))?,
    )?;
    let http = state.clone();
    let jobs = setup.jobs.clone();
    native.set(
        "http",
        Function::new(ctx.clone(), move |id: u32, json: String| {
            http.http.set(http.http.get() + 1);
            let _ = jobs.send(HttpJob { id, json });
        })?,
    )?;
    ctx.globals().set("__native", native)
}

fn ungzip(encoded: &str, limit: i64) -> Option<String> {
    let data = STANDARD.decode(encoded).ok()?;
    let cap = u64::try_from(limit).ok()?;
    let mut out = Vec::new();
    flate2::read::MultiGzDecoder::new(data.as_slice())
        .take(cap + 1)
        .read_to_end(&mut out)
        .ok()?;
    (out.len() as u64 <= cap).then(|| STANDARD.encode(out))
}

fn eval(ctx: &Ctx<'_>, source: &str) -> Result<(), String> {
    let mut options = EvalOptions::default();
    options.strict = false;
    ctx.eval_with_options::<Value<'_>, _>(source, options)
        .catch(ctx)
        .map(|_| ())
        .map_err(|err| describe(&err))
}

fn call(ctx: &Ctx<'_>, name: &str, id: u32, json: Option<&str>) -> Result<(), String> {
    let function: Function<'_> = ctx.globals().get(name).map_err(|err| err.to_string())?;
    let result = match json {
        Some(json) => function.call::<_, Value<'_>>((id, json)),
        None => function.call::<_, Value<'_>>((id,)),
    };
    result.catch(ctx).map(|_| ()).map_err(|err| describe(&err))
}

fn run_thread(setup: Setup) -> Result<ScriptResult, ScriptError> {
    let fail = |message: String| ScriptError(message);
    let runtime = Runtime::new().map_err(|err| fail(err.to_string()))?;
    if let Ok(limit) = usize::try_from(setup.memory_limit)
        && limit > 0
    {
        runtime.set_memory_limit(limit);
    }
    let flag = setup.cancel.clone();
    runtime.set_interrupt_handler(Some(Box::new(move || flag.load(Ordering::Relaxed))));
    let context = Context::full(&runtime).map_err(|err| fail(err.to_string()))?;
    let state = Rc::new(State {
        timers: RefCell::default(),
        http: Cell::new(0),
        done: RefCell::new(None),
    });
    let setup = Rc::new(setup);

    let started = context.with(|ctx| -> Result<(), String> {
        install(&ctx, &state, &setup).map_err(|err| err.to_string())?;
        eval(&ctx, POLYFILL)?;
        eval(&ctx, PRELUDE)?;
        if setup.quantumult {
            eval(&ctx, QUANTUMULT)?;
        }
        match eval(&ctx, &setup.source) {
            Err(message) if state.done.borrow().is_none() => Err(message),
            _ => Ok(()),
        }
    });
    started.map_err(fail)?;

    loop {
        loop {
            match runtime.execute_pending_job() {
                Ok(true) => {}
                Ok(false) => break,
                Err(_) if state.done.borrow().is_some() => break,
                Err(job) => {
                    let message = job.0.with(|ctx| {
                        let value = ctx.catch();
                        value
                            .as_exception()
                            .map_or_else(|| "a job failed".to_string(), describe_exception)
                    });
                    return Err(fail(message));
                }
            }
        }
        if setup.cancel.load(Ordering::Relaxed) {
            return Err(fail(CANCELLED.to_string()));
        }
        if let Some(json) = state.done.borrow_mut().take() {
            return parse_result(&json).map_err(fail);
        }
        let next = state.timers.borrow().values().min().copied();
        if next.is_none() && state.http.get() == 0 {
            return Err(fail(NO_DONE.to_string()));
        }
        let message = match next {
            Some(at) => setup
                .inbox
                .recv_timeout(at.saturating_duration_since(Instant::now())),
            None => setup
                .inbox
                .recv()
                .map_err(|_| RecvTimeoutError::Disconnected),
        };
        let step = match message {
            Ok(Msg::Stop) | Err(RecvTimeoutError::Disconnected) => {
                return Err(fail(CANCELLED.to_string()));
            }
            Ok(Msg::Http { id, json }) => {
                state.http.set(state.http.get().saturating_sub(1));
                context.with(|ctx| call(&ctx, "__httpDone", id, Some(&json)))
            }
            Err(RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                let due = state
                    .timers
                    .borrow()
                    .iter()
                    .filter(|(_, at)| **at <= now)
                    .min_by_key(|(id, at)| (**at, **id))
                    .map(|(id, _)| *id);
                match due {
                    Some(id) => {
                        state.timers.borrow_mut().remove(&id);
                        context.with(|ctx| call(&ctx, "__fire", id, None))
                    }
                    None => Ok(()),
                }
            }
        };
        if let Err(message) = step
            && state.done.borrow().is_none()
        {
            return Err(fail(message));
        }
    }
}

#[derive(Deserialize, Default)]
struct DoneJson {
    url: Option<String>,
    status: Option<i64>,
    header: Option<Vec<(String, Vec<String>)>>,
    body: Option<BodyJson>,
    response: Option<ResponseJson>,
    abort: Option<bool>,
    value: Option<String>,
}

#[derive(Deserialize)]
struct ResponseJson {
    status: Option<i64>,
    header: Option<Vec<(String, Vec<String>)>>,
    body: Option<BodyJson>,
}

fn to_list(header: Vec<(String, Vec<String>)>) -> HeaderList {
    let mut list = HeaderList::new();
    for (name, values) in header {
        list.entry(canonical_header(&name))
            .or_default()
            .extend(values);
    }
    list
}

fn parse_result(json: &str) -> Result<ScriptResult, String> {
    let done: DoneJson = serde_json::from_str(json)
        .map_err(|err| format!("the script's result is unreadable: {err}"))?;
    let status = |value: Option<i64>| value.and_then(|n| u16::try_from(n).ok()).unwrap_or(0);
    Ok(ScriptResult {
        url: done.url.unwrap_or_default(),
        status: status(done.status),
        header: done.header.map(to_list),
        body: done.body.as_ref().and_then(BodyJson::bytes),
        response: done.response.map(|answer| ScriptResponse {
            status: status(answer.status),
            header: answer.header.map(to_list).unwrap_or_default(),
            body: answer.body.as_ref().and_then(BodyJson::bytes),
        }),
        abort: done.abort.unwrap_or(false),
        value: done.value.unwrap_or_default().into_bytes(),
    })
}
