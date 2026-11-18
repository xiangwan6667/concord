use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use concord_api::{Control, ControlService, Delivery, Origin, Reload, valid_status_ranges};
use concord_proto::types::{
    ConfigPatchParams, ConnectionCloseParams, CoreEvent, DelayRunEvent, DelayRunParams,
    DelayTestParams, DnsQueryParams, Empty, EventsWatchParams, GeoUpdateParams, ProviderKind,
    ProviderNameParams, ProxySelectParams, ProxyStatesParams, ResourceKind, ResourcePhase,
    TunPatch,
};
use concord_proto::{ApiError, ErrorData, MAX_MESSAGE};
use futures_util::StreamExt;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Limited};
use hyper::body::{Body as _, Incoming};
use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;

use crate::http::{
    Body, bad_request, empty, error, json, not_found, parse_body, query, segments, unsupported,
};
use crate::shapes::{self, Catalog};
use crate::stream;

pub struct Routes {
    pub control: Arc<Control>,
    pub stop: CancellationToken,
}

impl Routes {
    pub async fn handle(&self, request: Request<Incoming>) -> Response<Body> {
        let method = request.method().clone();
        let path = segments(request.uri().path());
        let path: Vec<&str> = path.iter().map(String::as_str).collect();
        match (&method, path.as_slice()) {
            (&Method::GET, []) => {
                json(&json!({ "hello": self.control.info().server.implementation }))
            }
            (&Method::GET, ["version"]) => json(&json!({
                "meta": true,
                "version": format!("v{}", self.control.info().server.version),
            })),
            (&Method::GET, ["traffic"]) => {
                let values = stream::traffic(&self.control).await;
                stream::respond(request, values, self.stop.clone())
            }
            (&Method::GET, ["memory"]) => {
                let values = stream::memory(self.control.clone());
                stream::respond(request, values, self.stop.clone())
            }
            (&Method::GET, ["logs"]) => self.logs(request).await,
            (_, ["configs", ..]) => self.configs(request, &method, &path[1..]).await,
            (_, ["proxies", rest @ ..]) => self.proxies(request, &method, rest).await,
            (&Method::GET, ["group", rest @ ..]) => self.groups(request, rest).await,
            (&Method::GET, ["rules"]) => self.rules().await,
            (_, ["connections", rest @ ..]) => self.connections(request, &method, rest).await,
            (_, ["providers", "proxies", rest @ ..]) => {
                self.proxy_providers(request, &method, rest).await
            }
            (_, ["providers", "rules", rest @ ..]) => self.rule_providers(&method, rest).await,
            (&Method::POST, ["cache", "fakeip", "flush"]) => {
                match self.control.dns_flush_fake_ip(Empty {}).await {
                    Ok(_) => empty(StatusCode::NO_CONTENT),
                    Err(err) => error(StatusCode::BAD_REQUEST, &err.message),
                }
            }
            (&Method::POST, ["cache", "dns", "flush"]) => {
                let _ = self.control.dns_clear_cache(Empty {}).await;
                empty(StatusCode::NO_CONTENT)
            }
            (&Method::GET, ["dns", "query"]) => self.dns_query(&request).await,
            (_, ["restart" | "upgrade" | "debug" | "storage" | "ui", ..])
            | (&Method::PATCH, ["rules", "disable"]) => unsupported(),
            (
                _,
                []
                | ["version" | "traffic" | "memory" | "logs" | "rules" | "group"]
                | ["group", _]
                | ["group", _, "delay"]
                | ["rules", "disable"]
                | ["cache", "fakeip" | "dns", "flush"]
                | ["dns", "query"],
            ) => method_not_allowed(),
            _ => not_found_text(),
        }
    }

    async fn logs(&self, request: Request<Incoming>) -> Response<Body> {
        let level = query(request.uri(), "level").unwrap_or_else(|| "info".to_string());
        let Some(level) = shapes::parse_level(&level) else {
            return bad_request();
        };
        let structured = query(request.uri(), "format").as_deref() == Some("structured");
        let values = stream::logs(&self.control, level, structured).await;
        stream::respond(request, values, self.stop.clone())
    }

    async fn catalog(&self) -> Option<Catalog> {
        let groups = self.control.proxy_groups(Empty {}).await.ok()?;
        let states = self
            .control
            .proxy_states(ProxyStatesParams::default())
            .await
            .map(|states| states.proxies)
            .unwrap_or_default();
        Some(Catalog::new(groups, states))
    }

    async fn proxies(
        &self,
        request: Request<Incoming>,
        method: &Method,
        rest: &[&str],
    ) -> Response<Body> {
        let Some(catalog) = self.catalog().await else {
            return not_found();
        };
        match (method, rest) {
            (&Method::GET, []) => json(&catalog.all()),
            (_, [name, tail @ ..]) => {
                let Some(proxy) = catalog.get(name) else {
                    return not_found();
                };
                match (method, tail) {
                    (&Method::GET, []) => json(&proxy),
                    (&Method::PUT, []) => self.select(request, &catalog, name).await,
                    (&Method::DELETE, []) => self.unfix(&catalog, name).await,
                    (&Method::GET, ["delay"]) => self.delay(&request, name).await,
                    _ => method_not_allowed(),
                }
            }
            _ => method_not_allowed(),
        }
    }

    async fn select(
        &self,
        request: Request<Incoming>,
        catalog: &Catalog,
        group: &str,
    ) -> Response<Body> {
        let Some(body) = read_json(request).await else {
            return bad_request();
        };
        let Some(name) = body.get("name").and_then(Value::as_str) else {
            return bad_request();
        };
        let selectable = catalog
            .group(group)
            .is_some_and(|info| info.kind == "Selector" || info.fixed.is_some());
        if !selectable {
            return error(StatusCode::BAD_REQUEST, "Must be a Selector");
        }
        let params = ProxySelectParams {
            group: group.to_string(),
            proxy: name.to_string(),
        };
        match self
            .control
            .proxy_select_as(Origin::Controller, params)
            .await
        {
            Ok(_) => empty(StatusCode::NO_CONTENT),
            Err(err) if matches!(err.data, ErrorData::NotFound { .. }) => error(
                StatusCode::BAD_REQUEST,
                "Selector update error: proxy not exist",
            ),
            Err(err) => error(
                StatusCode::BAD_REQUEST,
                &format!("Selector update error: {}", err.message),
            ),
        }
    }

    /// `proxies.go:150-160`: only a group that can be fixed, not a selector.
    async fn unfix(&self, catalog: &Catalog, group: &str) -> Response<Body> {
        if !catalog
            .group(group)
            .is_some_and(|info| info.fixed.is_some())
        {
            return bad_request();
        }
        match self.clear_fixed(group).await {
            Ok(()) => empty(StatusCode::NO_CONTENT),
            Err(_) => bad_request(),
        }
    }

    async fn clear_fixed(&self, group: &str) -> Result<(), ApiError> {
        let params = ProxySelectParams {
            group: group.to_string(),
            proxy: String::new(),
        };
        self.control
            .proxy_select_as(Origin::Controller, params)
            .await
            .map(|_| ())
    }

    /// `proxies.go:106-148`: a bad `timeout` or `expected` is 400, a deadline
    /// already past is 504, any other failure 503.
    async fn delay(&self, request: &Request<Incoming>, name: &str) -> Response<Body> {
        let Some(timeout) = query(request.uri(), "timeout").and_then(|t| t.parse::<i16>().ok())
        else {
            return bad_request();
        };
        let expected = query(request.uri(), "expected");
        if !valid_status_ranges(expected.as_deref().unwrap_or_default()) {
            return bad_request();
        }
        let Ok(timeout) = u64::try_from(timeout) else {
            return error(StatusCode::GATEWAY_TIMEOUT, "Timeout");
        };
        if timeout == 0 {
            return error(StatusCode::GATEWAY_TIMEOUT, "Timeout");
        }
        let params = DelayTestParams {
            proxy: name.to_string(),
            url: query(request.uri(), "url"),
            timeout: Some(timeout),
            expected,
        };
        match self.control.delay_test(params).await {
            Ok(result) if result.value > 0 => json(&json!({ "delay": result.value })),
            Ok(result) if result.value == -1 => error(StatusCode::GATEWAY_TIMEOUT, "Timeout"),
            Ok(_) | Err(_) => error(
                StatusCode::SERVICE_UNAVAILABLE,
                "An error occurred in the delay test",
            ),
        }
    }

    async fn groups(&self, request: Request<Incoming>, rest: &[&str]) -> Response<Body> {
        let Some(catalog) = self.catalog().await else {
            return not_found();
        };
        let [name, tail @ ..] = rest else {
            return json(&catalog.groups_only());
        };
        let Some(info) = catalog.group(name) else {
            return not_found();
        };
        match tail {
            [] => json(&shapes::group(info, catalog.states.get(*name))),
            ["delay"] => {
                if info.fixed.is_some() {
                    let _ = self.clear_fixed(name).await;
                }
                let members = info.all.clone().unwrap_or_default();
                self.group_delay(&request, members).await
            }
            _ => not_found_text(),
        }
    }

    /// `groupbase.go:237-263`: the members that answered, or 504 when none did.
    async fn group_delay(
        &self,
        request: &Request<Incoming>,
        members: Vec<String>,
    ) -> Response<Body> {
        let Some(timeout) = query(request.uri(), "timeout").and_then(|t| t.parse::<i32>().ok())
        else {
            return bad_request();
        };
        let expected = query(request.uri(), "expected");
        if !valid_status_ranges(expected.as_deref().unwrap_or_default()) {
            return bad_request();
        }
        let timeout = match u64::try_from(timeout) {
            Ok(timeout) if timeout > 0 => timeout,
            _ => return error(StatusCode::GATEWAY_TIMEOUT, ALL_TIMED_OUT),
        };
        let params = DelayRunParams {
            proxies: members,
            url: query(request.uri(), "url"),
            timeout: Some(timeout),
            concurrency: None,
            expected,
            watch: Default::default(),
        };
        let Ok(run) = self.control.delay_run(params).await else {
            return bad_request();
        };
        let mut delays: HashMap<String, i32> = HashMap::new();
        let mut events = run.events;
        while let Some(Delivery::Event { data, .. }) = events.next().await {
            match data {
                DelayRunEvent::Result { name, value, .. } if value > 0 => {
                    delays.insert(name, value);
                }
                DelayRunEvent::Result { .. } => {}
                DelayRunEvent::Done => break,
            }
        }
        if delays.is_empty() {
            return error(StatusCode::GATEWAY_TIMEOUT, ALL_TIMED_OUT);
        }
        json(&delays)
    }

    async fn rules(&self) -> Response<Body> {
        match self.control.rule_list(Empty {}).await {
            Ok(list) => json(&shapes::rules(&list.rules)),
            Err(_) => json(&json!({ "rules": [] })),
        }
    }

    async fn connections(
        &self,
        request: Request<Incoming>,
        method: &Method,
        rest: &[&str],
    ) -> Response<Body> {
        match (method, rest) {
            (&Method::GET, []) if crate::http::is_websocket(request.headers()) => {
                let period = match query(request.uri(), "interval") {
                    None => 1000,
                    Some(text) => match text.parse::<u64>() {
                        Ok(millis) if millis > 0 => millis,
                        _ => return bad_request(),
                    },
                };
                let values =
                    stream::connections(self.control.clone(), Duration::from_millis(period));
                stream::respond(request, values, self.stop.clone())
            }
            (&Method::GET, []) => {
                let mut table = stream::Table::new(self.control.clone());
                json(&table.snapshot().await)
            }
            (&Method::DELETE, []) => {
                let params = ConnectionCloseParams {
                    ids: None,
                    all: true,
                };
                let _ = self.control.connection_close(params).await;
                empty(StatusCode::NO_CONTENT)
            }
            (&Method::DELETE, [id]) => {
                if let Ok(id) = id.parse::<u64>() {
                    let params = ConnectionCloseParams {
                        ids: Some(vec![id]),
                        all: false,
                    };
                    let _ = self.control.connection_close(params).await;
                }
                empty(StatusCode::NO_CONTENT)
            }
            _ => method_not_allowed(),
        }
    }

    async fn proxy_providers(
        &self,
        request: Request<Incoming>,
        method: &Method,
        rest: &[&str],
    ) -> Response<Body> {
        let Some(catalog) = self.catalog().await else {
            return not_found();
        };
        let providers: Vec<_> = self
            .control
            .provider_list(Empty {})
            .await
            .map(|list| list.providers)
            .unwrap_or_default()
            .into_iter()
            .filter(|info| info.kind == ProviderKind::Proxy)
            .collect();
        let [name, tail @ ..] = rest else {
            if method != Method::GET {
                return method_not_allowed();
            }
            let mut map = Map::new();
            for info in &providers {
                map.insert(info.name.clone(), catalog.provider(info));
            }
            map.insert("default".to_string(), catalog.default_provider());
            return json(&json!({ "providers": map }));
        };
        if *name == "default" {
            return match (method, tail) {
                (&Method::GET, []) => json(&catalog.default_provider()),
                (&Method::PUT, []) | (&Method::GET, ["healthcheck"]) => {
                    empty(StatusCode::NO_CONTENT)
                }
                (&Method::GET, [proxy, rest @ ..]) => {
                    let Some(member) = catalog.default_member(proxy) else {
                        return not_found();
                    };
                    match rest {
                        [] => json(&member),
                        ["healthcheck"] => self.delay(&request, proxy).await,
                        _ => not_found_text(),
                    }
                }
                _ => method_not_allowed(),
            };
        }
        let Some(info) = providers.iter().find(|info| info.name == *name) else {
            return not_found();
        };
        let params = || ProviderNameParams {
            name: name.to_string(),
        };
        match (method, tail) {
            (&Method::GET, []) => json(&catalog.provider(info)),
            (&Method::PUT, []) => match self.control.provider_update(params()).await {
                Ok(_) => empty(StatusCode::NO_CONTENT),
                Err(err) => error(StatusCode::SERVICE_UNAVAILABLE, &err.message),
            },
            (&Method::GET, ["healthcheck"]) => {
                let _ = self.control.provider_health_check(params()).await;
                empty(StatusCode::NO_CONTENT)
            }
            (&Method::GET, [proxy, rest @ ..]) => {
                let member = catalog
                    .groups
                    .nodes
                    .iter()
                    .find(|node| node.name == *proxy && node.provider.as_deref() == Some(name));
                let Some(member) = member else {
                    return not_found();
                };
                match rest {
                    [] => json(&shapes::node(member, catalog.states.get(*proxy))),
                    ["healthcheck"] => self.delay(&request, proxy).await,
                    _ => not_found_text(),
                }
            }
            _ => method_not_allowed(),
        }
    }

    async fn rule_providers(&self, method: &Method, rest: &[&str]) -> Response<Body> {
        let providers: Vec<_> = self
            .control
            .provider_list(Empty {})
            .await
            .map(|list| list.providers)
            .unwrap_or_default()
            .into_iter()
            .filter(|info| info.kind == ProviderKind::Rule)
            .collect();
        match (method, rest) {
            (&Method::GET, []) => {
                let map: Map<String, Value> = providers
                    .iter()
                    .map(|info| (info.name.clone(), shapes::rule_provider(info)))
                    .collect();
                json(&json!({ "providers": map }))
            }
            (&Method::PUT, [name]) => {
                if !providers.iter().any(|info| info.name == *name) {
                    return not_found();
                }
                let params = ProviderNameParams {
                    name: name.to_string(),
                };
                match self.control.provider_update(params).await {
                    Ok(_) => empty(StatusCode::NO_CONTENT),
                    Err(err) => error(StatusCode::SERVICE_UNAVAILABLE, &err.message),
                }
            }
            _ => method_not_allowed(),
        }
    }

    async fn dns_query(&self, request: &Request<Incoming>) -> Response<Body> {
        let params = DnsQueryParams {
            name: query(request.uri(), "name").unwrap_or_default(),
            qtype: Some(query(request.uri(), "type").unwrap_or_else(|| "A".to_string())),
        };
        match self.control.dns_query(params).await {
            Ok(result) => json(&shapes::dns(&result)),
            Err(err) if matches!(err.data, ErrorData::InvalidParams { .. }) => {
                error(StatusCode::BAD_REQUEST, "invalid query type")
            }
            Err(err) => error(StatusCode::INTERNAL_SERVER_ERROR, &err.message),
        }
    }

    async fn configs(
        &self,
        request: Request<Incoming>,
        method: &Method,
        rest: &[&str],
    ) -> Response<Body> {
        match (method, rest) {
            (&Method::GET, []) => match self.control.config_general(Empty {}).await {
                Ok(state) => json(&shapes::configs(&state)),
                Err(err) => error(StatusCode::SERVICE_UNAVAILABLE, &err.message),
            },
            (&Method::PATCH, []) => self.patch(request).await,
            (&Method::PUT, []) => self.reload(request).await,
            (&Method::POST, ["geo"]) => self.update_geo().await,
            _ => method_not_allowed(),
        }
    }

    async fn patch(&self, request: Request<Incoming>) -> Response<Body> {
        let Some(Value::Object(body)) = read_json(request).await else {
            return bad_request();
        };
        let params = match patch_params(&body, self.control.host_owned()) {
            Ok(params) => params,
            Err(Refusal::Invalid) => return bad_request(),
            Err(Refusal::Unsupported(keys)) => {
                return error(
                    StatusCode::BAD_REQUEST,
                    &format!("cannot be changed by Concord: {}", keys.join(", ")),
                );
            }
        };
        match self
            .control
            .config_patch_as(Origin::Controller, params)
            .await
        {
            Ok(_) => empty(StatusCode::NO_CONTENT),
            Err(err) => error(StatusCode::BAD_REQUEST, &err.message),
        }
    }

    /// `configs.go:405-454`. A host owns the profile, so only a core running on
    /// its own reloads one; mihomo's embedded builds refuse this the same way.
    async fn reload(&self, request: Request<Incoming>) -> Response<Body> {
        if self.control.host_owned() {
            return error(
                StatusCode::METHOD_NOT_ALLOWED,
                "the host owns the profile; reload it there",
            );
        }
        let Some(body) = read_json(request).await else {
            return bad_request();
        };
        let text = |key: &str| {
            body.get(key)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        };
        let reload = match (text("payload"), text("path")) {
            (Some(payload), _) => Reload::Text(payload),
            (None, Some(path)) => Reload::Path(path),
            (None, None) => Reload::Started,
        };
        match self
            .control
            .reload_profile_as(Origin::Controller, reload)
            .await
        {
            Ok(_) => empty(StatusCode::NO_CONTENT),
            Err(err) => error(StatusCode::BAD_REQUEST, &err.message),
        }
    }

    /// mihomo updates every database before it answers; `geo.update` starts one
    /// kind at a time and reports each on `events.watch`. A kind already
    /// updating is waited for, not refused.
    async fn update_geo(&self) -> Response<Body> {
        let watch = EventsWatchParams::default();
        let Ok(subscription) = self.control.events_watch(watch).await else {
            return error(StatusCode::INTERNAL_SERVER_ERROR, "events unavailable");
        };
        let mut events = subscription.events;
        let mut pending = Vec::new();
        for (index, kind) in GEO_KINDS.into_iter().enumerate() {
            let params = GeoUpdateParams {
                kind: kind.to_string(),
            };
            match self.control.geo_update(params).await {
                Ok(_) => pending.push(kind),
                Err(err) if matches!(err.data, ErrorData::Conflict { .. }) => pending.push(kind),
                Err(err) => {
                    let mut message = format!("{kind}: {}", err.message);
                    if !pending.is_empty() {
                        message.push_str(&format!("; {} still updating", pending.join(", ")));
                    }
                    let skipped = &GEO_KINDS[index + 1..];
                    if !skipped.is_empty() {
                        message.push_str(&format!("; {} not started", skipped.join(", ")));
                    }
                    return error(StatusCode::INTERNAL_SERVER_ERROR, &message);
                }
            }
        }
        let mut failure = None;
        while !pending.is_empty() {
            let Some(delivery) = events.next().await else {
                let message = format!("no outcome for {}: events ended", pending.join(", "));
                return error(StatusCode::INTERNAL_SERVER_ERROR, &message);
            };
            let Delivery::Event {
                data:
                    CoreEvent::ResourceUpdate {
                        kind: ResourceKind::Geo,
                        name,
                        phase,
                        error,
                    },
                ..
            } = delivery
            else {
                continue;
            };
            if phase == ResourcePhase::Updating {
                continue;
            }
            pending.retain(|kind| *kind != name);
            if phase == ResourcePhase::Failed {
                failure = Some(error);
            }
        }
        match failure {
            Some(message) => error(StatusCode::INTERNAL_SERVER_ERROR, &message),
            None => empty(StatusCode::NO_CONTENT),
        }
    }
}

const GEO_KINDS: [&str; 3] = ["MMDB", "ASN", "GEOSITE"];
/// `groupbase.go:259`.
const ALL_TIMED_OUT: &str = "get delay: all proxies timeout";

fn method_not_allowed() -> Response<Body> {
    empty(StatusCode::METHOD_NOT_ALLOWED)
}

/// chi's plain answer for a path it has no route for.
fn not_found_text() -> Response<Body> {
    let mut response = Response::new(crate::http::full("404 page not found\n"));
    *response.status_mut() = StatusCode::NOT_FOUND;
    response.headers_mut().insert(
        http::header::CONTENT_TYPE,
        http::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

async fn read_json(request: Request<Incoming>) -> Option<Value> {
    let body = request.into_body();
    if body.size_hint().lower() > MAX_MESSAGE {
        return None;
    }
    let limit = usize::try_from(MAX_MESSAGE).unwrap_or(usize::MAX);
    let bytes = Limited::new(body, limit).collect().await.ok()?.to_bytes();
    parse_body(&bytes)
}

enum Refusal {
    Invalid,
    Unsupported(Vec<String>),
}

/// Keys of mihomo's `configSchema` that Concord does not change live.
const FIXED_KEYS: [&str; 11] = [
    "port",
    "socks-port",
    "redir-port",
    "tproxy-port",
    "tuic-server",
    "ss-config",
    "vmess-config",
    "tcptun-config",
    "udptun-config",
    "skip-auth-prefixes",
    "interface-name",
];

const TUN_KEYS: [&str; 4] = ["enable", "device", "stack", "auto-route"];

/// mihomo's `PATCH /configs` over the fields Concord can change. Nothing is
/// applied when a field is out of reach, so a dashboard never sees a change
/// reported that did not happen.
fn patch_params(body: &Map<String, Value>, host_owned: bool) -> Result<ConfigPatchParams, Refusal> {
    let present = |key: &str| body.get(key).is_some_and(|value| !value.is_null());
    let mut refused: Vec<String> = FIXED_KEYS
        .iter()
        .filter(|key| present(key))
        .map(|key| (*key).to_string())
        .collect();
    if present("sniffing") {
        refused.push("sniffing".to_string());
    }
    let mut params = ConfigPatchParams::default();
    if let Some(tun) = body.get("tun").filter(|tun| !tun.is_null()) {
        let Value::Object(tun) = tun else {
            return Err(Refusal::Invalid);
        };
        if host_owned {
            refused.push("tun".to_string());
        } else {
            refused.extend(
                tun.iter()
                    .filter(|(key, value)| !value.is_null() && !TUN_KEYS.contains(&key.as_str()))
                    .map(|(key, _)| format!("tun.{key}")),
            );
            params.tun = Some(TunPatch {
                enable: tun.get("enable").and_then(Value::as_bool).unwrap_or(false),
                device: tun
                    .get("device")
                    .and_then(Value::as_str)
                    .map(str::to_string),
                stack: tun.get("stack").and_then(Value::as_str).map(str::to_string),
                auto_route: tun.get("auto-route").and_then(Value::as_bool),
            });
        }
    }
    if !refused.is_empty() {
        return Err(Refusal::Unsupported(refused));
    }
    let flag = |key: &str| -> Result<Option<bool>, Refusal> {
        match body.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::Bool(value)) => Ok(Some(*value)),
            Some(_) => Err(Refusal::Invalid),
        }
    };
    let word = |key: &str, allowed: &[&str]| -> Result<Option<String>, Refusal> {
        match body.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(text)) => {
                let lower = text.to_ascii_lowercase();
                if allowed.contains(&lower.as_str()) {
                    Ok(Some(lower))
                } else {
                    Err(Refusal::Invalid)
                }
            }
            Some(_) => Err(Refusal::Invalid),
        }
    };
    params.mode = word("mode", &["rule", "global", "direct"])?;
    params.find_process_mode = word("find-process-mode", &["always", "strict", "off"])?;
    params.log_level = match word(
        "log-level",
        &["debug", "info", "warning", "error", "silent"],
    )? {
        Some(level) => shapes::parse_level(&level),
        None => None,
    };
    params.allow_lan = flag("allow-lan")?;
    params.bind_address = match body.get("bind-address") {
        None | Some(Value::Null) => None,
        Some(Value::String(host)) => Some(host.clone()),
        Some(_) => return Err(Refusal::Invalid),
    };
    params.lan_allowed_ips = prefix_list(body, "lan-allowed-ips")?;
    params.lan_disallowed_ips = prefix_list(body, "lan-disallowed-ips")?;
    params.ipv6 = flag("ipv6")?;
    params.tcp_concurrent = flag("tcp-concurrent")?;
    params.mixed_port = match body.get("mixed-port") {
        None | Some(Value::Null) => None,
        Some(value) => Some(
            value
                .as_u64()
                .and_then(|port| u16::try_from(port).ok())
                .ok_or(Refusal::Invalid)?,
        ),
    };
    Ok(params)
}

/// Checked as prefixes by the core, which refuses the whole patch on a bad one.
fn prefix_list(body: &Map<String, Value>, key: &str) -> Result<Option<Vec<String>>, Refusal> {
    match body.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().map(str::to_string).ok_or(Refusal::Invalid))
            .collect::<Result<_, _>>()
            .map(Some),
        Some(_) => Err(Refusal::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use concord_proto::types::LogLevel;

    use super::*;

    fn object(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            _ => unreachable!(),
        }
    }

    #[test]
    fn a_patch_maps_what_concord_changes_live() {
        let body = object(json!({
            "mode": "Global",
            "log-level": "warning",
            "allow-lan": true,
            "mixed-port": 7891,
            "unknown-key": 1,
        }));
        let params = patch_params(&body, true).ok().unwrap();
        assert_eq!(params.mode.as_deref(), Some("global"));
        assert_eq!(params.log_level, Some(LogLevel::Warning));
        assert_eq!(params.allow_lan, Some(true));
        assert_eq!(params.mixed_port, Some(7891));
    }

    #[test]
    fn a_patch_carries_the_lan_keys() {
        let body = object(json!({
            "bind-address": "192.168.1.2",
            "lan-allowed-ips": ["192.168.0.0/16"],
            "lan-disallowed-ips": [],
        }));
        let params = patch_params(&body, true).ok().unwrap();
        assert_eq!(params.bind_address.as_deref(), Some("192.168.1.2"));
        assert_eq!(
            params.lan_allowed_ips,
            Some(vec!["192.168.0.0/16".to_string()])
        );
        assert_eq!(params.lan_disallowed_ips, Some(Vec::new()));
        let body = object(json!({ "lan-allowed-ips": "192.168.0.0/16" }));
        assert!(matches!(patch_params(&body, true), Err(Refusal::Invalid)));
    }

    #[test]
    fn a_patch_with_a_field_out_of_reach_changes_nothing() {
        let body = object(json!({ "mode": "rule", "port": 7890, "sniffing": true }));
        match patch_params(&body, false) {
            Err(Refusal::Unsupported(keys)) => assert_eq!(keys, ["port", "sniffing"]),
            _ => panic!("the patch must be refused"),
        }
    }

    #[test]
    fn tun_is_the_hosts_when_a_host_owns_the_core() {
        let body = object(json!({ "tun": { "enable": true } }));
        assert!(matches!(
            patch_params(&body, true),
            Err(Refusal::Unsupported(keys)) if keys == ["tun"]
        ));
        let params = patch_params(&body, false).ok().unwrap();
        assert_eq!(params.tun.map(|tun| tun.enable), Some(true));
    }

    #[test]
    fn a_bad_value_is_a_bad_body() {
        for body in [
            json!({ "mode": "everything" }),
            json!({ "ipv6": "yes" }),
            json!({ "mixed-port": 70000 }),
        ] {
            assert!(matches!(
                patch_params(&object(body), false),
                Err(Refusal::Invalid)
            ));
        }
    }
}
