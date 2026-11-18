use std::sync::atomic::Ordering;
use std::time::Duration;

use ::http::Method;
use bytes::Bytes;
use concord_common::{CoreEvent, DelayResult, DialCx, Initiator, Network};
use futures_util::stream::{self, StreamExt};
use tokio::time::Instant;

use crate::check::Check;
use crate::group::Touch;
use crate::health::{Outcome, StatusRanges};
use crate::http::{self, Target, TlsSettings};
use crate::node::Node;
use crate::outbounds::{Outbounds, Resolved, dummy_flow};

const ROUND_CONCURRENCY: usize = 10;
const HEAD_LIMIT: usize = 10 << 20;

/// What Go's http.Client adds to a HEAD request on its own.
fn head_headers() -> [(String, String); 1] {
    [("user-agent".into(), "Go-http-client/1.1".into())]
}

impl Outbounds {
    pub(crate) async fn url_test_node(
        &self,
        node: &Node,
        url: &str,
        expected: &StatusRanges,
        timeout: Duration,
    ) -> Outcome {
        let tested = tokio::time::timeout(timeout, self.probe(node, url, expected, timeout)).await;
        let timed_out = tested.is_err();
        let (delay, failed, satisfied) = match tested {
            Ok(Ok((delay, satisfied))) => (delay, false, satisfied),
            _ => (0, true, false),
        };
        node.health()
            .record(url, delay, failed, satisfied, &self.shared.health_epoch);
        let outcome = Outcome::from_hook(delay, timed_out);
        self.shared.emit(|| {
            CoreEvent::Delay(DelayResult {
                url: url.to_string(),
                name: node.name().to_string(),
                value: outcome.value(),
            })
        });
        outcome
    }

    async fn probe(
        &self,
        node: &Node,
        url: &str,
        expected: &StatusRanges,
        timeout: Duration,
    ) -> Result<(u16, bool), String> {
        let target = Target::parse(url).map_err(|err| err.to_string())?;
        let unified = self.shared.defaults.unified_delay();
        let mut started = Instant::now();
        let dst = target.address();
        let flow = dummy_flow(dst.clone(), Network::Tcp);
        let (leaf, chain) = match self.walk(node.clone(), &flow, dst.domain(), Touch::Yes) {
            Resolved::Route { leaf, chain, .. } => (leaf, chain),
            Resolved::Rematch(leaf) => {
                let chain = vec![leaf.info().name.clone()].into();
                (leaf, chain)
            }
            Resolved::Pass | Resolved::PassRule => return Err("PASS cannot be tested".into()),
            Resolved::Rejected(reason) => return Err(reason.to_string()),
            Resolved::Unknown => return Err("proxy not found".into()),
        };
        let env = self.env();
        let cx = DialCx::new(&env, Initiator::Other, Some(started + timeout));
        let kind = leaf.info().kind;
        let io = match leaf.connect(&cx, &dst).await {
            Ok(io) => self.watch_first_write(&chain, kind, io),
            Err(err) => {
                self.note_dial_failed(&chain, kind, Network::Tcp, &err);
                return Err(err.to_string());
            }
        };
        let settings = TlsSettings {
            trust: self.shared.trust.clone(),
            skip_cert_verify: false,
            offer_h2: false,
        };
        let mut connection = http::connect(io, &target, &settings)
            .await
            .map_err(|err| err.to_string())?;
        let first = connection
            .send(Method::HEAD, &head_headers(), Bytes::new(), HEAD_LIMIT)
            .await
            .map_err(|err| err.to_string())?;
        let mut status = first.status;
        if unified {
            let second = Instant::now();
            match connection
                .send(Method::HEAD, &head_headers(), Bytes::new(), HEAD_LIMIT)
                .await
            {
                Ok(response) => {
                    status = response.status;
                    started = second;
                }
                Err(err) if url.starts_with("http://") => {
                    tracing::warn!(
                        "{} failed to get the second response from {url}: {err}; HTTPS is more reliable for health checks",
                        node.name()
                    );
                }
                Err(_) => {}
            }
        }
        let millis = started.elapsed().as_millis().min(u128::from(u16::MAX));
        let delay = u16::try_from(millis).unwrap_or(u16::MAX).max(1);
        Ok((delay, expected.accepts(status)))
    }

    /// The longest wins, so no scheduled check passes a node the manual test fails.
    fn configured_timeout(&self, name: &str, url: &str) -> Option<Duration> {
        self.checks()
            .iter()
            .filter(|check| check.covers(name))
            .filter_map(|check| check.timeout_for(url))
            .max()
    }

    /// `None` means no slot came free in time, which says nothing about the node.
    pub async fn test_delay(&self, name: &str, url: &str, timeout: Duration) -> DelayResult {
        self.test_delay_expecting(name, url, &StatusRanges::default(), timeout)
            .await
    }

    /// A response outside `expected` counts as a failure, as in a health check.
    pub async fn test_delay_expecting(
        &self,
        name: &str,
        url: &str,
        expected: &StatusRanges,
        timeout: Duration,
    ) -> DelayResult {
        let url = if url.is_empty() {
            self.shared.default_url()
        } else {
            url.to_string()
        };
        let mut result = DelayResult {
            url: url.clone(),
            name: name.to_string(),
            value: Outcome::Failed.value(),
        };
        let Some(node) = self.node(name) else {
            self.report_missing(name);
            return result;
        };
        let timeout = self
            .configured_timeout(name, &url)
            .unwrap_or(if timeout.is_zero() {
                self.shared.default_timeout()
            } else {
                timeout
            });
        let outcome = self.url_test_node(&node, &url, expected, timeout).await;
        self.shared.request_refresh();
        result.value = outcome.value();
        result
    }

    /// Every node of the profile misses when the apply fell back to another config, so one
    /// line per applied config names it.
    fn report_missing(&self, name: &str) {
        if self.shared.missing_reported.swap(true, Ordering::Relaxed) {
            return;
        }
        tracing::error!("delay test: {name:?} is not part of the applied config");
    }

    pub(crate) async fn run_round(&self, check: &Check, version: u32, nodes: Vec<Node>) {
        let timeout = check
            .timeout()
            .unwrap_or_else(|| self.shared.default_timeout());
        for (url, expected, matcher) in check.plan() {
            let url = url.trim().to_string();
            if url.is_empty() {
                continue;
            }
            let selected = nodes.iter().filter(|node| {
                matcher
                    .as_ref()
                    .is_none_or(|matcher| matcher.is_match(node.name()))
            });
            stream::iter(selected)
                .for_each_concurrent(ROUND_CONCURRENCY, |node| {
                    let (url, expected) = (&url, &expected);
                    async move {
                        if check.version() == version {
                            self.url_test_node(node, url, expected, timeout).await;
                        }
                    }
                })
                .await;
        }
        self.shared.request_refresh();
    }
}
