use std::collections::BTreeMap;
use std::time::Duration;

use concord_common::{Change, DelayResult, Origin};
use concord_group::{NodeStateView, ProxyViews, StatusRanges};
use serde_json::Value;

use super::{Engine, NOT_INITIALIZED};
use crate::error::Failure;
use crate::ops;
use crate::views::SelectOutcome;

const DEFAULT_DELAY_TIMEOUT: Duration = Duration::from_secs(5);

impl Engine {
    pub fn selections(&self) -> BTreeMap<String, String> {
        self.outbounds()
            .map(|outbounds| outbounds.selections().into_iter().collect())
            .unwrap_or_default()
    }

    pub fn node_states(&self, names: Option<&[String]>) -> Vec<NodeStateView> {
        self.outbounds()
            .map(|outbounds| outbounds.node_states(names))
            .unwrap_or_default()
    }

    pub fn proxy_views(&self) -> ProxyViews {
        self.outbounds()
            .map(|outbounds| outbounds.views())
            .unwrap_or_default()
    }

    pub async fn select(&self, group: &str, proxy: &str) -> SelectOutcome {
        self.select_as(Origin::Host, group, proxy).await
    }

    pub async fn select_as(&self, origin: Origin, group: &str, proxy: &str) -> SelectOutcome {
        let mut seq = self.intent.lock().await;
        let Some(outbounds) = self.outbounds() else {
            return SelectOutcome {
                message: "Not found group".to_string(),
                changed: false,
                seq: *seq,
            };
        };
        let before = outbounds.selection(group);
        let staged = match outbounds.stage_selection(group, proxy) {
            Ok(staged) => staged,
            Err(failed) => {
                return SelectOutcome {
                    message: failed.message,
                    changed: false,
                    seq: *seq,
                };
            }
        };
        let after = outbounds.selection(group);
        if after != before {
            let group = group.to_string();
            self.publish_change(
                &mut seq,
                origin,
                Change::Selected {
                    group,
                    proxy: after,
                },
            );
        }
        let made = *seq;
        drop(seq);
        outbounds.probe_selection(&staged).await;
        let outcome = outbounds.settle_selection(staged);
        SelectOutcome {
            message: outcome.message,
            changed: outcome.changed,
            seq: made,
        }
    }

    pub async fn proxy_definition(&self, name: String) -> Result<Option<Value>, Failure> {
        let home = self.home().ok_or_else(|| Failure::core(NOT_INITIALIZED))?;
        if let Some(outbounds) = self.outbounds()
            && let Some(definition) = outbounds.definition(&name).await
        {
            return Ok(Some(Value::Object(definition)));
        }
        let path = home.join("config.yaml");
        ops::on_parse_stack(move || ops::configured_proxy(&path, &name))
            .await?
            .map(|mapping| mapping.map(Value::Object))
    }

    pub async fn test_delay(&self, name: &str, url: &str, timeout: i64) -> DelayResult {
        self.test_delay_expecting(name, url, &StatusRanges::default(), timeout)
            .await
    }

    pub async fn test_delay_expecting(
        &self,
        name: &str,
        url: &str,
        expected: &StatusRanges,
        timeout: i64,
    ) -> DelayResult {
        let url = if url.is_empty() {
            let current = self.shared.options.current.load();
            if current.test_url.is_empty() {
                concord_group::DEFAULT_TEST_URL.to_string()
            } else {
                current.test_url.clone()
            }
        } else {
            url.to_string()
        };
        let Some(outbounds) = self.outbounds() else {
            return DelayResult {
                url,
                name: name.to_string(),
                value: -2,
            };
        };
        let timeout = u64::try_from(timeout)
            .ok()
            .filter(|millis| *millis > 0)
            .map_or(DEFAULT_DELAY_TIMEOUT, Duration::from_millis);
        outbounds
            .test_delay_expecting(name, &url, expected, timeout)
            .await
    }
}
