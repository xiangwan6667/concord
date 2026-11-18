use concord_proto::ApiError;
use concord_proto::types::*;

use super::{Control, core_error};
use crate::convert;
use crate::stream::Subscription;
use crate::watch as streams;

impl Control {
    pub(super) async fn traffic_watch(
        &self,
        params: TrafficWatchParams,
    ) -> Result<Subscription<Traffic, Traffic>, ApiError> {
        Ok(streams::traffic(
            self.engine.clone(),
            params.interval_ms,
            params.only_proxy,
        ))
    }

    pub(super) async fn traffic_reset(&self, _params: Empty) -> Result<Empty, ApiError> {
        self.engine.traffic_reset();
        Ok(Empty {})
    }

    pub(super) async fn connection_watch(
        &self,
        params: ConnectionWatchParams,
    ) -> Result<Subscription<ConnectionSnapshot, ConnectionDelta>, ApiError> {
        Ok(streams::connections(
            &self.engine,
            &self.bus,
            params.counters.unwrap_or(true),
        ))
    }

    pub(super) async fn connection_close(
        &self,
        params: ConnectionCloseParams,
    ) -> Result<Empty, ApiError> {
        if params.all {
            self.engine.close_all_connections();
        } else if let Some(ids) = params.ids {
            for record in self.engine.connections() {
                if ids.contains(&record.seq) {
                    record.close();
                }
            }
        } else {
            return Err(ApiError::invalid_params("name ids or set all"));
        }
        Ok(Empty {})
    }

    pub(super) async fn network_reset(&self, _params: Empty) -> Result<Empty, ApiError> {
        self.engine.reset_resolver_connections();
        Ok(Empty {})
    }

    pub(super) async fn network_update(
        &self,
        params: NetworkUpdateParams,
    ) -> Result<Empty, ApiError> {
        if let Some(servers) = params.dns_servers {
            self.engine.update_system_dns(servers.join(","));
        }
        if params.interface_changed {
            self.engine.reset_network();
        } else {
            self.engine.network_changed();
        }
        Ok(Empty {})
    }

    pub(super) async fn dns_clear_cache(&self, _params: Empty) -> Result<Empty, ApiError> {
        self.engine.clear_dns_cache();
        Ok(Empty {})
    }

    pub(super) async fn dns_flush_fake_ip(&self, _params: Empty) -> Result<Empty, ApiError> {
        self.engine.flush_fake_ip();
        Ok(Empty {})
    }

    pub(super) async fn dns_query(
        &self,
        params: DnsQueryParams,
    ) -> Result<DnsQueryResult, ApiError> {
        self.require_configured()?;
        let qtype = params.qtype.unwrap_or_else(|| "A".to_string());
        self.engine
            .dns_query(&params.name, &qtype)
            .await
            .map(convert::dns_query)
            .map_err(|failure| {
                if failure.code == "invalid_query" {
                    ApiError::invalid_field("qtype", failure.message)
                } else {
                    core_error(failure)
                }
            })
    }

    pub(super) async fn dns_watch(
        &self,
        _params: DnsWatchParams,
    ) -> Result<Subscription<Empty, DnsEntry>, ApiError> {
        let events = streams::map_stream(self.bus.watch_dns(), |entry| entry);
        Ok(Subscription::new(None, events))
    }

    pub(super) async fn route_watch(
        &self,
        _params: RouteWatchParams,
    ) -> Result<Subscription<RouteStamp, RouteStamp>, ApiError> {
        let events = streams::map_stream(self.bus.watch_route(), |stamp| stamp);
        let stamp = convert::route_stamp(self.engine.route_view());
        Ok(Subscription::new(Some(stamp), events))
    }

    pub(super) async fn route_check(
        &self,
        params: RouteCheckParams,
    ) -> Result<RouteCheckResult, ApiError> {
        let routes = params
            .routes
            .into_iter()
            .map(|route| {
                route
                    .into_iter()
                    .map(|hit| concord_engine::RouteHit {
                        host: hit.host,
                        proxy: hit.proxy,
                        exit: hit.exit,
                    })
                    .collect()
            })
            .collect();
        let (stamp, held) = self.engine.check_routes(routes).await;
        Ok(RouteCheckResult {
            epoch: stamp.epoch,
            version: stamp.version,
            held,
        })
    }
}
