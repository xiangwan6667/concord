use std::sync::Arc;
use std::sync::atomic::Ordering;

use concord_dns::Resolver;
use concord_inbound::ListenSpec;

use super::Engine;
use crate::apply::{Applied, listen_spec};
use crate::dns_server::DnsServer;
use crate::faults::{Service, ServiceFault};

impl Engine {
    pub(super) async fn sync_dns_server(&self, address: &str, mark: u32, resolver: Arc<Resolver>) {
        let mut server = self.dns_server.lock().await;
        if let Some(running) = server.as_ref() {
            if running.address() == address && running.mark() == mark {
                running.set_resolver(resolver);
                return;
            }
            *server = None;
        }
        self.faults.set_dns(None);
        if address.is_empty() {
            return;
        }
        match DnsServer::start(address, mark, resolver, &self.tasks, &self.handle) {
            Ok(started) => {
                tracing::info!("DNS server listening at: {address}");
                *server = Some(started);
            }
            Err(err) => {
                let message = format!("Start DNS server error: {err}");
                tracing::error!("{message}");
                self.faults.set_dns(Some(ServiceFault {
                    service: Service::Dns,
                    address: address.to_string(),
                    kind: err.kind(),
                    message,
                }));
            }
        }
    }

    /// `updateListeners`: nothing happens until the host has asked the core to run.
    pub(super) async fn reconcile_listeners(&self, applied: &Applied) {
        if !self.running.load(Ordering::SeqCst) {
            return;
        }
        let spec: ListenSpec = listen_spec(&applied.general);
        let handler = Arc::new(self.shared.tunnel.clone());
        let errors = self.listeners.reconcile(&spec, handler).await;
        for error in &errors {
            tracing::error!("{error}");
        }
        self.faults
            .set_listeners(errors.iter().map(ServiceFault::listener).collect());
        if !self.android {
            self.reconcile_tun(applied).await;
        }
    }

    pub async fn start_listeners(&self) {
        let state = self.state.lock().await;
        self.set_running(true);
        if let Some(applied) = state.as_ref() {
            self.reconcile_listeners(applied).await;
        }
        self.reset_resolver_connections();
        self.route.reset(self.is_running());
    }

    pub async fn stop_listeners(&self) {
        let _state = self.state.lock().await;
        self.set_running(false);
        self.listeners.stop_all().await;
        self.faults.set_listeners(Vec::new());
        if !self.android {
            let mut slot = self.tun.lock().await;
            self.close_tun(&mut slot).await;
            self.faults.set_tun(None);
        }
        self.reset_resolver_connections();
        self.route.reset(self.is_running());
    }
}
