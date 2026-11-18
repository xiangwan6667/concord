#[cfg(unix)]
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use concord_common::sync::lock;
use concord_tun::{DeviceSource, TunRunner};

use super::Engine;
use crate::apply::Applied;
use crate::faults::{Service, ServiceFault};
#[cfg(unix)]
use crate::tun::{InheritedTun, TunStartError, vpn_options};
use crate::tun::{KeepOffDevice, congestion_of, options_of, start_runner, stop_runner};

impl Engine {
    /// `listener.ReCreateTun`: a running device with the same settings is left alone,
    /// and a start that failed is tried again by the next call.
    pub(super) async fn reconcile_tun(&self, applied: &Applied) {
        let desired = (applied.tun.clone(), applied.tun_inet4, applied.general.ipv6);
        let mut slot = self.tun.lock().await;
        let same = lock(&self.tun_config).as_ref() == Some(&desired);
        if same && slot.as_ref().is_some_and(|runner| !runner.is_finished()) {
            return;
        }
        self.close_tun(&mut slot).await;
        self.faults.set_tun(None);
        {
            let mut held = lock(&self.tun_config);
            *held = Some(desired);
        }
        if !applied.tun.enable {
            return;
        }
        let options = options_of(&applied.tun, applied.tun_inet4, applied.general.ipv6);
        let congestion = congestion_of(&applied.tun.congestion_controller);
        let exclusion = Arc::new(KeepOffDevice {
            platform: self.shared.platform.clone(),
            sockets: self.shared.sockets.clone(),
            tunnel: self.shared.tunnel.clone(),
            auto_detect: applied.tun.auto_detect_interface,
        });
        match start_runner(
            &self.shared.tunnel,
            &self.shared.sockets,
            &options,
            DeviceSource::Create,
            congestion,
            Some(exclusion),
        )
        .await
        {
            Ok(runner) => *slot = Some(runner),
            Err(err) => {
                let message = format!("Start TUN listening error: {err}");
                tracing::error!("{message}");
                self.faults.set_tun(Some(ServiceFault {
                    service: Service::Tun,
                    address: applied.tun.device.clone(),
                    kind: err.kind,
                    message,
                }));
            }
        }
    }

    pub(super) async fn close_tun(&self, slot: &mut Option<TunRunner>) {
        if let Some(runner) = slot.take() {
            stop_runner(runner).await;
        }
    }

    /// `handleStartTun`: runs TUN on a descriptor the host opened. Takes the
    /// descriptor: it is closed on every failing path.
    #[cfg(unix)]
    pub async fn start_inherited_tun(
        &self,
        fd: OwnedFd,
        tun: InheritedTun,
    ) -> Result<(), TunStartError> {
        self.shared.sockets.protect_held().await;
        {
            let mut slot = self.tun.lock().await;
            self.close_tun(&mut slot).await;
            let (options, congestion) = vpn_options(&tun)?;
            let runner = start_runner(
                &self.shared.tunnel,
                &self.shared.sockets,
                &options,
                DeviceSource::Adopt(fd),
                congestion,
                None,
            )
            .await?;
            *slot = Some(runner);
        }
        if self.running.load(Ordering::SeqCst) {
            self.reset_resolver_connections();
            self.route.reset(self.is_running());
        } else {
            self.start_listeners().await;
        }
        Ok(())
    }

    /// `StopTun`.
    pub async fn stop_vpn_tun(&self) {
        {
            let mut slot = self.tun.lock().await;
            self.close_tun(&mut slot).await;
        }
        if self.running.load(Ordering::SeqCst) {
            self.stop_listeners().await;
        }
    }
}
