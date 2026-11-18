use std::net::IpAddr;

use async_trait::async_trait;
use concord_common::{FlowKey, ProcessInfo, RawSocket};
use concord_platform::InterfaceInfo;

use super::*;

/// The native platform, except that every connection belongs to `curl` and each lookup is counted.
struct Owners {
    native: NativePlatform,
    lookups: AtomicUsize,
}

impl Owners {
    fn lookups(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Platform for Owners {
    fn protect(&self, socket: RawSocket) -> bool {
        self.native.protect(socket)
    }

    async fn find_owner(&self, _flow: &FlowKey) -> Option<ProcessInfo> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        Some(ProcessInfo {
            uid: None,
            name: "curl".to_string(),
            path: "/usr/bin/curl".to_string(),
        })
    }

    fn default_interface(&self) -> Option<InterfaceInfo> {
        self.native.default_interface()
    }

    fn interface_for(&self, dest: IpAddr) -> Option<InterfaceInfo> {
        self.native.interface_for(dest)
    }

    fn interface_by_name(&self, name: &str) -> Option<InterfaceInfo> {
        self.native.interface_by_name(name)
    }

    fn system_dns(&self) -> Vec<SocketAddr> {
        self.native.system_dns()
    }

    fn fd_pressure(&self) -> bool {
        self.native.fd_pressure()
    }

    fn is_local_ip(&self, ip: IpAddr) -> bool {
        self.native.is_local_ip(ip)
    }

    fn set_excluded_interfaces(&self, names: Vec<String>) {
        self.native.set_excluded_interfaces(names);
    }

    fn network_changed(&self) {
        self.native.network_changed();
    }
}

async fn switch_to(rig: &Rig, mode: &str) {
    let request = UpdateRequest {
        find_process_mode: Some(mode.to_string()),
        ..UpdateRequest::default()
    };
    rig.engine.update(request).await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_find_process_mode_looks_up_the_owner_when_it_says() {
    let decided = tcp_echo().await;
    let asks = tcp_echo().await;
    let owners = Arc::new(Owners {
        native: NativePlatform::new(),
        lookups: AtomicUsize::new(0),
    });
    let rig = Rig::on(tempfile::tempdir().unwrap(), owners.clone());
    rig.apply(&format!(
        "rules:\n  - DST-PORT,{},DIRECT\n  - PROCESS-NAME,curl,REJECT\n  - MATCH,DIRECT\n",
        decided.port()
    ))
    .await
    .unwrap();
    rig.engine.start_listeners().await;

    let mut stream = socks_connect(rig.mixed, decided).await.unwrap();
    round_trip(&mut stream).await;
    assert_eq!(
        owners.lookups(),
        0,
        "strict, the default, waits for a rule to ask"
    );
    assert!(refused(rig.mixed, asks).await);
    assert_eq!(owners.lookups(), 1, "strict looks up when a rule asks");

    switch_to(&rig, "always").await;
    let mut stream = socks_connect(rig.mixed, decided).await.unwrap();
    round_trip(&mut stream).await;
    assert_eq!(owners.lookups(), 2, "always looks up every connection");

    switch_to(&rig, "off").await;
    let mut stream = socks_connect(rig.mixed, asks).await.unwrap();
    round_trip(&mut stream).await;
    assert_eq!(
        owners.lookups(),
        2,
        "off never looks up, so the process rule cannot match"
    );

    switch_to(&rig, "strict").await;
    assert!(refused(rig.mixed, asks).await);
    assert_eq!(owners.lookups(), 3);
    rig.engine.shutdown().await;
}
