use std::sync::Arc;

use concord_api::{Control, ControlOptions, EventBus};
use concord_engine::{Engine, EngineConfig};
use concord_ffi::Hub;
use concord_rpc::Server;
use tokio::runtime::{Builder, Runtime};

use crate::platform::{AndroidPlatform, PlatformHost};

const CAPABILITIES: [&str; 3] = ["tun.inherited", "host.protect", "host.resolveUid"];

pub type ThreadHook = Arc<dyn Fn() + Send + Sync>;

/// Everything one `libconcord.so` holds: the runtime that carries the flows, the control
/// surface on it, and the hub through which the Flutter engine and the service open sessions.
pub struct Core<C: PlatformHost> {
    _runtime: Runtime,
    control: Arc<Control>,
    platform: Arc<AndroidPlatform<C>>,
    hub: Arc<Hub>,
}

impl<C: PlatformHost> Core<C> {
    /// `on_thread_start` runs on every runtime thread, so the JVM attachment happens once per thread.
    pub fn new(on_thread_start: Option<ThreadHook>) -> std::io::Result<Self> {
        let workers = concord_platform::assignable_cpus().map_or(1, |count| count.get());
        let mut builder = Builder::new_multi_thread();
        builder
            .worker_threads(workers)
            .thread_name("concord")
            .enable_all();
        if let Some(hook) = on_thread_start {
            builder.on_thread_start(move || hook());
        }
        let runtime = builder.build()?;
        let entered = runtime.enter();

        let bus = EventBus::new();
        let platform = Arc::new(AndroidPlatform::<C>::new());
        let engine = Engine::new(EngineConfig {
            sink: bus.clone(),
            android: true,
            platform: platform.clone(),
        });
        let weak = Arc::downgrade(&engine);
        platform.bind_sdk_version(move || weak.upgrade().map_or(0, |engine| engine.sdk_version()));
        let control = Control::new(
            engine,
            bus,
            ControlOptions {
                privileged: false,
                capabilities: CAPABILITIES.map(String::from).to_vec(),
                build: env!("CARGO_PKG_VERSION").to_owned(),
                profile_controller: false,
            },
        );
        let server = Arc::new(Server::new(control.clone()));
        runtime.spawn(concord_controller::serve(control.clone()));
        drop(entered);
        let hub = Hub::new(runtime.handle().clone(), server);
        Ok(Core {
            _runtime: runtime,
            control,
            platform,
            hub,
        })
    }

    pub fn control(&self) -> &Arc<Control> {
        &self.control
    }

    pub fn hub(&self) -> &Arc<Hub> {
        &self.hub
    }

    /// The `VpnService` side that answers `protect` and the owner lookups, or none once it is gone.
    pub fn set_platform_host(&self, host: Option<Arc<C>>) {
        self.platform.set_host(host);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::mpsc::{Receiver as Inbox, channel};
    use std::time::Duration;

    use concord_ffi::Receiver;
    use serde_json::{Value, json};

    use super::*;

    use concord_common::sync::lock;

    struct Silent;

    impl PlatformHost for Silent {
        fn protect(&self, _fd: i32) -> bool {
            true
        }
        fn resolve_uid(&self, _protocol: i32, _source: &str, _target: &str) -> i32 {
            -1
        }
        fn resolve_package(&self, _uid: i32) -> String {
            String::new()
        }
    }

    struct Tap(Mutex<std::sync::mpsc::Sender<Vec<u8>>>);

    impl Receiver for Tap {
        fn deliver(&mut self, message: Vec<u8>) -> bool {
            lock(&self.0).send(message).is_ok()
        }
    }

    fn open(core: &Core<Silent>) -> (u64, Inbox<Vec<u8>>) {
        let (sender, inbox) = channel();
        (core.hub().open(Box::new(Tap(Mutex::new(sender)))), inbox)
    }

    fn call(core: &Core<Silent>, session: u64, inbox: &Inbox<Vec<u8>>, message: &Value) -> Value {
        assert!(core.hub().send(session, message.to_string().into_bytes()));
        serde_json::from_slice(&inbox.recv_timeout(Duration::from_secs(10)).unwrap()).unwrap()
    }

    fn hello(core: &Core<Silent>, session: u64, inbox: &Inbox<Vec<u8>>) -> Value {
        call(
            core,
            session,
            inbox,
            &json!({"id": 1, "method": "core.hello", "params": {
                "protocol": {"min": 1, "max": 1},
                "client": {"name": "test", "version": "0"}}}),
        )
    }

    #[test]
    fn hello_names_the_android_platform_and_the_hooks_the_service_provides() {
        let core = Core::<Silent>::new(None).unwrap();
        let (session, inbox) = open(&core);
        let reply = hello(&core, session, &inbox);
        assert_eq!(reply["result"]["server"]["implementation"], "concord");
        assert_eq!(reply["result"]["platform"]["os"], "android");
        assert_eq!(reply["result"]["platform"]["privileged"], false);
        assert_eq!(
            reply["result"]["platform"]["capabilities"],
            json!(["tun.inherited", "host.protect", "host.resolveUid"])
        );
    }

    #[test]
    fn two_sessions_stream_traffic_independently() {
        let core = Core::<Silent>::new(None).unwrap();
        let (first, first_inbox) = open(&core);
        let (second, second_inbox) = open(&core);
        hello(&core, first, &first_inbox);
        hello(&core, second, &second_inbox);

        let watch = call(
            &core,
            first,
            &first_inbox,
            &json!({"id": 2, "method": "traffic.watch", "params": {"intervalMs": 50}}),
        );
        assert_eq!(watch["result"]["snapshot"]["totalUp"], 0);
        assert!(
            second_inbox
                .recv_timeout(Duration::from_millis(200))
                .is_err()
        );
        let sub = watch["result"]["sub"].clone();
        assert!(
            core.hub().send(
                first,
                json!({"method": "$/credit", "params": {"sub": sub, "n": 4}})
                    .to_string()
                    .into_bytes()
            )
        );
        let event: Value =
            serde_json::from_slice(&first_inbox.recv_timeout(Duration::from_secs(10)).unwrap())
                .unwrap();
        assert_eq!(event["method"], "$/event");
    }

    #[test]
    fn a_host_set_for_the_platform_is_cleared_with_none() {
        let core = Core::<Silent>::new(None).unwrap();
        core.set_platform_host(Some(Arc::new(Silent)));
        assert!(core.platform.has_host());
        core.set_platform_host(None);
        assert!(!core.platform.has_host());
    }
}
