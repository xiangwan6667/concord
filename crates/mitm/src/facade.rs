use std::sync::{Arc, Mutex, MutexGuard};

use arc_swap::{ArcSwap, ArcSwapOption};
use async_trait::async_trait;
use concord_common::BoxStream;
use concord_common::intercept::{ConnInterceptor, InterceptFlow, Offer, UpstreamDialer};
use concord_platform::HomeDir;
use concord_tls::TrustStore;
use tokio::runtime::Handle;

use crate::ca::{Authority, CaError, CertificateInfo};
use crate::capture::{Body, CaptureStore, Exchange, ExchangeList};
use concord_config::mitm::MitmDef;

use crate::config::{Config, ParseEnv, RawConfig, Validation, check};
use crate::cron::LocalClock;
use crate::engine::{MitmEngine, Shared};
use crate::limits::Pressure;
use crate::script::{EVENT_ENGINE_STARTED, EVENT_PROFILE_RELOADED, ScriptHost, ScriptRuntime};
use crate::task::{ScriptOutput, ScriptRunError};

pub struct MitmEnv {
    pub home: Arc<HomeDir>,
    pub trust: Arc<TrustStore>,
    pub dialer: Arc<dyn UpstreamDialer>,
    pub clock: Arc<dyn LocalClock>,
    pub runtime: Option<Arc<dyn ScriptRuntime>>,
}

#[derive(Default)]
struct State {
    running: bool,
}

pub struct Mitm {
    #[cfg(feature = "script")]
    quickjs: Option<Arc<crate::quickjs::QuickJs>>,
    shared: Arc<Shared>,
    handle: Handle,
    state: Mutex<State>,
    current: Arc<ArcSwapOption<MitmEngine>>,
}

struct Router {
    current: Arc<ArcSwapOption<MitmEngine>>,
}

#[async_trait]
impl ConnInterceptor for Router {
    async fn offer(&self, flow: &InterceptFlow, stream: BoxStream, head: Vec<u8>) -> Offer {
        let engine = self.current.load_full();
        match engine {
            Some(engine) => engine.offer(flow, stream, head).await,
            None => Offer::Declined { stream, head },
        }
    }

    fn drop_quic(&self, flow: &InterceptFlow) -> bool {
        self.current
            .load()
            .as_ref()
            .is_some_and(|engine| engine.drop_quic(flow))
    }
}

fn lock(mutex: &Mutex<State>) -> MutexGuard<'_, State> {
    concord_common::sync::lock(mutex)
}

impl Mitm {
    pub fn new(env: MitmEnv) -> Mitm {
        let trust = Arc::new(ArcSwap::new(env.trust));
        #[cfg(feature = "script")]
        let quickjs = env
            .runtime
            .is_none()
            .then(|| crate::quickjs::QuickJs::new(env.home.clone(), trust.clone()));
        #[cfg(feature = "script")]
        let runtime = env
            .runtime
            .or_else(|| quickjs.clone().map(|js| js as Arc<dyn ScriptRuntime>));
        #[cfg(not(feature = "script"))]
        let runtime = env.runtime;
        let pressure = Arc::new(Pressure::default());
        let shared = Arc::new(Shared {
            authority: Arc::new(Authority::new(env.home)),
            captures: CaptureStore::new(pressure.clone()),
            pressure,
            trust,
            dialer: env.dialer,
            scripts: Arc::new(ScriptHost::new(runtime)),
            clock: env.clock,
        });
        Mitm {
            #[cfg(feature = "script")]
            quickjs,
            shared,
            handle: Handle::current(),
            state: Mutex::default(),
            current: Arc::new(ArcSwapOption::empty()),
        }
    }

    pub fn interceptor(&self) -> Arc<dyn ConnInterceptor> {
        Arc::new(Router {
            current: self.current.clone(),
        })
    }

    pub fn authority(&self) -> &Arc<Authority> {
        &self.shared.authority
    }

    pub fn scripts(&self) -> &Arc<ScriptHost> {
        &self.shared.scripts
    }

    fn parse_env(&self) -> ParseEnv {
        ParseEnv {
            resources: self.shared.authority.resources_dir(),
            scripts: self.shared.scripts.clone(),
        }
    }

    pub fn certificate(&self) -> Result<Option<CertificateInfo>, CaError> {
        match self.shared.authority.current() {
            Ok(ca) => Ok(Some(ca.info())),
            Err(CaError::Missing) => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub fn generate_certificate(&self) -> Result<CertificateInfo, CaError> {
        Ok(self.shared.authority.renew()?.info())
    }

    pub fn issue_certificate(&self, host: &str) -> Result<String, CaError> {
        self.shared.authority.current()?.issue_pem(host)
    }

    pub fn validate(&self, raw: &RawConfig) -> Validation {
        check(raw, &self.parse_env())
    }

    /// Replaces the section, keeping the engine, its schedule and the tasks
    /// under way while the section stays the same. Returns the lines that could
    /// not be read.
    pub fn apply(&self, raw: Option<RawConfig>) -> Vec<String> {
        self.apply_def(raw.map(|raw| MitmDef::read(&raw)), true)
    }

    /// As [Mitm::apply] for a profile's section, whose lines that cannot be read its load
    /// reported: returns the lines that read but cannot be put in force.
    pub fn apply_section(&self, def: Option<MitmDef>) -> Vec<String> {
        self.apply_def(def, false)
    }

    fn apply_def(&self, def: Option<MitmDef>, unread: bool) -> Vec<String> {
        let state = lock(&self.state);
        let previous = self.current.load_full();
        let Some(def) = def.filter(|def| def.enable) else {
            self.current.store(None);
            self.shared.captures.clear();
            if let Some(previous) = previous {
                previous.stop();
            }
            return Vec::new();
        };
        let (config, errors) = Config::compile(def, &self.parse_env(), unread);
        if let Some(previous) = &previous
            && previous.config().same(&config)
            && previous.trusts(&self.shared.trust.load())
        {
            if state.running {
                previous.notify(EVENT_PROFILE_RELOADED);
            }
            return errors;
        }
        let engine = Arc::new(MitmEngine::new(
            config,
            self.shared.clone(),
            self.handle.clone(),
        ));
        self.current.store(Some(engine.clone()));
        if let Some(previous) = &previous {
            previous.stop();
        }
        if state.running {
            engine.start();
            engine.notify(if previous.is_some() {
                EVENT_PROFILE_RELOADED
            } else {
                EVENT_ENGINE_STARTED
            });
        }
        errors
    }

    pub fn set_running(&self, running: bool) {
        let mut state = lock(&self.state);
        if state.running == running {
            return;
        }
        state.running = running;
        if !running {
            self.shared.captures.clear();
        }
        let Some(engine) = self.current.load_full() else {
            return;
        };
        if running {
            engine.start();
            engine.notify(EVENT_ENGINE_STARTED);
        } else {
            engine.stop();
        }
    }

    pub fn notify(&self, event: &str) {
        if let Some(engine) = self.current.load_full() {
            engine.notify(event);
        }
    }

    pub async fn run_script(&self, name: &str) -> Result<ScriptOutput, ScriptRunError> {
        let Some(engine) = self.current.load_full() else {
            return Err(ScriptRunError::Off);
        };
        engine.run_script(name).await
    }

    /// Takes effect with the next `apply`: an engine keeps the store it was built with.
    pub fn set_trust(&self, trust: Arc<TrustStore>) {
        self.shared.trust.store(trust);
    }

    pub fn set_capture(&self, on: bool) {
        self.shared.captures.set_capture(on);
    }

    pub fn exchanges(&self, connection: &str) -> ExchangeList {
        self.shared.captures.exchanges(connection)
    }

    /// Exchanges the capture may hold, none while MITM is off.
    pub fn capture_entries(&self) -> usize {
        if self.current.load().is_some() {
            self.shared.captures.max_entries()
        } else {
            0
        }
    }

    pub fn exchange(&self, id: i64) -> Option<Exchange> {
        self.shared.captures.find(id)
    }

    pub fn body(&self, id: i64, response: bool) -> Option<Body> {
        self.shared.captures.find_body(id, response)
    }

    pub fn set_pressure(&self, level: u8) {
        if self.shared.pressure.set(level) {
            self.shared.captures.shed();
        }
    }

    pub fn flush_scripts(&self) {
        #[cfg(feature = "script")]
        if let Some(quickjs) = &self.quickjs {
            quickjs.flush();
        }
    }

    pub fn pressure_level(&self) -> u8 {
        self.shared.pressure.level()
    }

    #[cfg(test)]
    pub(crate) fn engine(&self) -> Option<Arc<MitmEngine>> {
        self.current.load_full()
    }
}
