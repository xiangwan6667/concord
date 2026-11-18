use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use concord_common::intercept::{InterceptFlow, UpstreamRequest};
use concord_common::sync::lock;
use concord_common::{Address, BoxStream, FlowMeta, InboundInfo, InboundKind, Network};
use serde::Serialize;
use tokio_util::sync::CancellationToken;

use crate::engine::{Core, MitmEngine};
use crate::script::{
    EVENT_ENGINE_STARTED, ScriptDial, ScriptError, ScriptEvent, ScriptInvocation, ScriptKind,
    ScriptResult,
};

/// The schedule reads the wall clock at least this often, because timers run
/// on the monotonic clock, which stops while the device sleeps.
const SCHEDULE_CHECK: Duration = Duration::from_secs(60);
const MAX_OUTPUT_LINES: usize = 200;

#[derive(Default)]
pub(crate) struct Tasks {
    inner: Mutex<TaskInner>,
}

#[derive(Default)]
struct TaskInner {
    stop: Option<CancellationToken>,
    running: HashSet<usize>,
}

/// What a script the user ran wrote, and its `$done` value as JSON.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ScriptOutput {
    pub logs: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub result: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

pub(crate) fn task_flow(host: &str, port: u16) -> InterceptFlow {
    let meta = FlowMeta {
        dscp: 0,
        network: Network::Tcp,
        inbound: InboundInfo::new(InboundKind::Inner),
        src: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        dst: Address::new(host, port),
    };
    let (host, dst_ip) = match &meta.dst {
        Address::Socket(addr) => (None, Some(addr.ip())),
        Address::Domain(name, _) => (Some(name.clone()), None),
    };
    InterceptFlow {
        meta,
        host,
        sniffed: false,
        dst_ip,
        port,
    }
}

struct TaskDial {
    core: Arc<Core>,
}

#[async_trait]
impl ScriptDial for TaskDial {
    async fn dial(&self, host: &str, port: u16) -> io::Result<BoxStream> {
        self.core
            .shared
            .dialer
            .dial(UpstreamRequest {
                flow: task_flow(host, port),
                hold: false,
            })
            .await
            .map(|upstream| upstream.stream)
            .map_err(|failure| failure.error)
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs() as i64)
}

impl MitmEngine {
    /// Schedules the cron scripts until `stop`, and lets `notify` run event scripts.
    pub fn start(&self) {
        let mut inner = lock(&self.tasks.inner);
        if inner.stop.is_some() {
            return;
        }
        let stop = CancellationToken::new();
        inner.stop = Some(stop.clone());
        let crons: Vec<usize> = self
            .core
            .config
            .rules
            .scripts
            .iter()
            .enumerate()
            .filter(|(_, script)| script.kind == ScriptKind::Cron)
            .map(|(index, _)| index)
            .collect();
        if !crons.is_empty() {
            let (core, engine) = (self.core.clone(), self.tasks_handle());
            self.core.handle.spawn(schedule(core, engine, crons, stop));
        }
    }

    /// A run under way finishes or times out.
    pub fn stop(&self) {
        if let Some(stop) = lock(&self.tasks.inner).stop.take() {
            stop.cancel();
        }
    }

    pub fn is_started(&self) -> bool {
        lock(&self.tasks.inner).stop.is_some()
    }

    pub fn notify(&self, event: &str) {
        if !self.is_started() {
            return;
        }
        for (index, script) in self.core.config.rules.scripts.iter().enumerate() {
            if script.kind == ScriptKind::Event && script.event == event {
                let invocation = event_invocation(&self.core, event);
                let (core, tasks) = (self.core.clone(), self.tasks_handle());
                self.core.handle.spawn(async move {
                    let _ = run_task(&core, &tasks, index, invocation).await;
                });
            }
        }
    }

    pub async fn run_script(&self, name: &str) -> Result<ScriptOutput, ScriptRunError> {
        let mut found = None;
        for (index, candidate) in self.core.config.rules.scripts.iter().enumerate() {
            if !candidate.is_task() || candidate.name != name {
                continue;
            }
            if found.is_some() {
                return Err(ScriptRunError::Ambiguous(name.to_string()));
            }
            found = Some(index);
        }
        let Some(index) = found else {
            return Err(ScriptRunError::NotFound(name.to_string()));
        };
        let script = &self.core.config.rules.scripts[index];
        let lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = lines.clone();
        let mut invocation = ScriptInvocation::base(Arc::new(TaskDial {
            core: self.core.clone(),
        }));
        invocation.trigger = "button".to_string();
        invocation.console = Some(Arc::new(move |line| {
            let mut lines = lock(&sink);
            if lines.len() < MAX_OUTPUT_LINES {
                lines.push(line.to_string());
            }
        }));
        match script.kind {
            ScriptKind::Cron => invocation.cronexp.clone_from(&script.cronexp),
            ScriptKind::Event => {
                invocation.event = Some(ScriptEvent {
                    name: "manually".to_string(),
                })
            }
            _ => {}
        }
        let outcome = run_task(&self.core, &self.tasks_handle(), index, invocation).await;
        let mut output = ScriptOutput {
            logs: lock(&lines).clone(),
            ..ScriptOutput::default()
        };
        match outcome {
            Err(err) => output.error = err.to_string(),
            Ok(result) => output.result = String::from_utf8_lossy(&result.value).into_owned(),
        }
        Ok(output)
    }

    fn tasks_handle(&self) -> Arc<Tasks> {
        self.tasks.clone()
    }

    pub fn notify_started(&self) {
        self.notify(EVENT_ENGINE_STARTED);
    }
}

/// Why a script run on request did not start. A script that starts and fails reports in
/// `ScriptOutput::error` instead.
#[derive(Debug, thiserror::Error)]
pub enum ScriptRunError {
    #[error("decryption is off")]
    Off,
    #[error("no cron, event or generic script is named {0:?}")]
    NotFound(String),
    #[error("more than one cron, event or generic script is named {0:?}")]
    Ambiguous(String),
}

fn event_invocation(core: &Arc<Core>, event: &str) -> ScriptInvocation {
    let mut invocation = ScriptInvocation::base(Arc::new(TaskDial { core: core.clone() }));
    invocation.event = Some(ScriptEvent {
        name: event.to_string(),
    });
    invocation
}

/// Runs a script whose time has come once, even when the device slept through
/// several of its times.
async fn schedule(core: Arc<Core>, tasks: Arc<Tasks>, crons: Vec<usize>, stop: CancellationToken) {
    let clock = core.shared.clock.clone();
    let schedules: Vec<(usize, &crate::cron::CronSchedule)> = crons
        .iter()
        .filter_map(|index| {
            let script = core.config.rules.scripts.get(*index)?;
            Some((*index, script.cron.as_ref()?))
        })
        .collect();
    let mut next: Vec<Option<i64>> = schedules
        .iter()
        .map(|(_, cron)| cron.next(unix_now(), clock.as_ref()))
        .collect();
    loop {
        let now = unix_now();
        let mut wait = SCHEDULE_CHECK;
        for ((index, cron), due) in schedules.iter().zip(next.iter_mut()) {
            let Some(at) = *due else { continue };
            if now >= at {
                let (core, tasks, index) = (core.clone(), tasks.clone(), *index);
                let cronexp = core
                    .config
                    .rules
                    .scripts
                    .get(index)
                    .map(|s| s.cronexp.clone())
                    .unwrap_or_default();
                tokio::spawn(async move {
                    let mut invocation =
                        ScriptInvocation::base(Arc::new(TaskDial { core: core.clone() }));
                    invocation.cronexp = cronexp;
                    let _ = run_task(&core, &tasks, index, invocation).await;
                });
                *due = cron.next(now, clock.as_ref());
            }
            if let Some(at) = *due {
                wait = wait.min(Duration::from_secs((at - now).max(0) as u64));
            }
        }
        tokio::select! {
            () = stop.cancelled() => return,
            () = tokio::time::sleep(wait.max(Duration::from_millis(100))) => {}
        }
    }
}

async fn run_task(
    core: &Arc<Core>,
    tasks: &Arc<Tasks>,
    index: usize,
    invocation: ScriptInvocation,
) -> Result<ScriptResult, ScriptError> {
    let Some(script) = core.config.rules.scripts.get(index) else {
        return Err(ScriptError("the script is gone".to_string()));
    };
    if !lock(&tasks.inner).running.insert(index) {
        tracing::info!(
            "[MITM] script {} is still running and skips this run",
            script.name
        );
        return Err(ScriptError("the script is still running".to_string()));
    }
    let _release = Release {
        tasks: tasks.clone(),
        index,
    };
    tracing::info!("[MITM] running script {}", script.name);
    let dial = Arc::new(TaskDial { core: core.clone() });
    let result = core.invoke(&core.task_gate, script, invocation, dial).await;
    if let Err(err) = &result {
        tracing::warn!("[MITM] script {}: {err}", script.name);
    }
    result
}

struct Release {
    tasks: Arc<Tasks>,
    index: usize,
}

impl Drop for Release {
    fn drop(&mut self) {
        lock(&self.tasks.inner).running.remove(&self.index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn task_requests_are_routed_by_host() {
        let flow = task_flow("example.test", 443);
        assert!(flow.is_inner() && flow.meta.network == Network::Tcp);
        assert_eq!(
            (flow.host.as_deref(), flow.dst_ip, flow.port),
            (Some("example.test"), None, 443)
        );
        let flow = task_flow("::ffff:1.2.3.4", 80);
        assert_eq!(flow.host, None);
        assert_eq!(flow.dst_ip, Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
    }
}
