//! `concord run`: the core on its own, driven through the same calls an embedding app makes
//! over the control connection (`config.validate`, `core.init`, `config.apply`, `engine.start`).

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use concord_api::{Control, ControlService, Delivery, EventStream};
use concord_proto::ApiError;
use concord_proto::types::{
    ConfigApplyParams, ConfigValidateParams, CoreInitParams, Empty, LogEntry, LogLevel,
    LogWatchParams, ProfileRef,
};
use futures_util::StreamExt;

pub const USAGE: &str = "\
Usage: concord run [-c <file>] [-d <directory>]

  -c, --config <file>         The Clash profile to run [default: <directory>/config.yaml]
  -d, --directory <directory> Home of the working config, geo data and provider caches
                              [default: ~/.config/concord]
  -h, --help                  Print this help

The profile is copied to <directory>/config.yaml, which the core owns. SIGHUP re-reads it.
";

const CONFIG_FILE: &str = "config.yaml";

#[derive(Debug, PartialEq)]
pub enum Command {
    Run(Options),
    Help,
}

#[derive(Debug, PartialEq)]
pub struct Options {
    pub config: Option<PathBuf>,
    pub home: PathBuf,
}

pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Command, String> {
    let mut config = None;
    let mut home = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let slot = match arg.as_str() {
            "-h" | "--help" => return Ok(Command::Help),
            "-c" | "--config" => &mut config,
            "-d" | "--directory" => &mut home,
            _ => return Err(format!("unexpected argument {arg}")),
        };
        let value = args.next().ok_or_else(|| format!("{arg} needs a value"))?;
        *slot = Some(PathBuf::from(value));
    }
    let home = match home {
        Some(home) => home,
        None => default_home().ok_or("no home directory is known; pass -d")?,
    };
    Ok(Command::Run(Options { config, home }))
}

fn default_home() -> Option<PathBuf> {
    let home = std::env::var_os(if cfg!(windows) { "USERPROFILE" } else { "HOME" })?;
    Some(PathBuf::from(home).join(".config").join("concord"))
}

pub async fn run(control: Arc<Control>, options: Options) -> ExitCode {
    let controller = tokio::spawn(concord_controller::serve(Arc::clone(&control)));
    let code = match start(&control, &options).await {
        Ok(home) => {
            serve(&control, options.config.as_deref(), &home).await;
            ExitCode::SUCCESS
        }
        Err(message) => {
            eprintln!("[ERROR] {message}");
            ExitCode::FAILURE
        }
    };
    controller.abort();
    super::shut_down(&control).await;
    code
}

async fn start(control: &Arc<Control>, options: &Options) -> Result<PathBuf, String> {
    let home = std::path::absolute(&options.home)
        .map_err(|err| format!("{}: {err}", options.home.display()))?;
    std::fs::create_dir_all(&home).map_err(|err| format!("{}: {err}", home.display()))?;
    let logs = watch_logs(control).await.map_err(|err| err.to_string())?;
    tokio::spawn(print_logs(Arc::clone(control), logs));
    control
        .core_init(CoreInitParams {
            home: home.to_string_lossy().into_owned(),
            sdk_int: None,
        })
        .await
        .map_err(|err| err.to_string())?;
    load(control, options.config.as_deref(), &home).await?;
    control
        .engine_start(Empty {})
        .await
        .map_err(|err| err.to_string())?;
    Ok(home)
}

/// Checks the profile before it replaces the working copy, so a bad edit followed by SIGHUP
/// leaves the running config alone.
async fn load(control: &Control, config: Option<&Path>, home: &Path) -> Result<(), String> {
    let working = home.join(CONFIG_FILE);
    let source = match config {
        Some(config) => {
            std::path::absolute(config).map_err(|err| format!("{}: {err}", config.display()))?
        }
        None => working.clone(),
    };
    let validated = control
        .config_validate(ConfigValidateParams {
            profile: ProfileRef {
                path: source.to_string_lossy().into_owned(),
            },
        })
        .await
        .map_err(|err| format!("{}: {err}", source.display()))?;
    if let Some(issue) = validated.issues.first() {
        return Err(format!("{}: {}", source.display(), issue.message));
    }
    control.set_profile_source(source.clone());
    if !same_file(&source, &working) {
        std::fs::copy(&source, &working)
            .map_err(|err| format!("copy to {}: {err}", working.display()))?;
    }
    let applied = control
        .config_apply(ConfigApplyParams {
            profile: None,
            overlay: None,
            selection: control.selections(),
            options: Default::default(),
        })
        .await
        .map_err(|err| err.to_string())?;
    for warning in applied.warnings {
        eprintln!("[WARNING] {}: {}", warning.path, warning.message);
    }
    control.adopt_profile_controller().await;
    Ok(())
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

async fn serve(control: &Control, config: Option<&Path>, home: &Path) {
    let terminated = super::termination();
    tokio::pin!(terminated);
    let mut hangup = Hangup::new();
    loop {
        tokio::select! {
            () = &mut terminated => return,
            () = hangup.recv() => {
                match load(control, config, home).await {
                    Ok(()) => eprintln!("[INFO] reloaded the config"),
                    Err(message) => eprintln!("[ERROR] reload: {message}"),
                }
            }
        }
    }
}

/// Leaves the level to the log gate, which `config.apply` sets from the profile's `log-level`.
async fn watch_logs(control: &Control) -> Result<EventStream<LogEntry>, ApiError> {
    let subscription = control
        .log_watch(LogWatchParams {
            level: Some(LogLevel::Debug),
            ..Default::default()
        })
        .await?;
    Ok(subscription.events)
}

async fn print_logs(control: Arc<Control>, mut events: EventStream<LogEntry>) {
    while let Some(delivery) = events.next().await {
        match delivery {
            Delivery::Event { data, .. } => eprintln!("[{}] {}", label(data.level), data.text),
            Delivery::Resync => match watch_logs(&control).await {
                Ok(fresh) => events = fresh,
                Err(_) => return,
            },
        }
    }
}

fn label(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Debug => "DEBUG",
        LogLevel::Info => "INFO",
        LogLevel::Warning => "WARNING",
        LogLevel::Error | LogLevel::Silent => "ERROR",
    }
}

#[cfg(unix)]
struct Hangup(Option<tokio::signal::unix::Signal>);

#[cfg(unix)]
impl Hangup {
    fn new() -> Self {
        use tokio::signal::unix::{SignalKind, signal};
        Hangup(signal(SignalKind::hangup()).ok())
    }

    async fn recv(&mut self) {
        if let Some(signal) = &mut self.0
            && signal.recv().await.is_some()
        {
            return;
        }
        std::future::pending().await
    }
}

#[cfg(windows)]
struct Hangup;

#[cfg(windows)]
impl Hangup {
    fn new() -> Self {
        Hangup
    }

    async fn recv(&mut self) {
        std::future::pending().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(args: &[&str]) -> Result<Command, String> {
        parse(args.iter().map(|arg| (*arg).to_owned()))
    }

    #[test]
    fn config_and_directory_are_read_in_either_spelling() {
        let expected = Command::Run(Options {
            config: Some(PathBuf::from("a.yaml")),
            home: PathBuf::from("home"),
        });
        assert_eq!(parse_args(&["-c", "a.yaml", "-d", "home"]), Ok(expected));
        let expected = Command::Run(Options {
            config: Some(PathBuf::from("a.yaml")),
            home: PathBuf::from("home"),
        });
        assert_eq!(
            parse_args(&["--directory", "home", "--config", "a.yaml"]),
            Ok(expected)
        );
    }

    #[test]
    fn help_wins_and_unknown_or_dangling_arguments_are_refused() {
        assert_eq!(parse_args(&["-c", "a.yaml", "-h"]), Ok(Command::Help));
        assert!(parse_args(&["-x"]).is_err());
        assert!(parse_args(&["-d", "home", "-c"]).is_err());
    }
}
