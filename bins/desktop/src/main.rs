//! `concord`: the core process of the desktop app. It reads the session token
//! from its standard input, dials the socket the app listens on, proves both ends
//! hold the token, then speaks length-prefixed JSON frames until that connection ends.
//! `concord run` runs a profile without an app; see `standalone`. `concord -t` checks one; see
//! `check`.

mod check;
mod standalone;

use std::io::BufRead;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use concord_api::{Control, ControlOptions, EventBus, LogBridge};
use concord_engine::{Engine, EngineConfig};
use concord_ipc::{FramedChannel, Token};
use concord_rpc::Server;
use tokio::runtime::Builder;
use tracing_subscriber::layer::SubscriberExt;

const EXIT_CLEANUP_TIMEOUT: Duration = Duration::from_secs(3);
/// The token and its line end, which the host writes with `writeln`.
const TOKEN_LINE_LIMIT: u64 = concord_ipc::TOKEN_LEN as u64 + 2;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let Some(first) = args.next() else {
        eprintln!("Arguments error");
        return ExitCode::FAILURE;
    };
    if first == "-t" {
        return match check::parse(args) {
            Ok(options) => block_on(|| check::run(options)),
            Err(message) => {
                eprint!("[ERROR] {message}\n\n{}", check::USAGE);
                ExitCode::FAILURE
            }
        };
    }
    if first == "run" {
        return match standalone::parse(args) {
            Ok(standalone::Command::Run(options)) => block_on(|| async {
                let control = control(false, true);
                standalone::run(control, options).await
            }),
            Ok(standalone::Command::Help) => {
                print!("{}", standalone::USAGE);
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprint!("[ERROR] {message}\n\n{}", standalone::USAGE);
                ExitCode::FAILURE
            }
        };
    }
    let token = match read_token(std::io::stdin().lock()) {
        Ok(token) => token,
        Err(reason) => {
            eprintln!("[ERROR] session token: {reason}");
            return ExitCode::FAILURE;
        }
    };
    block_on(|| embedded(first, token))
}

fn block_on<F: Future<Output = ExitCode>>(work: impl FnOnce() -> F) -> ExitCode {
    concord_platform::raise_fd_limit();
    let workers = concord_platform::available_cpus().map_or(1, |count| count.get());
    let mut builder = Builder::new_multi_thread();
    if std::env::var_os("TOKIO_WORKER_THREADS").is_none() {
        builder.worker_threads(workers);
    }
    let runtime = match builder.enable_all().build() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("[ERROR] runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    runtime.block_on(work())
}

/// `errors_to_stderr` echoes error logs to stderr whether or not a `log.watch` is open.
/// `profile_controller` is set when no host drives the core.
fn control(errors_to_stderr: bool, profile_controller: bool) -> Arc<Control> {
    let bus = EventBus::new();
    let bridge = LogBridge::new(bus.gate().clone(), bus.clone(), errors_to_stderr);
    let _ = tracing::subscriber::set_global_default(tracing_subscriber::registry().with(bridge));

    let engine = Engine::new(EngineConfig {
        sink: bus.clone(),
        android: false,
        platform: Arc::new(concord_platform::NativePlatform::new()),
    });
    Control::new(
        engine,
        bus,
        ControlOptions {
            privileged: is_privileged(),
            capabilities: Vec::new(),
            build: env!("CARGO_PKG_VERSION").to_owned(),
            profile_controller,
        },
    )
}

async fn shut_down(control: &Control) {
    if tokio::time::timeout(EXIT_CLEANUP_TIMEOUT, control.shutdown())
        .await
        .is_err()
    {
        eprintln!("[ERROR] core cleanup did not finish before exit");
    }
}

async fn embedded(address: String, token: Token) -> ExitCode {
    let control = control(std::env::var_os("CONCORD_DEBUG").is_some(), false);
    let mut socket = match concord_ipc::dial(&address).await {
        Ok(socket) => socket,
        Err(err) => {
            eprintln!("[ERROR] dial {address}: {err}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(err) = concord_ipc::initiate(&mut socket, &token).await {
        eprintln!("[ERROR] ipc authentication: {err}");
        return ExitCode::FAILURE;
    }

    let server = Server::new(Arc::clone(&control));
    let controller = tokio::spawn(concord_controller::serve(Arc::clone(&control)));
    tokio::select! {
        () = server.serve(FramedChannel::new(socket)) => {}
        () = termination() => {}
    }

    controller.abort();
    shut_down(&control).await;
    ExitCode::SUCCESS
}

fn read_token(stdin: impl BufRead) -> Result<Token, &'static str> {
    let mut line = String::new();
    stdin
        .take(TOKEN_LINE_LIMIT)
        .read_line(&mut line)
        .map_err(|_| "unreadable")?;
    if line.is_empty() {
        return Err("missing");
    }
    Token::parse(line.trim_end_matches(['\r', '\n'])).map_err(|_| "malformed")
}

#[cfg(unix)]
#[allow(unsafe_code, reason = "geteuid takes no arguments and cannot fail")]
fn is_privileged() -> bool {
    // SAFETY: see the allow above.
    unsafe { libc::geteuid() == 0 }
}

#[cfg(windows)]
fn is_privileged() -> bool {
    false
}

#[cfg(unix)]
async fn termination() {
    use tokio::signal::unix::{SignalKind, signal};
    let Ok(mut terminate) = signal(SignalKind::terminate()) else {
        std::future::pending::<()>().await;
        return;
    };
    tokio::select! {
        _ = terminate.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

#[cfg(windows)]
async fn termination() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::read_token;

    const TOKEN: &str = "00112233445566778899aabbccddeeff";

    #[test]
    fn the_token_is_the_first_line_with_or_without_a_line_ending() {
        for input in [
            format!("{TOKEN}\n"),
            format!("{TOKEN}\r\n"),
            TOKEN.to_owned(),
        ] {
            assert!(read_token(input.as_bytes()).is_ok());
        }
    }

    #[test]
    fn a_missing_or_malformed_token_is_named_without_echoing_it() {
        assert_eq!(read_token(&b""[..]).unwrap_err(), "missing");
        assert_eq!(read_token(&b"secret\n"[..]).unwrap_err(), "malformed");
        let endless = vec![b'a'; 4096];
        assert_eq!(read_token(&endless[..]).unwrap_err(), "malformed");
    }
}
