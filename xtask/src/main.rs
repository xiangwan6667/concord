mod bench;
mod commits;
#[cfg(test)]
mod doc_paths;
mod internal_marks;
mod interop_peers;
mod layers;
mod mihomo_keys;
#[cfg(test)]
mod public_tree;
#[cfg(test)]
mod ratchets;
#[cfg(test)]
mod reference_choices;
mod schema;
mod size;
#[cfg(test)]
mod stream_policy;
#[cfg(test)]
mod task_owner;
#[cfg(test)]
mod tunables;
#[cfg(test)]
mod unsafe_policy;
#[cfg(test)]
mod vendor_patches;

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let result = match args.next().as_deref() {
        Some("check-layers") => layers::check(),
        Some("schema") => schema::run(args.next().as_deref() == Some("--check")),
        Some("check-size") => size::check(args.next().as_deref(), args.next().as_deref()),
        Some("bench") => bench::run(args.collect()),
        Some("check-commits") => commits::check(&args.collect::<Vec<_>>()),
        Some("mihomo-keys") => mihomo_keys::run(args.next().as_deref()),
        Some("check-interop-peers") => interop_peers::check(),
        _ => Err(
            "usage: xtask check-layers | schema [--check] | check-size <file> <max-bytes> \
             | check-commits <git log revisions> | mihomo-keys <mihomo checkout> | check-interop-peers \
             | bench [--quick|--full] [--base <rev>|--no-baseline] [--mihomo <path>] [concord-bench run options]"
                .to_string(),
        ),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}
