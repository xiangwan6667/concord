//! `concord -t -c <file>`: loads a profile without running it and prints, as JSON, what applying
//! it would warn about. Exits 0 when it loads and 1 when it does not, as mihomo's `-t`.

use std::process::ExitCode;

use serde_json::json;

pub const USAGE: &str = "\
Usage: concord -t -c <file> [--android]

  -c, --config <file>  The Clash profile to check
      --android        Check it as the Android build loads it

Prints {\"warnings\": [{\"level\", \"code\", \"path\", \"message\"}]} when the profile loads,
or {\"error\": \"...\"} and exit status 1 when it does not.
";

#[derive(Debug, PartialEq)]
pub struct Options {
    pub config: String,
    pub android: bool,
}

pub fn parse(args: impl IntoIterator<Item = String>) -> Result<Options, &'static str> {
    let mut config = None;
    let mut android = false;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => config = Some(args.next().ok_or("-c needs a value")?),
            "--android" => android = true,
            _ => return Err("an argument -t does not take"),
        }
    }
    Ok(Options {
        config: config.ok_or("-t needs -c <file>")?,
        android,
    })
}

pub async fn run(options: Options) -> ExitCode {
    match concord_engine::ops::check_config(options.config, options.android).await {
        Ok(warnings) => {
            println!("{}", json!({ "warnings": warnings }));
            ExitCode::SUCCESS
        }
        Err(failure) => {
            println!("{}", json!({ "error": failure.message }));
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn a_check_needs_a_profile() {
        assert_eq!(
            parse(args(&["-c", "a.yaml", "--android"])),
            Ok(Options {
                config: "a.yaml".into(),
                android: true
            })
        );
        assert!(parse(args(&[])).is_err());
        assert!(parse(args(&["-c"])).is_err());
        assert!(parse(args(&["-x"])).is_err());
    }
}
