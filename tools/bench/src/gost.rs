use std::path::Path;
use std::process::Stdio;

use tokio::process::Child;

use crate::cases::Case;
use crate::isolate::{self, Placement};

pub fn start(
    cases: &[Case],
    dir: &Path,
    placement: &Placement,
) -> Result<Vec<(String, Child)>, String> {
    let mut children = Vec::new();
    for case in cases {
        let Some((variable, listen)) = &case.gost else {
            continue;
        };
        let binary = std::env::var_os(variable).ok_or_else(|| {
            format!(
                "{} needs {variable} pointing to the gost server binary",
                case.name()
            )
        })?;
        let log = std::fs::File::create(dir.join(format!("logs/{}-gost.log", case.name())))
            .map_err(|error| error.to_string())?;
        let mut command = isolate::command(Path::new(&binary), placement);
        command
            .args(["-L", listen])
            .stdin(Stdio::null())
            .stdout(log.try_clone().map_err(|error| error.to_string())?)
            .stderr(log);
        let child = isolate::spawn(&mut command, placement)
            .map_err(|error| format!("spawn gost server: {error}"))?;
        children.push((case.name().to_string(), child));
    }
    Ok(children)
}
