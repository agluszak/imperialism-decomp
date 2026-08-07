#![forbid(unsafe_code)]

use imperialism_formats::LegacySaveV62;
use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

fn main() -> ExitCode {
    let Some(path) = env::args_os().nth(1) else {
        eprintln!("usage: legacy-inspect SAVE.imp");
        return ExitCode::FAILURE;
    };
    match inspect(Path::new(&path)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn inspect(path: &Path) -> Result<(), String> {
    let bytes =
        fs::read(path).map_err(|error| format!("could not read {}: {error}", path.display()))?;
    let save = LegacySaveV62::parse(&bytes).map_err(|error| error.to_string())?;
    serde_json::to_writer(std::io::stdout(), &save.map.snapshot_world())
        .map_err(|error| format!("could not encode map snapshot: {error}"))?;
    Ok(())
}
