#![forbid(unsafe_code)]

use imperialism_formats::{LegacySaveV62, LegacySnapshotContext};
use imperialism_testkit::{first_snapshot_difference, read_game_snapshot};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut arguments = env::args_os();
    let program = arguments.next().unwrap_or_else(|| "differential".into());
    let fixture = required_argument(&program, arguments.next())?;
    let source = match required_argument(&program, arguments.next())? {
        flag if flag == "--legacy-save" => {
            RustSource::LegacySave(required_argument(&program, arguments.next())?)
        }
        snapshot => RustSource::Snapshot(snapshot),
    };
    let seed = parse_seed(arguments.next(), arguments.next())?;
    if arguments.next().is_some() {
        return Err("differential received unexpected extra arguments".to_owned());
    }

    let repository = repository_root()?;
    let output = Command::new("just")
        .current_dir(repository)
        .arg("runtime-run")
        .arg(&fixture)
        .arg("--seed")
        .arg(seed.to_string())
        .output()
        .map_err(|error| format!("could not launch the C++ oracle: {error}"))?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        return Err(format!(
            "C++ oracle fixture {} failed:\n{}",
            Path::new(&fixture).display(),
            stderr.trim()
        ));
    }
    let artifact_dir = artifact_path(&stderr)
        .ok_or_else(|| "C++ oracle did not report its artifact directory".to_owned())?;
    let cpp_snapshot_path = artifact_dir.join("native-result.json");
    let cpp = read_game_snapshot(&cpp_snapshot_path)
        .map_err(|error| format!("C++ oracle snapshot is invalid: {error}"))?;
    let rust = match source {
        RustSource::Snapshot(path) => read_game_snapshot(Path::new(&path))
            .map_err(|error| format!("Rust snapshot is invalid: {error}"))?,
        RustSource::LegacySave(path) => {
            let bytes = fs::read(&path).map_err(|error| {
                format!(
                    "could not read retail save {}: {error}",
                    Path::new(&path).display()
                )
            })?;
            let save = LegacySaveV62::parse(&bytes)
                .map_err(|error| format!("could not decode retail save: {error}"))?;
            save.snapshot(LegacySnapshotContext {
                runtime_seed: cpp.rng.runtime_seed,
                crt_rand_state: cpp.rng.crt_rand_state,
                map_generation_lcg: cpp.rng.map_generation_lcg,
                zone_status_lcg: cpp.rng.zone_status_lcg,
                selected_nation: cpp.metadata.selected_nation,
            })
            .map_err(|error| format!("could not project retail save: {error}"))?
        }
    };

    println!("section       C++       Rust");
    for (section, cpp_hash, rust_hash) in [
        ("metadata", &cpp.hashes.metadata, &rust.hashes.metadata),
        ("rng", &cpp.hashes.rng, &rust.hashes.rng),
        ("world", &cpp.hashes.world, &rust.hashes.world),
        ("nations", &cpp.hashes.nations, &rust.hashes.nations),
        ("economy", &cpp.hashes.economy, &rust.hashes.economy),
        ("military", &cpp.hashes.military, &rust.hashes.military),
        ("missions", &cpp.hashes.missions, &rust.hashes.missions),
        ("pending", &cpp.hashes.pending, &rust.hashes.pending),
        ("state", &cpp.hashes.state, &rust.hashes.state),
    ] {
        println!("{section:<12} {cpp_hash}  {rust_hash}");
    }

    match first_snapshot_difference(&cpp, &rust)
        .map_err(|error| format!("could not compare snapshots: {error}"))?
    {
        None => {
            println!("semantic snapshots are identical");
            Ok(())
        }
        Some(difference) => Err(format!(
            "{} differs: C++ {:?}, Rust {:?}",
            difference.path, difference.original, difference.reimplementation
        )),
    }
}

enum RustSource {
    Snapshot(OsString),
    LegacySave(OsString),
}

fn required_argument(program: &OsString, value: Option<OsString>) -> Result<OsString, String> {
    value.ok_or_else(|| {
        format!(
            "usage: {} FIXTURE RUST_SNAPSHOT.json [--seed N]\n       {} FIXTURE --legacy-save SAVE.imp [--seed N]",
            Path::new(program).display(),
            Path::new(program).display()
        )
    })
}

fn parse_seed(flag: Option<OsString>, value: Option<OsString>) -> Result<u32, String> {
    match (flag, value) {
        (None, None) => Ok(1),
        (Some(flag), Some(value)) if flag == "--seed" => value
            .to_string_lossy()
            .parse()
            .map_err(|_| "--seed must be an unsigned integer".to_owned()),
        _ => Err("expected optional --seed N after the snapshot path".to_owned()),
    }
}

fn repository_root() -> Result<&'static Path, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .ok_or_else(|| "could not locate the repository root".to_owned())
}

fn artifact_path(stderr: &str) -> Option<PathBuf> {
    stderr.lines().rev().find_map(|line| {
        line.split_whitespace()
            .find_map(|field| field.strip_prefix("artifacts="))
            .filter(|value| *value != "none")
            .map(PathBuf::from)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_artifact_path_from_runtime_summary() {
        assert_eq!(
            artifact_path("runtime fixture: passed artifacts=/tmp/result failure=none\n"),
            Some(PathBuf::from("/tmp/result"))
        );
    }

    #[test]
    fn rejects_missing_artifact_path() {
        assert_eq!(
            artifact_path("runtime fixture: failed artifacts=none"),
            None
        );
    }
}
