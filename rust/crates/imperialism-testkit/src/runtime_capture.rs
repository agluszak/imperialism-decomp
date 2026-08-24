use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) fn repository_root() -> Result<&'static Path> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .context("could not locate the repository root")
}

/// One native runtime invocation and the unique output directory it wrote.
pub struct RuntimeRun {
    captures: serde_json::Value,
    capture_dir: PathBuf,
    game_dir: PathBuf,
    _output_dir: tempfile::TempDir,
}

impl RuntimeRun {
    pub fn capture<T: DeserializeOwned>(&self, name: &str) -> Result<T> {
        let value = self
            .captures
            .get(name)
            .with_context(|| format!("runtime captures.json is missing {name}"))?;
        serde_json::from_value(value.clone())
            .with_context(|| format!("decoding runtime {name} capture"))
    }

    pub fn save_backed_game_state(&self, name: &str) -> Result<imperialism_core::GameState> {
        crate::differential::load_save_backed_capture(&self.capture_dir, &self.captures, name)
    }

    pub fn game_dir(&self) -> &Path {
        &self.game_dir
    }
}

/// Run one catalogued native runtime scenario into a unique output directory.
pub fn run_runtime(scenario: &str) -> Result<RuntimeRun> {
    let output_dir = tempfile::Builder::new()
        .prefix("imperialism-runtime-")
        .tempdir()
        .context("creating a unique native result directory")?;
    let output = Command::new("just")
        .current_dir(repository_root()?.join("decomp"))
        .args(["--quiet", "runtime-run", scenario, "--seed", "1"])
        .env("IMPERIALISM_RUNTIME_RESULT_DIR", output_dir.path())
        .output()
        .context("launching native runtime scenario")?;

    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        bail!("native scenario {scenario} failed:\n{detail}");
    }

    let result_path = output_dir.path().join(format!("{scenario}.json"));
    let result_json: serde_json::Value = serde_json::from_slice(
        &fs::read(&result_path)
            .with_context(|| format!("reading native result {}", result_path.display()))?,
    )
    .with_context(|| format!("parsing native result {}", result_path.display()))?;
    let status = result_json.get("status").and_then(|value| value.as_str());
    if status != Some("passed") {
        bail!(
            "native scenario {scenario} status {}",
            status.unwrap_or("missing")
        );
    }
    let game_dir = result_json
        .get("host")
        .and_then(|host| host.get("game_dir"))
        .and_then(|value| value.as_str())
        .map(PathBuf::from)
        .context("native runtime result is missing host.game_dir")?;

    let captures_name = result_json
        .get("captures_path")
        .and_then(|value| value.as_str())
        .unwrap_or("captures.json");
    let captures_path = output_dir.path().join(captures_name);
    let captures: serde_json::Value = serde_json::from_slice(
        &fs::read(&captures_path)
            .with_context(|| format!("reading native captures {}", captures_path.display()))?,
    )
    .with_context(|| format!("parsing native captures {}", captures_path.display()))?;
    let capture_dir = captures_path
        .parent()
        .context("native captures path has no parent directory")?
        .to_owned();

    Ok(RuntimeRun {
        captures,
        capture_dir,
        game_dir,
        _output_dir: output_dir,
    })
}
