use anyhow::{Context, Result, bail};
use serde::de::DeserializeOwned;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Copy, Debug)]
pub enum NativeCommand<'a> {
    RuntimeScenario(&'a str),
    Transition(&'a str),
}

impl NativeCommand<'_> {
    fn name(&self) -> &'static str {
        match self {
            Self::RuntimeScenario(_) => "runtime scenario",
            Self::Transition(_) => "native transition case",
        }
    }

    fn case(&self) -> &str {
        match self {
            Self::RuntimeScenario(case) | Self::Transition(case) => case,
        }
    }

    fn just_args(&self) -> [&'static str; 2] {
        match self {
            Self::RuntimeScenario(_) => ["--quiet", "runtime-run"],
            Self::Transition(_) => ["--quiet", "native-oracle"],
        }
    }

    fn result_name(&self) -> String {
        match self {
            Self::RuntimeScenario(case) => format!("{case}.json"),
            Self::Transition(_) => "result.json".to_owned(),
        }
    }
}

/// One native invocation and the captures written into its unique result directory.
pub struct NativeRun {
    captures: serde_json::Value,
    capture_dir: PathBuf,
    _output_dir: tempfile::TempDir,
}

impl NativeRun {
    pub fn execute(command: NativeCommand<'_>) -> Result<Self> {
        let output_dir = tempfile::Builder::new()
            .prefix("imperialism-native-")
            .tempdir()
            .context("creating a unique native result directory")?;
        let output = Command::new("just")
            .current_dir(repository_root()?.join("decomp"))
            .args(command.just_args())
            .arg(command.case())
            .args(["--seed", "1"])
            .env("IMPERIALISM_RUNTIME_RESULT_DIR", output_dir.path())
            .output()
            .with_context(|| format!("launching {} {}", command.name(), command.case()))?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            bail!("{} {} failed:\n{detail}", command.name(), command.case());
        }

        let result_path = output_dir.path().join(command.result_name());
        let result_json: serde_json::Value = serde_json::from_slice(
            &fs::read(&result_path)
                .with_context(|| format!("reading native result {}", result_path.display()))?,
        )
        .with_context(|| format!("parsing native result {}", result_path.display()))?;
        let status = result_json
            .get("status")
            .and_then(serde_json::Value::as_str);
        if status != Some("passed") {
            bail!(
                "{} {} status {}",
                command.name(),
                command.case(),
                status.unwrap_or("missing")
            );
        }

        let captures_name = result_json
            .get("captures_path")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("captures.json");
        let captures_path = output_dir.path().join(captures_name);
        let captures = serde_json::from_slice(
            &fs::read(&captures_path)
                .with_context(|| format!("reading native captures {}", captures_path.display()))?,
        )
        .with_context(|| format!("parsing native captures {}", captures_path.display()))?;
        let capture_dir = captures_path
            .parent()
            .context("native captures path has no parent directory")?
            .to_owned();

        Ok(Self {
            captures,
            capture_dir,
            _output_dir: output_dir,
        })
    }

    pub fn capture<T: DeserializeOwned>(&self, name: &str) -> Result<T> {
        let value = self
            .captures
            .get(name)
            .with_context(|| format!("native captures.json is missing {name}"))?;
        serde_json::from_value(value.clone())
            .with_context(|| format!("decoding native {name} capture"))
    }

    pub fn save_backed_game_state(&self, name: &str) -> Result<imperialism_core::GameState> {
        crate::differential::load_save_backed_capture(&self.capture_dir, &self.captures, name)
    }

    pub(crate) fn captures(&self) -> &serde_json::Value {
        &self.captures
    }

    pub(crate) fn capture_dir(&self) -> &Path {
        &self.capture_dir
    }
}

fn repository_root() -> Result<&'static Path> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .context("could not locate the repository root")
}
