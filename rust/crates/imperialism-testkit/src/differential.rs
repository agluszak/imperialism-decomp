//! Process-isolated native transition comparison.

use anyhow::{Context, Result, bail};
use imperialism_core::GameState;
use serde::de::DeserializeOwned;
use std::fmt::Debug;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{
    EvidenceKind, RuntimeResultExpectations, first_serialized_difference, read_runtime_result,
};

const NATIVE_ORACLE: &str = "native_transition_oracle";
const NATIVE_CASE_ENV: &str = "IMPERIALISM_NATIVE_CASE";
const DEFAULT_SEED: u32 = 1;
const DIFFERENTIAL_CAPTURES: &[&str] = &["before", "case", "after", "result"];

/// Run the shared C++ native transition oracle for `case_name`, apply the matching
/// Rust operation to the captured `before` state, and compare result plus post-state.
pub fn compare_native<C, R>(
    case_name: &str,
    apply: impl FnOnce(&mut GameState, C) -> R,
) -> Result<()>
where
    C: DeserializeOwned,
    R: DeserializeOwned + Debug + PartialEq,
{
    let result = run_native_case(case_name, DEFAULT_SEED)?;
    compare_native_from_result(&result, apply)
}

/// Compare against an already-published Python runtime `result.json`.
pub fn compare_native_from_result<C, R>(
    result: &Path,
    apply: impl FnOnce(&mut GameState, C) -> R,
) -> Result<()>
where
    C: DeserializeOwned,
    R: DeserializeOwned + Debug + PartialEq,
{
    let expectations = RuntimeResultExpectations {
        name: NATIVE_ORACLE,
        seed: DEFAULT_SEED,
        evidence_kind: EvidenceKind::RetailFixtureOracle,
        required_captures: DIFFERENTIAL_CAPTURES,
    };
    let runtime = read_runtime_result(result, expectations)
        .with_context(|| format!("reading runtime result from {}", result.display()))?;
    let mut actual: GameState = runtime
        .capture("before")
        .with_context(|| format!("reading before from {}", result.display()))?;
    let case: C = runtime
        .capture("case")
        .with_context(|| format!("reading case from {}", result.display()))?;
    let expected: GameState = runtime
        .capture("after")
        .with_context(|| format!("reading after from {}", result.display()))?;
    let expected_result: R = runtime
        .capture("result")
        .with_context(|| format!("reading result from {}", result.display()))?;

    let actual_result = apply(&mut actual, case);
    if actual_result != expected_result {
        bail!("operation result differs: C++ {expected_result:?}, Rust {actual_result:?}");
    }
    assert_game_state_eq(&expected, &actual)
}

pub fn assert_game_state_eq(expected: &GameState, actual: &GameState) -> Result<()> {
    if expected == actual {
        return Ok(());
    }
    match first_serialized_difference(expected, actual).context("comparing game states")? {
        None => Ok(()),
        Some(difference) => bail!(
            "{} differs: expected {:?}, actual {:?}",
            difference.path,
            difference.original,
            difference.reimplementation
        ),
    }
}

/// Run one native transition case through the shared oracle and return its result path.
pub fn run_native_case(case_name: &str, seed: u32) -> Result<PathBuf> {
    let repository = repository_root()?;
    let output = Command::new("just")
        .current_dir(repository.join("decomp"))
        .env(NATIVE_CASE_ENV, case_name)
        .arg("runtime-run")
        .arg(NATIVE_ORACLE)
        .arg("--seed")
        .arg(seed.to_string())
        .output()
        .context("launching the native transition oracle")?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        bail!(
            "native transition case {} failed:\n{}",
            case_name,
            stderr.trim()
        );
    }
    let artifact_dir =
        artifact_path(&stderr).context("native oracle did not report its artifact directory")?;
    Ok(artifact_dir.join("result.json"))
}

/// Run one catalogued native runtime scenario (UI/application tests, not model cases).
pub fn run_native_scenario(name: &str, seed: u32) -> Result<PathBuf> {
    let repository = repository_root()?;
    let output = Command::new("just")
        .current_dir(repository.join("decomp"))
        .arg("runtime-run")
        .arg(name)
        .arg("--seed")
        .arg(seed.to_string())
        .output()
        .context("launching the native runtime scenario")?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !output.status.success() {
        bail!("native scenario {} failed:\n{}", name, stderr.trim());
    }
    let artifact_dir =
        artifact_path(&stderr).context("native scenario did not report its artifact directory")?;
    Ok(artifact_dir.join("result.json"))
}

fn repository_root() -> Result<&'static Path> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .context("could not locate the repository root")
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
    fn artifact_path_reads_the_trailing_artifacts_field() {
        let stderr = "progress\nstatus=passed artifacts=/tmp/run-1\n";
        assert_eq!(artifact_path(stderr), Some(PathBuf::from("/tmp/run-1")));
    }
}
