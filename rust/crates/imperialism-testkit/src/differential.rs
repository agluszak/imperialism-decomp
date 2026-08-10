//! Process-isolated native transition comparison.

use anyhow::{Context, Result, bail};
use imperialism_core::GameState;
use serde::de::DeserializeOwned;
use std::fmt::Debug;
use std::path::Path;
use std::process::Command;

use crate::{
    EvidenceKind, RuntimeResultExpectations, ValidatedRuntimeResult, decode_runtime_result,
    first_serialized_difference,
};

const NATIVE_ORACLE: &str = "native_transition_oracle";
const NATIVE_CASE_ENV: &str = "IMPERIALISM_NATIVE_CASE";
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
    let runtime = run_native_case_result(case_name, DIFFERENTIAL_CAPTURES)?;
    compare_validated(runtime, apply)
}

/// Compare a catalogued retail-fixture runtime scenario (UI / multi-step flows such as
/// `easy_turn_from_save`) the same way as a native transition case.
pub fn compare_runtime_scenario<C, R>(
    name: &str,
    apply: impl FnOnce(&mut GameState, C) -> R,
) -> Result<()>
where
    C: DeserializeOwned,
    R: DeserializeOwned + Debug + PartialEq,
{
    let runtime = run_retail_fixture_result(name, DIFFERENTIAL_CAPTURES)?;
    compare_validated(runtime, apply)
}

fn compare_validated<C, R>(
    runtime: ValidatedRuntimeResult,
    apply: impl FnOnce(&mut GameState, C) -> R,
) -> Result<()>
where
    C: DeserializeOwned,
    R: DeserializeOwned + Debug + PartialEq,
{
    let mut actual: GameState = runtime.capture("before")?;
    let case: C = runtime.capture("case")?;
    let expected: GameState = runtime.capture("after")?;
    let expected_result: R = runtime.capture("result")?;

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

/// Run one native transition case through the shared oracle and decode stdout JSON.
pub fn run_native_case_result(
    case_name: &str,
    required_captures: &'static [&'static str],
) -> Result<ValidatedRuntimeResult> {
    let output = Command::new("just")
        .current_dir(repository_root()?.join("decomp"))
        .env(NATIVE_CASE_ENV, case_name)
        .args(["--quiet", "runtime-run", NATIVE_ORACLE, "--seed", "1"])
        .output()
        .context("launching the native transition oracle")?;

    if !output.status.success() {
        bail!(
            "native transition case {} failed:\n{}",
            case_name,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    decode_runtime_result(
        output.stdout.as_slice(),
        RuntimeResultExpectations {
            name: NATIVE_ORACLE,
            seed: 1,
            evidence_kind: EvidenceKind::RetailFixtureOracle,
            required_captures,
        },
    )
    .context("decoding native transition oracle result")
}

/// Run one catalogued native runtime scenario and decode the published result JSON from stdout.
pub fn run_retail_fixture_result(
    name: &str,
    required_captures: &'static [&'static str],
) -> Result<ValidatedRuntimeResult> {
    let output = Command::new("just")
        .current_dir(repository_root()?.join("decomp"))
        .args(["--quiet", "runtime-run", name, "--seed", "1"])
        .output()
        .context("launching native runtime scenario")?;

    if !output.status.success() {
        bail!(
            "native scenario {name} failed:\n{}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    decode_runtime_result(
        output.stdout.as_slice(),
        RuntimeResultExpectations {
            name,
            seed: 1,
            evidence_kind: EvidenceKind::RetailFixtureOracle,
            required_captures,
        },
    )
    .context("decoding native runtime result")
}

fn repository_root() -> Result<&'static Path> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .context("could not locate the repository root")
}
