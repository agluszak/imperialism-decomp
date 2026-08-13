//! Process-isolated native transition comparison.

use anyhow::{Context, Result, bail};
use imperialism_core::{
    GameState, NewsState, PendingWorkState, RngState, TurnState, UnitIdAllocator,
};
use imperialism_formats::{LegacyGameStateContext, LegacySaveV62};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::fmt::Debug;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::{
    EvidenceKind, RuntimeCaptureError, RuntimeResultExpectations, ValidatedRuntimeResult,
    first_serialized_difference, read_runtime_result,
};

const NATIVE_ORACLE: &str = "native_transition_oracle";
const NATIVE_CASE_ENV: &str = "IMPERIALISM_NATIVE_CASE";
const DIFFERENTIAL_CAPTURES: &[&str] = &["before", "case", "after", "result"];

#[derive(Debug, Deserialize)]
struct SaveBackedCapture {
    save: String,
    ephemeral: EphemeralGameState,
}

#[derive(Debug, Deserialize)]
struct EphemeralGameState {
    turn: TurnState,
    unit_ids: UnitIdAllocator,
    rng: RngState,
    news: NewsState,
    pending: PendingWorkState,
}

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
    let run = run_native_case_result(case_name, DIFFERENTIAL_CAPTURES)?;
    compare_validated(&run.result, apply)
}

fn compare_validated<C, R>(
    runtime: &ValidatedRuntimeResult,
    apply: impl FnOnce(&mut GameState, C) -> R,
) -> Result<()>
where
    C: DeserializeOwned,
    R: DeserializeOwned + Debug + PartialEq,
{
    let mut actual = load_save_backed_state(runtime, "before")?;
    let case: C = runtime.capture("case")?;
    let expected = load_save_backed_state(runtime, "after")?;
    let expected_result: R = runtime.capture("result")?;

    let actual_result = apply(&mut actual, case);
    if actual_result != expected_result {
        bail!("operation result differs: C++ {expected_result:?}, Rust {actual_result:?}");
    }
    assert_game_state_eq(&expected, &actual)
}

fn load_save_backed_state(
    runtime: &ValidatedRuntimeResult,
    capture_name: &str,
) -> Result<GameState> {
    let capture: SaveBackedCapture = runtime.capture(capture_name)?;
    let artifact_dir = runtime
        .artifact_dir()
        .with_context(|| format!("resolving save-backed {capture_name} capture"))?;
    let save_path = artifact_dir.join(&capture.save);
    let bytes = fs::read(&save_path)
        .with_context(|| format!("reading save-backed capture {}", save_path.display()))?;
    let save = LegacySaveV62::parse(&bytes);
    let mut state = save.game_state(LegacyGameStateContext {
        crt_rand_state: capture.ephemeral.rng.crt_rand.state(),
        map_generation_lcg: capture.ephemeral.rng.map_generation.state(),
        zone_status_lcg: capture.ephemeral.rng.zone_status.state(),
        selected_nation: capture.ephemeral.turn.selected_nation,
    });

    state.apply_save_backed_ephemeral(
        capture.ephemeral.turn,
        capture.ephemeral.unit_ids,
        capture.ephemeral.rng,
        capture.ephemeral.news,
        capture.ephemeral.pending,
    );
    Ok(state)
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

fn run_native_case_result(
    case_name: &str,
    required_captures: &'static [&'static str],
) -> Result<RuntimeRun> {
    run_runtime_result(
        NATIVE_ORACLE,
        Some(case_name),
        EvidenceKind::RetailFixtureOracle,
        required_captures,
    )
}

/// Run one catalogued native runtime scenario into a unique output directory.
///
/// The returned run keeps that directory alive so save-backed artifacts remain
/// readable until the caller is finished.
pub fn run_retail_fixture_result(
    name: &str,
    required_captures: &'static [&'static str],
) -> Result<RuntimeRun> {
    run_runtime_result(
        name,
        None,
        EvidenceKind::RetailFixtureOracle,
        required_captures,
    )
}

/// Run a catalogued self-consistency scenario such as random-map generation.
pub fn run_self_consistency_result(
    name: &str,
    required_captures: &'static [&'static str],
) -> Result<RuntimeRun> {
    run_runtime_result(name, None, EvidenceKind::SelfConsistency, required_captures)
}

/// One native runtime invocation and the unique output directory it wrote.
pub struct RuntimeRun {
    result: ValidatedRuntimeResult,
    _output_dir: tempfile::TempDir,
}

impl RuntimeRun {
    pub fn capture<T: DeserializeOwned>(&self, name: &str) -> Result<T, RuntimeCaptureError> {
        self.result.capture(name)
    }

    pub fn artifact_dir(&self) -> Result<&Path, RuntimeCaptureError> {
        self.result.artifact_dir()
    }
}

fn run_runtime_result(
    scenario: &str,
    native_case: Option<&str>,
    evidence_kind: EvidenceKind,
    required_captures: &'static [&'static str],
) -> Result<RuntimeRun> {
    let output_dir = tempfile::Builder::new()
        .prefix("imperialism-runtime-")
        .tempdir()
        .context("creating a unique native result directory")?;
    let mut command = Command::new("just");
    command
        .current_dir(repository_root()?.join("decomp"))
        .args(["--quiet", "runtime-run", scenario, "--seed", "1"])
        .env("IMPERIALISM_RUNTIME_RESULT_DIR", output_dir.path());
    if let Some(case_name) = native_case {
        command.env(NATIVE_CASE_ENV, case_name);
    }

    let output = command.output().with_context(|| {
        if native_case.is_some() {
            "launching the native transition oracle".to_owned()
        } else {
            "launching native runtime scenario".to_owned()
        }
    })?;

    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        if let Some(case_name) = native_case {
            bail!("native transition case {case_name} failed:\n{detail}");
        }
        bail!("native scenario {scenario} failed:\n{detail}");
    }

    let result_path = output_dir.path().join(format!("{scenario}.json"));
    let result = read_runtime_result(
        &result_path,
        RuntimeResultExpectations {
            name: scenario,
            seed: 1,
            evidence_kind,
            required_captures,
        },
    )
    .with_context(|| {
        if native_case.is_some() {
            format!("reading native transition result {}", result_path.display())
        } else {
            format!("reading native runtime result {}", result_path.display())
        }
    })?;
    Ok(RuntimeRun {
        result,
        _output_dir: output_dir,
    })
}

fn repository_root() -> Result<&'static Path> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .context("could not locate the repository root")
}
