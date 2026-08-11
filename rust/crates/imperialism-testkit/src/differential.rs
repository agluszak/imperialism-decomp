//! Process-isolated native transition comparison.

use anyhow::{Context, Result, bail};
use imperialism_core::{
    AiDevelopmentPressureState, GameState, MAJOR_NATION_COUNT, NewsState, PendingWorkState,
    RngState, TurnState, UnitIdAllocator,
};
use imperialism_formats::{LegacyGameStateContext, LegacySaveV62};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::fmt::Debug;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::{
    EvidenceKind, RuntimeResultExpectations, ValidatedRuntimeResult, decode_runtime_result,
    first_serialized_difference,
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
    #[serde(default)]
    pending: Option<PendingWorkState>,
    #[serde(default)]
    ai_development_pressure: Option<Vec<Option<AiDevelopmentPressureState>>>,
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
    let mut actual = load_save_backed_state(&runtime, "before")?;
    let case: C = runtime.capture("case")?;
    let expected = load_save_backed_state(&runtime, "after")?;
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
    let save = LegacySaveV62::parse(&bytes)
        .with_context(|| format!("parsing save-backed capture {}", save_path.display()))?;
    let mut state = save
        .game_state(LegacyGameStateContext {
            crt_rand_state: capture.ephemeral.rng.crt_rand.state(),
            map_generation_lcg: capture.ephemeral.rng.map_generation.state(),
            zone_status_lcg: capture.ephemeral.rng.zone_status.state(),
            selected_nation: capture.ephemeral.turn.selected_nation,
        })
        .with_context(|| format!("projecting save-backed capture {}", save_path.display()))?;

    let pressures = match capture.ephemeral.ai_development_pressure {
        None => None,
        Some(pressures) => {
            if pressures.len() != MAJOR_NATION_COUNT {
                bail!(
                    "{capture_name} ai_development_pressure length {}, expected {MAJOR_NATION_COUNT}",
                    pressures.len()
                );
            }
            let mut fixed = [None; MAJOR_NATION_COUNT];
            for (slot, pressure) in pressures.into_iter().enumerate() {
                fixed[slot] = pressure;
            }
            Some(fixed)
        }
    };
    state.apply_save_backed_ephemeral(
        capture.ephemeral.turn,
        capture.ephemeral.unit_ids,
        capture.ephemeral.rng,
        capture.ephemeral.news,
        capture.ephemeral.pending,
        pressures,
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
) -> Result<ValidatedRuntimeResult> {
    run_runtime_result(NATIVE_ORACLE, Some(case_name), required_captures)
}

/// Run one catalogued native runtime scenario and decode the published result JSON from stdout.
pub fn run_retail_fixture_result(
    name: &str,
    required_captures: &'static [&'static str],
) -> Result<ValidatedRuntimeResult> {
    run_runtime_result(name, None, required_captures)
}

fn run_runtime_result(
    scenario: &str,
    native_case: Option<&str>,
    required_captures: &'static [&'static str],
) -> Result<ValidatedRuntimeResult> {
    let mut command = Command::new("just");
    command
        .current_dir(repository_root()?.join("decomp"))
        .args(["--quiet", "runtime-run", scenario, "--seed", "1"]);
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

    decode_runtime_result(
        output.stdout.as_slice(),
        RuntimeResultExpectations {
            name: scenario,
            seed: 1,
            evidence_kind: EvidenceKind::RetailFixtureOracle,
            required_captures,
        },
    )
    .with_context(|| {
        if native_case.is_some() {
            "decoding native transition oracle result".to_owned()
        } else {
            "decoding native runtime result".to_owned()
        }
    })
}

fn repository_root() -> Result<&'static Path> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .context("could not locate the repository root")
}
