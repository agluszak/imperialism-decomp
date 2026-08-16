//! Process-isolated native transition comparison.

use anyhow::{Context, Result, bail};
use imperialism_core::{
    GameState, NewsState, PendingWorkState, RngState, TurnContinuation, TurnState, UnitIdAllocator,
};
use imperialism_formats::{LegacyGameStateContext, LegacySaveV62};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use std::fmt::Debug;
use std::fs;
use std::path::Path;
use std::process::Command;

use crate::first_serialized_difference;
use crate::runtime_capture::repository_root;

const NATIVE_ORACLE_JUST: &str = "native-oracle";

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
    #[serde(default)]
    continuation: TurnContinuation,
}

/// Save bytes plus the runtime-only overlay the `.imp` does not store.
pub struct SaveBackedState {
    save: Vec<u8>,
    ephemeral: EphemeralGameState,
}

/// One native transition: prepared before/after saves, case arguments, and result.
pub struct NativeCaptures<C, R> {
    pub before: SaveBackedState,
    pub case: C,
    pub result: R,
    pub after: SaveBackedState,
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
    let native = run_native(case_name)?;
    let mut actual = load_save_backed_state(native.before)?;
    let expected = load_save_backed_state(native.after)?;
    let result = apply(&mut actual, native.case);
    if result != native.result {
        bail!(
            "operation result differs: C++ {:?}, Rust {result:?}",
            native.result
        );
    }
    assert_game_state_eq(&expected, &actual)
}

pub fn run_native<C, R>(case_name: &str) -> Result<NativeCaptures<C, R>>
where
    C: DeserializeOwned,
    R: DeserializeOwned,
{
    let output_dir = tempfile::Builder::new()
        .prefix("imperialism-native-")
        .tempdir()
        .context("creating a unique native result directory")?;
    let output = Command::new("just")
        .current_dir(repository_root()?.join("decomp"))
        .args(["--quiet", NATIVE_ORACLE_JUST, case_name, "--seed", "1"])
        .env("IMPERIALISM_RUNTIME_RESULT_DIR", output_dir.path())
        .output()
        .context("launching the native transition oracle")?;
    if !output.status.success() {
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        bail!("native transition case {case_name} failed:\n{detail}");
    }

    let result_path = output_dir.path().join("result.json");
    let result_json: serde_json::Value = serde_json::from_slice(
        &fs::read(&result_path)
            .with_context(|| format!("reading native result {}", result_path.display()))?,
    )
    .with_context(|| format!("parsing native result {}", result_path.display()))?;
    let status = result_json.get("status").and_then(|value| value.as_str());
    if status != Some("passed") {
        bail!(
            "native transition case {case_name} status {}",
            status.unwrap_or("missing")
        );
    }

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

    Ok(NativeCaptures {
        before: read_save_backed_capture(output_dir.path(), &captures, "before")?,
        case: read_capture(&captures, "case")?,
        result: read_capture(&captures, "result")?,
        after: read_save_backed_capture(output_dir.path(), &captures, "after")?,
    })
}

pub fn load_save_backed_state(capture: SaveBackedState) -> Result<GameState> {
    let save = LegacySaveV62::parse(&capture.save);
    let mut parts = save.game_state_parts(LegacyGameStateContext {
        crt_rand_state: capture.ephemeral.rng.crt_rand.state(),
        map_generation_lcg: capture.ephemeral.rng.map_generation.state(),
        zone_status_lcg: capture.ephemeral.rng.zone_status.state(),
        selected_nation: capture.ephemeral.turn.selected_nation,
    });
    parts.turn = capture.ephemeral.turn;
    parts.unit_ids = capture.ephemeral.unit_ids;
    parts.rng = capture.ephemeral.rng;
    parts.news = capture.ephemeral.news;
    parts.pending = capture.ephemeral.pending;
    parts.continuation = capture.ephemeral.continuation;
    Ok(GameState::from_parts(parts))
}

pub fn assert_game_state_eq(expected: &GameState, actual: &GameState) -> Result<()> {
    if expected == actual {
        return Ok(());
    }
    match first_serialized_difference(expected, actual).context("comparing game states")? {
        None => bail!("game states differ only in non-serialized state"),
        Some(difference) => bail!(
            "{} differs: expected {:?}, actual {:?}",
            difference.path,
            difference.original,
            difference.reimplementation
        ),
    }
}

fn read_capture<T: DeserializeOwned>(captures: &serde_json::Value, name: &str) -> Result<T> {
    let value = captures
        .get(name)
        .with_context(|| format!("native captures.json is missing {name}"))?;
    serde_json::from_value(value.clone()).with_context(|| format!("decoding native {name} capture"))
}

fn read_save_backed_capture(
    run_dir: &Path,
    captures: &serde_json::Value,
    name: &str,
) -> Result<SaveBackedState> {
    let capture: SaveBackedCapture = read_capture(captures, name)?;
    let save_path = run_dir.join(&capture.save);
    let save = fs::read(&save_path)
        .with_context(|| format!("reading save-backed capture {}", save_path.display()))?;
    Ok(SaveBackedState {
        save,
        ephemeral: capture.ephemeral,
    })
}
