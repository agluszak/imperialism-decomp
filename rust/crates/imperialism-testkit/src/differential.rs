//! Process-isolated native transition comparison.

use anyhow::{Context, Result, bail};
use imperialism_core::{
    Difficulty, GameState, MajorNationId, NationId, NewsState, PendingWorkState, PhaseCode,
    RngState, ScenarioMapId, TurnFlow, TurnState, UnitIdAllocator,
};
use imperialism_formats::{LegacyGameStateContext, LegacySaveV62};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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
    turn: NativeTurnState,
    unit_ids: UnitIdAllocator,
    rng: RngState,
    news: NewsState,
    pending: PendingWorkState,
    #[serde(default)]
    last_processed_nation: Option<MajorNationId>,
}

#[derive(Debug, Deserialize)]
struct NativeTurnState {
    scenario_map: Option<ScenarioMapId>,
    economic_turn: i32,
    diplomacy_year_term_raw: i16,
    phase: PhaseCode,
    turn_flow_status_flags: u32,
    quarter_gate_by_decade: [u8; 10],
    difficulty: Difficulty,
    active_nation: NationId,
    last_turn_alert_tick: i32,
}

impl NativeTurnState {
    fn into_core(self) -> TurnState {
        let mut phase_state_by_decade = [0; 12];
        phase_state_by_decade[..10].copy_from_slice(&self.quarter_gate_by_decade);
        let mut turn = TurnState::new(
            self.scenario_map,
            self.economic_turn,
            self.diplomacy_year_term_raw,
            0,
            self.turn_flow_status_flags,
            phase_state_by_decade,
            self.difficulty,
            self.active_nation,
        );
        turn.last_turn_alert_tick = self.last_turn_alert_tick;
        turn
    }
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
    let native_phase = capture.ephemeral.turn.phase;
    let save = LegacySaveV62::parse(&capture.save);
    let mut parts = save.game_state_parts(LegacyGameStateContext {
        crt_rand_state: capture.ephemeral.rng.crt_rand.state(),
        map_generation_lcg: capture.ephemeral.rng.map_generation.state(),
        zone_status_lcg: capture.ephemeral.rng.zone_status.state(),
    });
    parts.turn = capture.ephemeral.turn.into_core();
    parts.turn_flow = TurnFlow::from_retail_phase(native_phase);
    parts.unit_ids = capture.ephemeral.unit_ids;
    parts.rng = capture.ephemeral.rng;
    parts.news = capture.ephemeral.news;
    parts.pending = capture.ephemeral.pending;
    parts.diplomacy.last_processed_nation = capture.ephemeral.last_processed_nation;
    Ok(GameState::from_parts(parts))
}

pub fn assert_game_state_eq(expected: &GameState, actual: &GameState) -> Result<()> {
    // `turnStateCode` is all the oracle can report, and it names the phase retail already
    // advanced to rather than the interrupt the turn stopped at. Compare that projection;
    // the flow behind it has no counterpart in the capture.
    if expected.phase() != actual.phase() {
        bail!(
            "turn phase differs: C++ {:?}, Rust {:?}",
            expected.phase(),
            actual.phase()
        );
    }
    let mut expected_json =
        serde_json::to_value(expected).context("serializing native game state")?;
    let mut actual_json = serde_json::to_value(actual).context("serializing Rust game state")?;
    discard_process_local_allocator_state(&mut expected_json, expected);
    discard_process_local_allocator_state(&mut actual_json, actual);
    match first_serialized_difference(&expected_json, &actual_json)
        .context("comparing game states")?
    {
        None => Ok(()),
        Some(difference) => bail!(
            "{} differs: expected {:?}, actual {:?}",
            difference.path,
            difference.original,
            difference.reimplementation
        ),
    }
}

fn discard_process_local_allocator_state(state: &mut serde_json::Value, game: &GameState) {
    let state = state
        .as_object_mut()
        .expect("GameState serializes as an object");
    state.remove("object_ids");
    state.remove("turn_flow");
    discard_uncalculated_new_town_adjacent_city(state);

    // Retail saves these ordered lists but not their object pointers. Loader-assigned numeric
    // keys therefore depend on how many other pointer-like objects the capture contains; list
    // order, contents, and relationships are the complete persisted semantics.
    let mut ship_ordinals = HashMap::new();
    let ships = game
        .ships()
        .enumerate()
        .map(|(ordinal, (id, ship))| {
            let id = serialized_id(id, "ship");
            ship_ordinals.insert(id, ordinal as u64);
            serde_json::to_value(ship).expect("ship serializes")
        })
        .collect();
    state.insert("ships".to_owned(), serde_json::Value::Array(ships));

    let admirals = game
        .admirals()
        .map(|(_, admiral)| {
            let mut admiral = serde_json::to_value(admiral).expect("admiral serializes");
            replace_ship_ids(&mut admiral, &ship_ordinals);
            admiral
        })
        .collect();
    state.insert("admirals".to_owned(), serde_json::Value::Array(admirals));

    let mut task_force_ordinals = HashMap::new();
    let task_forces = game
        .task_forces()
        .enumerate()
        .map(|(ordinal, (id, force))| {
            let id = serialized_id(id, "task-force");
            task_force_ordinals.insert(id, ordinal as u64);
            let mut force = serde_json::to_value(force).expect("task force serializes");
            replace_ship_ids(&mut force, &ship_ordinals);
            force
        })
        .collect();
    state.insert(
        "task_forces".to_owned(),
        serde_json::Value::Array(task_forces),
    );

    let missions = game
        .missions()
        .map(|(_, mission)| {
            let mut mission = serde_json::to_value(mission).expect("mission serializes");
            replace_ship_ids(&mut mission, &ship_ordinals);
            replace_task_force_ids(&mut mission, &task_force_ordinals);
            mission
        })
        .collect();
    state.insert("missions".to_owned(), serde_json::Value::Array(missions));
}

fn discard_uncalculated_new_town_adjacent_city(
    state: &mut serde_json::Map<String, serde_json::Value>,
) {
    let Some(serde_json::Value::Object(majors)) = state
        .get_mut("nations")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|nations| nations.get_mut("majors"))
    else {
        return;
    };
    for major in majors.values_mut() {
        let Some(towns) = major
            .get_mut("towns")
            .and_then(serde_json::Value::as_object_mut)
        else {
            continue;
        };
        for town in towns.values_mut() {
            let Some(town) = town.as_object_mut() else {
                continue;
            };
            let constructed_after_start = town
                .get("created_turn")
                .and_then(serde_json::Value::as_i64)
                .is_some_and(|created| created > 0);
            let resources_uncalculated = town
                .get("resource_yield_by_type")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|yields| yields.values().all(|amount| amount.as_i64() == Some(0)));
            if constructed_after_start && resources_uncalculated {
                // `TTown::ITown` does not initialize this byte. A town built during the
                // turn retains allocator noise until `CalculateRawResources` or
                // `CalculateResources` populates its still-zero yield table and this flag.
                town.remove("has_adjacent_city");
            }
        }
    }
}

fn serialized_id(id: impl Serialize, kind: &str) -> u64 {
    serde_json::to_value(id)
        .unwrap_or_else(|_| panic!("{kind} id serializes"))
        .as_u64()
        .unwrap_or_else(|| panic!("{kind} id serializes as an integer"))
}

fn replace_ship_ids(value: &mut serde_json::Value, ordinals: &HashMap<u64, u64>) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                replace_ship_ids(value, ordinals);
            }
        }
        serde_json::Value::Object(object) => {
            for field in ["ship", "selected_ship", "flagship"] {
                if let Some(ship) = object.get_mut(field)
                    && let Some(id) = ship.as_u64()
                    && let Some(&ordinal) = ordinals.get(&id)
                {
                    *ship = serde_json::Value::from(ordinal);
                }
            }
            if let Some(serde_json::Value::Object(ships)) = object.get_mut("ships") {
                let mut canonical = serde_json::Map::new();
                for (id, selected) in std::mem::take(ships) {
                    let id = id
                        .parse::<u64>()
                        .ok()
                        .and_then(|id| ordinals.get(&id).copied())
                        .map_or(id, |ordinal| ordinal.to_string());
                    canonical.insert(id, selected);
                }
                *ships = canonical;
            }
            for value in object.values_mut() {
                replace_ship_ids(value, ordinals);
            }
        }
        _ => {}
    }
}

fn replace_task_force_ids(value: &mut serde_json::Value, ordinals: &HashMap<u64, u64>) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                replace_task_force_ids(value, ordinals);
            }
        }
        serde_json::Value::Object(object) => {
            if let Some(task_force) = object.get_mut("task_force")
                && let Some(id) = task_force.as_u64()
                && let Some(&ordinal) = ordinals.get(&id)
            {
                *task_force = serde_json::Value::from(ordinal);
            }
            for value in object.values_mut() {
                replace_task_force_ids(value, ordinals);
            }
        }
        _ => {}
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
    let published_path = run_dir.join(&capture.save);
    let runtime_path = run_dir
        .join("game")
        .join("Save")
        .join(format!("rt_native_{name}.imp"));
    let save_path = if published_path.is_file() {
        published_path
    } else {
        runtime_path
    };
    let save = fs::read(&save_path)
        .with_context(|| format!("reading save-backed capture {}", save_path.display()))?;
    Ok(SaveBackedState {
        save,
        ephemeral: capture.ephemeral,
    })
}

pub(crate) fn load_save_backed_capture(
    run_dir: &Path,
    captures: &serde_json::Value,
    name: &str,
) -> Result<GameState> {
    load_save_backed_state(read_save_backed_capture(run_dir, captures, name)?)
}
