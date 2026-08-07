#![forbid(unsafe_code)]

use imperialism_core::{CoarseMapGeneration, RetailLcg, generate_coarse_random_map};
pub use imperialism_formats::{
    GameSnapshotV1, SnapshotReadError, SnapshotValidationError, decode_game_snapshot,
    read_game_snapshot,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum GeneratedWorldReadError {
    #[error("could not read generated-world snapshot: {0}")]
    Io(#[source] std::io::Error),
    #[error("could not decode generated-world snapshot: {0}")]
    Json(#[source] serde_json::Error),
    #[error("result contains no generated-world snapshot")]
    MissingGeneratedWorld,
    #[error("generated-world snapshot contains no coarse-generation oracle")]
    MissingCoarseGeneration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedWorldCoarseOracle {
    pub initial_map_lcg: u32,
    pub attempt_count: usize,
    pub attempts: Vec<GeneratedWorldCoarseAttempt>,
    pub accepted_map_lcg: u32,
    pub accepted_grid: Vec<i32>,
    pub city_region_next_id: i32,
    pub city_region_ids: Vec<i32>,
    pub group_members: Vec<i32>,
    pub expanded_province_count: usize,
    pub expanded_tile_fields: Vec<String>,
    pub expanded_tiles: Vec<[i32; 3]>,
    pub expanded_provinces: Vec<[i32; 2]>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedWorldCoarseAttempt {
    pub index: usize,
    pub draw_count: u32,
    pub map_lcg_after_seeding: u32,
    pub pre_validation_grid: Vec<i32>,
    pub city_region_next_id: i32,
    pub city_region_ids: Vec<i32>,
    pub group_members: Vec<i32>,
    pub post_validation_grid: Vec<i32>,
    pub error_check_failed: i32,
    pub has_continuous_ocean_column: i32,
    pub frontier_mask_complete: i32,
    pub accepted: i32,
    pub map_lcg_after_validation: u32,
}

pub fn read_generated_world_coarse(
    path: &Path,
) -> Result<GeneratedWorldCoarseOracle, GeneratedWorldReadError> {
    let file = File::open(path).map_err(GeneratedWorldReadError::Io)?;
    decode_generated_world_coarse(file)
}

pub fn decode_generated_world_coarse(
    reader: impl Read,
) -> Result<GeneratedWorldCoarseOracle, GeneratedWorldReadError> {
    let value: serde_json::Value =
        serde_json::from_reader(reader).map_err(GeneratedWorldReadError::Json)?;
    let world = if value.get("schema").is_some() {
        value
    } else {
        value
            .get("generated_world")
            .cloned()
            .filter(|snapshot| !snapshot.is_null())
            .ok_or(GeneratedWorldReadError::MissingGeneratedWorld)?
    };
    let coarse = world
        .get("coarse_generation")
        .cloned()
        .ok_or(GeneratedWorldReadError::MissingCoarseGeneration)?;
    serde_json::from_value(coarse).map_err(GeneratedWorldReadError::Json)
}

pub fn generate_and_compare_coarse_oracle(
    oracle: &GeneratedWorldCoarseOracle,
) -> Result<CoarseMapGeneration, SnapshotDifference> {
    let mut rng = RetailLcg::from_state(oracle.initial_map_lcg);
    let actual = generate_coarse_random_map(&mut rng);
    if let Some(difference) = coarse_oracle_difference(oracle, &actual) {
        Err(difference)
    } else {
        Ok(actual)
    }
}

pub fn coarse_oracle_difference(
    oracle: &GeneratedWorldCoarseOracle,
    actual: &CoarseMapGeneration,
) -> Option<SnapshotDifference> {
    let expected = serde_json::to_value(oracle).expect("oracle serialization cannot fail");
    let attempts = actual
        .attempts
        .iter()
        .enumerate()
        .map(|(index, attempt)| {
            serde_json::json!({
                "index": index,
                "draw_count": attempt.draw_count,
                "map_lcg_after_seeding": attempt.map_lcg_after_seeding,
                "pre_validation_grid": attempt.pre_validation_grid.flattened().map(i32::from).collect::<Vec<_>>(),
                "city_region_next_id": attempt.city_region_next_id,
                "city_region_ids": attempt.city_region_ids,
                "group_members": attempt.group_members.iter().flatten().copied().collect::<Vec<_>>(),
                "post_validation_grid": attempt.post_validation_grid.flattened().map(i32::from).collect::<Vec<_>>(),
                "error_check_failed": i32::from(attempt.error_check_failed),
                "has_continuous_ocean_column": option_bool_code(attempt.has_continuous_ocean_column),
                "frontier_mask_complete": option_bool_code(attempt.frontier_mask_complete),
                "accepted": i32::from(attempt.accepted),
                "map_lcg_after_validation": attempt.map_lcg_after_validation,
            })
        })
        .collect::<Vec<_>>();
    let actual = serde_json::json!({
        "initial_map_lcg": actual.initial_map_lcg,
        "attempt_count": actual.attempts.len(),
        "attempts": attempts,
        "accepted_map_lcg": actual.accepted_map_lcg,
        "accepted_grid": actual.accepted_grid.flattened().map(i32::from).collect::<Vec<_>>(),
        "city_region_next_id": actual.city_region_next_id,
        "city_region_ids": actual.city_region_ids,
        "group_members": actual.group_members.iter().flatten().copied().collect::<Vec<_>>(),
        "expanded_province_count": actual.expanded_provinces.len(),
        "expanded_tile_fields": ["terrain_kind", "owner_nation", "province_index"],
        "expanded_tiles": actual.expanded_tiles.iter().map(|tile| [
            i32::from(tile.terrain_kind), i32::from(tile.owner_nation), i32::from(tile.province_index)
        ]).collect::<Vec<_>>(),
        "expanded_provinces": actual.expanded_provinces.iter().map(|province| [
            i32::from(province.owner_nation), i32::from(province.region_class)
        ]).collect::<Vec<_>>(),
    });
    difference_at(
        "coarse_generation".to_owned(),
        Some(&expected),
        Some(&actual),
    )
}

fn option_bool_code(value: Option<bool>) -> i32 {
    value.map_or(-1, i32::from)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotDifference {
    pub path: String,
    pub original: Option<serde_json::Value>,
    pub reimplementation: Option<serde_json::Value>,
}

pub fn first_snapshot_difference(
    original: &GameSnapshotV1,
    reimplementation: &GameSnapshotV1,
) -> Result<Option<SnapshotDifference>, serde_json::Error> {
    for (name, original_section, reimplementation_section) in [
        (
            "metadata",
            serde_json::to_value(&original.metadata)?,
            serde_json::to_value(&reimplementation.metadata)?,
        ),
        (
            "rng",
            serde_json::to_value(&original.rng)?,
            serde_json::to_value(&reimplementation.rng)?,
        ),
        (
            "world",
            serde_json::to_value(&original.world)?,
            serde_json::to_value(&reimplementation.world)?,
        ),
        (
            "nations",
            serde_json::to_value(&original.nations)?,
            serde_json::to_value(&reimplementation.nations)?,
        ),
        (
            "economy",
            serde_json::to_value(&original.economy)?,
            serde_json::to_value(&reimplementation.economy)?,
        ),
        (
            "military",
            serde_json::to_value(&original.military)?,
            serde_json::to_value(&reimplementation.military)?,
        ),
        (
            "missions",
            serde_json::to_value(&original.missions)?,
            serde_json::to_value(&reimplementation.missions)?,
        ),
        (
            "pending",
            serde_json::to_value(&original.pending)?,
            serde_json::to_value(&reimplementation.pending)?,
        ),
    ] {
        if let Some(difference) = difference_at(
            name.to_owned(),
            Some(&original_section),
            Some(&reimplementation_section),
        ) {
            return Ok(Some(difference));
        }
    }
    Ok(None)
}

fn difference_at(
    path: String,
    original: Option<&serde_json::Value>,
    reimplementation: Option<&serde_json::Value>,
) -> Option<SnapshotDifference> {
    if original == reimplementation {
        return None;
    }
    match (original, reimplementation) {
        (Some(serde_json::Value::Object(left)), Some(serde_json::Value::Object(right))) => {
            let keys = left
                .keys()
                .chain(right.keys())
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            keys.into_iter().find_map(|key| {
                difference_at(format!("{path}.{key}"), left.get(key), right.get(key))
            })
        }
        (Some(serde_json::Value::Array(left)), Some(serde_json::Value::Array(right))) => {
            (0..left.len().max(right.len())).find_map(|index| {
                difference_at(
                    format!("{path}[{index}]"),
                    left.get(index),
                    right.get(index),
                )
            })
        }
        _ => Some(SnapshotDifference {
            path,
            original: original.cloned(),
            reimplementation: reimplementation.cloned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn snapshot() -> GameSnapshotV1 {
        let mut snapshot: GameSnapshotV1 = serde_json::from_value(json!({
            "schema": "imperialism.game_snapshot.v1",
            "sections": [
                "metadata", "rng", "world", "nations", "economy", "military",
                "missions", "pending"
            ],
            "hashes": {
                "metadata": "00000000", "rng": "00000000", "world": "00000000",
                "nations": "00000000", "economy": "00000000", "military": "00000000",
                "missions": "00000000", "pending": "00000000", "state": "00000000"
            },
            "metadata": {
                "scenario_map_index_plus_one": 0, "economic_turn": 1, "turn_state": 5,
                "difficulty": 1, "active_nation": 6, "selected_nation": 6,
                "persistent_unit_id_counter": 0
            },
            "rng": {
                "runtime_seed": 1, "crt_rand_state": 1, "map_generation_lcg": 1,
                "zone_status_lcg": 1
            },
            "world": {
                "width": 108, "height": 60, "wraps_horizontally": true,
                "tiles": vec![[0; 10]; 6480]
            },
            "nations": {"records": (0..23).map(|slot| json!({
                "slot": slot,
                "kind": if slot < 7 { "major" } else { "minor" },
                "present": false
            })).collect::<Vec<_>>()},
            "economy": {"cities": (0..7).map(|nation| json!({
                "nation": nation, "present": false
            })).collect::<Vec<_>>()},
            "military": {"units": [], "civilians": [], "ships": [], "task_forces": []},
            "missions": {"records": []},
            "pending": {
                "turn_flow_status_flags": 0,
                "nations": (0..7).map(|nation| json!({
                    "nation": nation, "turn_events": [], "proposals": [],
                    "turn_summary": [], "turn_start_events": []
                })).collect::<Vec<_>>(),
                "war_transitions": []
            }
        }))
        .unwrap();
        snapshot.refresh_hashes().unwrap();
        snapshot
    }

    #[test]
    fn reports_the_first_structural_path() {
        let original = json!({"cities": [{"stock": [2, 4, 6]}]});
        let reimplementation = json!({"cities": [{"stock": [2, 5, 6]}]});
        let difference = difference_at(
            "economy".to_owned(),
            Some(&original),
            Some(&reimplementation),
        )
        .unwrap();
        assert_eq!(difference.path, "economy.cities[0].stock[1]");
        assert_eq!(difference.original, Some(json!(4)));
        assert_eq!(difference.reimplementation, Some(json!(5)));
    }

    #[test]
    fn accepts_equal_semantic_snapshots() {
        let snapshot = snapshot();
        assert_eq!(
            first_snapshot_difference(&snapshot, &snapshot).unwrap(),
            None
        );
    }

    #[test]
    fn reports_unequal_semantic_snapshots() {
        let original = snapshot();
        let mut reimplementation = original.clone();
        reimplementation.pending.turn_flow_status_flags = 0x40;
        let difference = first_snapshot_difference(&original, &reimplementation)
            .unwrap()
            .unwrap();
        assert_eq!(difference.path, "pending.turn_flow_status_flags");
    }

    #[test]
    fn rejects_malformed_and_incompatible_snapshots() {
        assert!(matches!(
            decode_game_snapshot(&b"{"[..]),
            Err(SnapshotReadError::Json(_))
        ));
        let mut incompatible = snapshot();
        incompatible.schema = "imperialism.game_snapshot.v2".to_owned();
        assert!(matches!(
            incompatible.verify_hashes(),
            Err(SnapshotValidationError::Schema(_))
        ));
    }
}
