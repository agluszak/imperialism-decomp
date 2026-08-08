#![forbid(unsafe_code)]

use imperialism_core::{
    CoarseMapGeneration, GameState, RandomMapTerrainGeneration, RandomMapTuning, RetailLcg,
    RetailTopologyByte, generate_coarse_random_map, generate_random_map_terrain,
};
pub use imperialism_formats::RuntimeCaptureError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;

const TERRAIN_TILE_FIELDS: [&str; 5] = [
    "terrain_kind",
    "river_sprite_code",
    "owner_nation",
    "gate_flag",
    "province_index",
];

#[derive(Debug, thiserror::Error)]
pub enum TerrainOracleReadError {
    #[error("could not read generated-world oracle: {0}")]
    Io(#[source] std::io::Error),
    #[error("could not decode generated-world oracle: {0}")]
    Json(#[source] serde_json::Error),
    #[error("runtime result contains no generated-world oracle")]
    MissingGeneratedWorld,
    #[error("generated-world oracle contains no terrain-generation evidence")]
    MissingTerrainGeneration,
    #[error("invalid terrain-generation oracle: {0}")]
    InvalidTerrainGeneration(String),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedWorldTerrainOracle {
    pub scenario_tag: String,
    pub initial_map_lcg: u32,
    pub terrain_generation: GeneratedWorldTerrainGeneration,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedWorldTerrainGeneration {
    pub topology_byte: i8,
    pub tuning: RandomMapTuning,
    pub attempt_count: usize,
    pub attempts: Vec<GeneratedWorldTerrainAttempt>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedWorldTerrainAttempt {
    pub index: usize,
    pub map_lcg_after_expansion: u32,
    pub after_expansion: GeneratedWorldTerrainStage,
    pub after_templates: GeneratedWorldTerrainStage,
    pub after_features: GeneratedWorldTerrainStage,
    pub after_rotation: GeneratedWorldTerrainStage,
    pub after_water_regions: GeneratedWorldTerrainStage,
    pub after_keyword: GeneratedWorldTerrainStage,
    pub accepted: i32,
    pub map_lcg_after_validation: u32,
    pub rotation_column: usize,
    pub seed_candidate_tiles: [i32; 23],
    pub tile_fields: Vec<String>,
    pub tiles: Vec<[i32; 5]>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeneratedWorldTerrainStage {
    pub map_lcg: u32,
    pub tile_hash: u32,
    pub terrain_counts: [u32; 8],
    pub river_tile_count: u32,
}

pub fn read_generated_world_terrain(
    path: &Path,
) -> Result<GeneratedWorldTerrainOracle, TerrainOracleReadError> {
    let file = File::open(path).map_err(TerrainOracleReadError::Io)?;
    decode_generated_world_terrain(file)
}

pub fn decode_generated_world_terrain(
    reader: impl Read,
) -> Result<GeneratedWorldTerrainOracle, TerrainOracleReadError> {
    let value: serde_json::Value =
        serde_json::from_reader(reader).map_err(TerrainOracleReadError::Json)?;
    let world = value
        .get("generated_world")
        .cloned()
        .filter(|snapshot| !snapshot.is_null())
        .ok_or(TerrainOracleReadError::MissingGeneratedWorld)?;
    let scenario_tag = world
        .pointer("/map/scenario_tag")
        .and_then(serde_json::Value::as_str)
        .ok_or(TerrainOracleReadError::MissingTerrainGeneration)?
        .to_owned();
    let initial_map_lcg = world
        .pointer("/coarse_generation/initial_map_lcg")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or(TerrainOracleReadError::MissingTerrainGeneration)?;
    let terrain_generation = world
        .get("terrain_generation")
        .cloned()
        .ok_or(TerrainOracleReadError::MissingTerrainGeneration)
        .and_then(|value| serde_json::from_value(value).map_err(TerrainOracleReadError::Json))?;
    validate_generated_world_terrain_shape(&terrain_generation)?;
    Ok(GeneratedWorldTerrainOracle {
        scenario_tag,
        initial_map_lcg,
        terrain_generation,
    })
}

fn validate_generated_world_terrain_shape(
    generation: &GeneratedWorldTerrainGeneration,
) -> Result<(), TerrainOracleReadError> {
    if generation.attempt_count == 0 || generation.attempt_count != generation.attempts.len() {
        return Err(TerrainOracleReadError::InvalidTerrainGeneration(
            "attempt_count must match a nonempty attempts array".to_owned(),
        ));
    }
    for (index, attempt) in generation.attempts.iter().enumerate() {
        if attempt.index != index {
            return Err(TerrainOracleReadError::InvalidTerrainGeneration(
                "attempt indices must be contiguous".to_owned(),
            ));
        }
        if attempt.map_lcg_after_expansion != attempt.after_expansion.map_lcg {
            return Err(TerrainOracleReadError::InvalidTerrainGeneration(
                "expansion RNG fields disagree".to_owned(),
            ));
        }
        if attempt.rotation_column >= 108 {
            return Err(TerrainOracleReadError::InvalidTerrainGeneration(
                "rotation column is outside the retail map".to_owned(),
            ));
        }
        if !(0..=1).contains(&attempt.accepted) {
            return Err(TerrainOracleReadError::InvalidTerrainGeneration(
                "accepted must be zero or one".to_owned(),
            ));
        }
        if attempt
            .tile_fields
            .iter()
            .map(String::as_str)
            .ne(TERRAIN_TILE_FIELDS)
        {
            return Err(TerrainOracleReadError::InvalidTerrainGeneration(
                "tile_fields do not match the terrain oracle".to_owned(),
            ));
        }
        if attempt.tiles.len() != 108 * 60 {
            return Err(TerrainOracleReadError::InvalidTerrainGeneration(
                "tiles must contain the 108x60 map".to_owned(),
            ));
        }
    }
    if !generation
        .attempts
        .last()
        .is_some_and(|attempt| attempt.accepted != 0)
        || generation
            .attempts
            .iter()
            .take(generation.attempts.len() - 1)
            .any(|attempt| attempt.accepted != 0)
    {
        return Err(TerrainOracleReadError::InvalidTerrainGeneration(
            "only the final terrain attempt may be accepted".to_owned(),
        ));
    }
    Ok(())
}

pub fn generate_and_compare_terrain_oracle(
    oracle: &GeneratedWorldTerrainOracle,
) -> Result<RandomMapTerrainGeneration, Difference> {
    let mut rng = RetailLcg::from_state(oracle.initial_map_lcg);
    let actual = generate_random_map_terrain(
        oracle.scenario_tag.as_bytes(),
        RetailTopologyByte::from_retail_byte(oracle.terrain_generation.topology_byte as u8),
        &mut rng,
    );
    if let Some(difference) = terrain_oracle_difference(oracle, &actual) {
        Err(difference)
    } else {
        Ok(actual)
    }
}

pub fn terrain_oracle_difference(
    oracle: &GeneratedWorldTerrainOracle,
    actual: &RandomMapTerrainGeneration,
) -> Option<Difference> {
    let expected_header = serde_json::json!({
        "tuning": oracle.terrain_generation.tuning,
        "attempt_count": oracle.terrain_generation.attempt_count,
        "attempt_record_count": oracle.terrain_generation.attempts.len(),
    });
    let actual_header = serde_json::json!({
        "tuning": actual.tuning,
        "attempt_count": actual.attempts.len(),
        "attempt_record_count": actual.attempts.len(),
    });
    if let Some(difference) = difference_at(
        "terrain_generation".to_owned(),
        Some(&expected_header),
        Some(&actual_header),
    ) {
        return Some(difference);
    }
    for (index, (expected, actual)) in oracle
        .terrain_generation
        .attempts
        .iter()
        .zip(&actual.attempts)
        .enumerate()
    {
        let expected_stages = serde_json::json!({
            "index": expected.index,
            "map_lcg_after_expansion": expected.map_lcg_after_expansion,
            "after_expansion": expected.after_expansion,
            "after_templates": expected.after_templates,
            "after_features": expected.after_features,
            "after_rotation": expected.after_rotation,
            "after_water_regions": expected.after_water_regions,
            "after_keyword": expected.after_keyword,
            "accepted": expected.accepted,
            "map_lcg_after_validation": expected.map_lcg_after_validation,
            "rotation_column": expected.rotation_column,
            "seed_candidate_tiles": expected.seed_candidate_tiles,
            "tile_fields": expected.tile_fields,
            "tile_count": expected.tiles.len(),
        });
        let actual_stages = serde_json::json!({
            "index": index,
            "map_lcg_after_expansion": actual.after_expansion.map_lcg,
            "after_expansion": actual.after_expansion,
            "after_templates": actual.after_templates,
            "after_features": actual.after_features,
            "after_rotation": actual.after_rotation,
            "after_water_regions": actual.after_water_regions,
            "after_keyword": actual.after_keyword,
            "accepted": i32::from(actual.accepted),
            "map_lcg_after_validation": actual.map_lcg_after_validation,
            "rotation_column": actual.rotation_column,
            "seed_candidate_tiles": actual.seed_candidate_tiles,
            "tile_fields": TERRAIN_TILE_FIELDS,
            "tile_count": actual.tiles.len(),
        });
        if let Some(difference) = difference_at(
            format!("terrain_generation.attempts[{index}]"),
            Some(&expected_stages),
            Some(&actual_stages),
        ) {
            return Some(difference);
        }
        for (tile_index, (expected_tile, actual_tile)) in
            expected.tiles.iter().zip(&actual.tiles).enumerate()
        {
            let actual_values = [
                i32::from(actual_tile.terrain_kind),
                i32::from(actual_tile.river_sprite_code),
                i32::from(actual_tile.owner_nation),
                i32::from(actual_tile.gate_flag),
                i32::from(actual_tile.province_index),
            ];
            for field in [0, 1, 3]
                .into_iter()
                .chain((actual_tile.terrain_kind != 5).then_some(2))
                .chain((actual_tile.terrain_kind != 5).then_some(4))
            {
                if expected_tile[field] != actual_values[field] {
                    return Some(Difference {
                        path: format!(
                            "terrain_generation.attempts[{index}].tiles[{tile_index}][{field}]"
                        ),
                        original: Some(serde_json::json!(expected_tile[field])),
                        reimplementation: Some(serde_json::json!(actual_values[field])),
                    });
                }
            }
        }
    }
    None
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Difference {
    pub path: String,
    pub original: Option<serde_json::Value>,
    pub reimplementation: Option<serde_json::Value>,
}

pub fn read_game_state(path: impl AsRef<Path>) -> Result<GameState, RuntimeCaptureError> {
    imperialism_formats::read_runtime_capture(path, "game_state")
}

pub fn read_coarse_map_generation(
    path: impl AsRef<Path>,
) -> Result<CoarseMapGeneration, RuntimeCaptureError> {
    imperialism_formats::read_runtime_capture(path, "coarse_map_generation")
}

pub fn generate_and_compare_coarse_capture(
    expected: &CoarseMapGeneration,
) -> Result<CoarseMapGeneration, Difference> {
    let mut rng = RetailLcg::from_state(expected.initial_map_lcg);
    let actual = generate_coarse_random_map(&mut rng);
    match first_serialized_difference(expected, &actual) {
        Ok(None) => Ok(actual),
        Ok(Some(difference)) => Err(difference),
        Err(error) => unreachable!("semantic state serialization failed: {error}"),
    }
}

pub fn first_serialized_difference<T: Serialize>(
    original: &T,
    reimplementation: &T,
) -> Result<Option<Difference>, serde_json::Error> {
    let original = serde_json::to_value(original)?;
    let reimplementation = serde_json::to_value(reimplementation)?;
    Ok(difference_at(
        String::new(),
        Some(&original),
        Some(&reimplementation),
    ))
}

fn difference_at(
    path: String,
    original: Option<&serde_json::Value>,
    reimplementation: Option<&serde_json::Value>,
) -> Option<Difference> {
    if original == reimplementation {
        return None;
    }
    match (original, reimplementation) {
        (Some(serde_json::Value::Object(left)), Some(serde_json::Value::Object(right))) => left
            .keys()
            .chain(right.keys())
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .find_map(|key| {
                let child = if path.is_empty() {
                    key.to_owned()
                } else {
                    format!("{path}.{key}")
                };
                difference_at(child, left.get(key), right.get(key))
            }),
        (Some(serde_json::Value::Array(left)), Some(serde_json::Value::Array(right))) => {
            (0..left.len().max(right.len())).find_map(|index| {
                difference_at(
                    format!("{path}[{index}]"),
                    left.get(index),
                    right.get(index),
                )
            })
        }
        _ => Some(Difference {
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

    fn terrain_result() -> serde_json::Value {
        let stage = serde_json::json!({
            "map_lcg": 2,
            "tile_hash": 3,
            "terrain_counts": [6480, 0, 0, 0, 0, 0, 0, 0],
            "river_tile_count": 0,
        });
        serde_json::json!({
            "name": "generated_world_ordinary_terrain",
            "seed": 1,
            "status": "passed",
            "generated_world": {
                "map": {"scenario_tag": "ordinary"},
                "coarse_generation": {"initial_map_lcg": 1},
                "terrain_generation": {
                    "topology_byte": 0,
                    "tuning": {
                        "desert_quota": 200,
                        "mountain_quota": 150,
                        "hills_quota": 250,
                        "forest_quota": 250,
                        "swamp_quota": 150,
                        "river_count": 10,
                        "region_seed_rows": 14,
                        "region_seed_columns": 8,
                    },
                    "attempt_count": 1,
                    "attempts": [{
                        "index": 0,
                        "map_lcg_after_expansion": 2,
                        "after_expansion": stage,
                        "after_templates": stage,
                        "after_features": stage,
                        "after_rotation": stage,
                        "after_water_regions": stage,
                        "after_keyword": stage,
                        "accepted": 1,
                        "map_lcg_after_validation": 2,
                        "rotation_column": 0,
                        "seed_candidate_tiles": vec![0; 23],
                        "tile_fields": TERRAIN_TILE_FIELDS,
                        "tiles": vec![[0, 0, -1, -1, -1]; 108 * 60],
                    }],
                },
            },
        })
    }

    #[test]
    fn terrain_decoder_rejects_unknown_fields_and_malformed_shapes() {
        let mut unknown = terrain_result();
        unknown["generated_world"]["terrain_generation"]["unknown"] = serde_json::json!(1);
        assert!(matches!(
            decode_generated_world_terrain(serde_json::to_vec(&unknown).unwrap().as_slice()),
            Err(TerrainOracleReadError::Json(_))
        ));

        let mut malformed = terrain_result();
        malformed["generated_world"]["terrain_generation"]["attempts"][0]["tiles"] =
            serde_json::json!([]);
        assert!(matches!(
            decode_generated_world_terrain(serde_json::to_vec(&malformed).unwrap().as_slice()),
            Err(TerrainOracleReadError::InvalidTerrainGeneration(_))
        ));

        let mut invalid_topology = terrain_result();
        invalid_topology["generated_world"]["terrain_generation"]["topology_byte"] =
            serde_json::json!(128);
        assert!(matches!(
            decode_generated_world_terrain(
                serde_json::to_vec(&invalid_topology).unwrap().as_slice()
            ),
            Err(TerrainOracleReadError::Json(_))
        ));
    }

    #[test]
    fn terrain_decoder_requires_the_runtime_result_shape() {
        let standalone = terrain_result()["generated_world"].clone();
        assert!(matches!(
            decode_generated_world_terrain(serde_json::to_vec(&standalone).unwrap().as_slice()),
            Err(TerrainOracleReadError::MissingGeneratedWorld)
        ));
    }

    #[test]
    fn reports_the_first_serialized_path() {
        let original = json!({"cities": [{"stock": [2, 4, 6]}]});
        let reimplementation = json!({"cities": [{"stock": [2, 5, 6]}]});
        let difference = first_serialized_difference(&original, &reimplementation)
            .unwrap()
            .unwrap();
        assert_eq!(difference.path, "cities[0].stock[1]");
        assert_eq!(difference.original, Some(json!(4)));
        assert_eq!(difference.reimplementation, Some(json!(5)));
    }

    #[test]
    fn accepts_equal_values() {
        let value = json!({"turn": 3, "flags": [true, false]});
        assert_eq!(first_serialized_difference(&value, &value).unwrap(), None);
    }
}
