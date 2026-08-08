#![forbid(unsafe_code)]

mod runtime_capture;
mod start_boundary;

use imperialism_core::{
    Difficulty, GameState, MajorNationId, RetailLcg, RetailTopologyByte,
    differential_trace::{
        CoarseMapTrace, RandomMapTerrainCapture, RandomMapTerrainTrace, trace_coarse_random_map,
        trace_random_map_terrain,
    },
};
pub use runtime_capture::{
    RuntimeCaptureError, decode_runtime_capture, read_runtime_capture, read_runtime_seed,
};
use serde::{Deserialize, Serialize};
pub use start_boundary::{
    RandomGameStartBoundarySubset, compare_random_game_start_boundary,
    project_random_game_start_boundary,
};
use std::collections::BTreeSet;
use std::path::Path;

pub fn generate_and_compare_terrain_capture(
    capture: &RandomMapTerrainCapture,
) -> Result<RandomMapTerrainTrace, Difference> {
    let mut rng = RetailLcg::from_state(capture.generation.initial_map_lcg);
    let actual = trace_random_map_terrain(
        capture.scenario_tag.as_bytes(),
        capture.retail_topology,
        &mut rng,
    );
    if let Some(difference) = first_serialized_difference(&capture.generation, &actual)
        .expect("semantic terrain state serialization failed")
    {
        Err(difference)
    } else {
        Ok(actual)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Difference {
    pub path: String,
    pub original: Option<serde_json::Value>,
    pub reimplementation: Option<serde_json::Value>,
}

/// The initial or explicitly regenerated controls and preview seed from the
/// random-game setup screen, before the flow edits its scripted country or
/// difficulty controls.
///
/// The native runtime emits this directly as its `random_game_setup` capture.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
pub struct RandomGameSetupCapture {
    pub planet_seed: String,
    pub topology: RetailTopologyByte,
    pub nation: MajorNationId,
    pub country_name: String,
    pub difficulty: Difficulty,
    pub localized_names: bool,
}

pub fn read_game_state(path: impl AsRef<Path>) -> Result<GameState, RuntimeCaptureError> {
    read_runtime_capture(path, "game_state")
}

pub fn read_coarse_map_trace(
    path: impl AsRef<Path>,
) -> Result<CoarseMapTrace, RuntimeCaptureError> {
    read_runtime_capture(path, "coarse_map_generation")
}

pub fn read_random_game_setup(
    path: impl AsRef<Path>,
) -> Result<RandomGameSetupCapture, RuntimeCaptureError> {
    read_runtime_capture(path, "random_game_setup")
}

pub fn generate_and_compare_coarse_trace(
    expected: &CoarseMapTrace,
) -> Result<CoarseMapTrace, Difference> {
    let mut rng = RetailLcg::from_state(expected.initial_map_lcg);
    let actual = trace_coarse_random_map(&mut rng);
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
    use imperialism_core::generate_random_setup_preview;
    use serde_json::json;

    fn terrain_capture() -> RandomMapTerrainCapture {
        let scenario_tag = "ordinary".to_owned();
        let retail_topology = RetailTopologyByte::from_retail_byte(0);
        let mut rng = RetailLcg::from_state(3_122_877_655);
        let generation =
            trace_random_map_terrain(scenario_tag.as_bytes(), retail_topology, &mut rng);
        RandomMapTerrainCapture {
            scenario_tag,
            retail_topology,
            generation,
        }
    }

    fn random_game_setup_capture() -> RandomGameSetupCapture {
        RandomGameSetupCapture {
            planet_seed: "ordinary".to_owned(),
            topology: RetailTopologyByte::from_retail_byte(0),
            nation: MajorNationId::new(6),
            country_name: "Purtast".to_owned(),
            difficulty: Difficulty::Introductory,
            localized_names: true,
        }
    }

    #[test]
    fn reads_the_direct_random_map_terrain_capture() {
        let expected = terrain_capture();
        let result = json!({
            "name": "terrain",
            "seed": 1,
            "status": "passed",
            "captures": {"random_map_terrain": expected},
        });
        let actual = decode_runtime_capture::<RandomMapTerrainCapture>(
            serde_json::to_vec(&result).unwrap().as_slice(),
            "random_map_terrain",
        )
        .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn terrain_capture_requires_its_named_capture() {
        let result = json!({
            "name": "terrain",
            "seed": 1,
            "status": "passed",
            "captures": {"other_capture": {}},
        });
        assert!(matches!(
            decode_runtime_capture::<RandomMapTerrainCapture>(
                serde_json::to_vec(&result).unwrap().as_slice(),
                "random_map_terrain",
            ),
            Err(RuntimeCaptureError::MissingCapture(name)) if name == "random_map_terrain"
        ));
    }

    #[test]
    fn reads_the_direct_random_game_setup_capture() {
        let expected = random_game_setup_capture();
        let result = json!({
            "name": "random_map_generation",
            "seed": 1,
            "status": "passed",
            "captures": {"random_game_setup": {
                "planet_seed": expected.planet_seed,
                "topology": expected.topology.retail_byte(),
                "nation": expected.nation.get(),
                "country_name": expected.country_name,
                "difficulty": expected.difficulty.retail_byte(),
                "localized_names": expected.localized_names,
            }},
        });
        let actual = decode_runtime_capture::<RandomGameSetupCapture>(
            serde_json::to_vec(&result).unwrap().as_slice(),
            "random_game_setup",
        )
        .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn random_game_setup_capture_replays_its_explicit_preview_seed() {
        let capture = random_game_setup_capture();
        let preview =
            generate_random_setup_preview(capture.planet_seed.as_bytes(), capture.topology)
                .unwrap();
        assert_eq!(preview.map.tiles.len(), 6_480);
        assert_eq!(preview.map.provinces.len(), 120);
        assert_eq!(preview.final_map_lcg, 0x46a4_5026);
    }

    #[test]
    fn direct_terrain_capture_replays_its_generation() {
        let expected = terrain_capture();
        assert_eq!(
            generate_and_compare_terrain_capture(&expected).unwrap(),
            expected.generation
        );
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
