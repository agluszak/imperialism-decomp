#![forbid(unsafe_code)]

mod differential;
mod oracle;
mod runtime_capture;

pub use differential::{
    assert_game_state_eq, compare_native, compare_runtime_scenario, run_retail_fixture_result,
};
use imperialism_core::{
    Difficulty, MajorNationId, MapTopology, RetailLcg,
    differential_trace::{
        CoarseMapTrace, RandomMapTerrainTrace, trace_coarse_random_map, trace_random_map_terrain,
    },
};
pub use oracle::{
    check_coarse, check_random_game_start, check_random_setup, check_random_setup_initial,
    check_snapshot, check_terrain,
};
pub use runtime_capture::{
    EvidenceKind, RuntimeCaptureError, RuntimeResultExpectations, ValidatedRuntimeResult,
    decode_runtime_result, read_runtime_result,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RetailTopologyByte(u8);

impl RetailTopologyByte {
    pub const fn from_retail_byte(value: u8) -> Self {
        Self(value)
    }

    pub const fn retail_byte(self) -> u8 {
        self.0
    }

    pub const fn topology(self) -> MapTopology {
        if self.0 == 0 {
            MapTopology::Wrapping
        } else {
            MapTopology::Bounded
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RandomMapTerrainCapture {
    pub scenario_tag: String,
    pub retail_topology: RetailTopologyByte,
    pub generation: RandomMapTerrainTrace,
}

pub fn generate_and_compare_terrain_capture(
    capture: &RandomMapTerrainCapture,
) -> Result<RandomMapTerrainTrace, Difference> {
    let mut rng = RetailLcg::from_state(capture.generation.initial_map_lcg);
    let actual = trace_random_map_terrain(
        capture.scenario_tag.as_bytes(),
        capture.retail_topology.topology(),
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

/// The controls paired with a random-game setup boundary.
///
/// Map-generation scenarios capture the initial or explicitly regenerated preview
/// before scripted edits. Game-start scenarios capture the accepted controls after
/// those edits and immediately before retail commits them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RandomGameSetupCapture {
    pub planet_seed: String,
    pub topology: RetailTopologyByte,
    pub nation: MajorNationId,
    pub country_name: String,
    pub difficulty: Difficulty,
    pub localized_names: bool,
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
    use imperialism_core::*;
    use serde_json::json;

    fn terrain_capture() -> RandomMapTerrainCapture {
        let scenario_tag = "ordinary".to_owned();
        let retail_topology = RetailTopologyByte::from_retail_byte(0);
        let mut rng = RetailLcg::from_state(3_122_877_655);
        let generation = trace_random_map_terrain(
            scenario_tag.as_bytes(),
            retail_topology.topology(),
            &mut rng,
        );
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

    fn self_consistency_expectations(
        required_captures: &'static [&'static str],
    ) -> RuntimeResultExpectations<'static> {
        RuntimeResultExpectations {
            name: "random_map_generation",
            seed: 1,
            evidence_kind: EvidenceKind::SelfConsistency,
            required_captures,
        }
    }

    #[test]
    fn reads_the_published_random_map_terrain_capture() {
        let expected = terrain_capture();
        let bytes = serde_json::to_vec(&json!({
            "name": "random_map_generation",
            "seed": 1,
            "status": "passed",
            "evidence_kind": "self_consistency",
            "captures": {"random_map_terrain": expected},
        }))
        .unwrap();
        let actual: RandomMapTerrainCapture = decode_runtime_result(
            bytes.as_slice(),
            self_consistency_expectations(&["random_map_terrain"]),
        )
        .unwrap()
        .capture("random_map_terrain")
        .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn terrain_capture_requires_its_named_capture() {
        let bytes = serde_json::to_vec(&json!({
            "name": "random_map_generation",
            "seed": 1,
            "status": "passed",
            "evidence_kind": "self_consistency",
            "captures": {"other_capture": {}},
        }))
        .unwrap();
        assert!(matches!(
            decode_runtime_result(
                bytes.as_slice(),
                self_consistency_expectations(&["random_map_terrain"]),
            ),
            Err(RuntimeCaptureError::MissingCapture(name)) if name == "random_map_terrain"
        ));
    }

    #[test]
    fn reads_the_published_random_game_setup_capture() {
        let expected = random_game_setup_capture();
        let bytes = serde_json::to_vec(&json!({
            "name": "random_map_generation",
            "seed": 1,
            "status": "passed",
            "evidence_kind": "self_consistency",
            "captures": {"random_game_setup": expected},
        }))
        .unwrap();
        let actual: RandomGameSetupCapture = decode_runtime_result(
            bytes.as_slice(),
            self_consistency_expectations(&["random_game_setup"]),
        )
        .unwrap()
        .capture("random_game_setup")
        .unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn random_game_setup_capture_replays_its_explicit_preview_seed() {
        let capture = random_game_setup_capture();
        let preview = generate_random_setup_preview(
            capture.planet_seed.as_bytes(),
            capture.topology.topology(),
            RetailCrtRng::from_state(1),
        )
        .unwrap();
        assert_eq!(preview.map.tiles().len(), 6_480);
        assert_eq!(preview.map.provinces().len(), 120);
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
