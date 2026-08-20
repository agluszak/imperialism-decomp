#![forbid(unsafe_code)]

mod differential;
mod runtime_capture;

pub use differential::{assert_game_state_eq, compare_native, load_save_backed_state, run_native};
use imperialism_core::{
    Difficulty, MajorNationId, MapTopology, ProvinceId, RetailCrtRng, RetailLcg, ZoneKind,
    create_random_game,
    differential::{
        CoarseMapTrace, RandomMapTerrainTrace, trace_coarse_random_map, trace_random_map_terrain,
    },
    generate_random_setup_preview,
};
use imperialism_formats::RetailAssets;
pub use runtime_capture::{RuntimeRun, run_runtime};
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

/// Replay a catalogued random-map runtime scenario and compare its terrain capture.
pub fn compare_map_generation_terrain(scenario: &str) -> anyhow::Result<()> {
    let runtime = run_runtime(scenario)?;
    let capture: RandomMapTerrainCapture = runtime.capture("random_map_terrain")?;
    generate_and_compare_terrain_capture(&capture).map_err(|difference| {
        anyhow::anyhow!(
            "terrain oracle mismatch at {}: C++={:?}, Rust={:?}",
            difference.path,
            difference.original,
            difference.reimplementation
        )
    })?;
    Ok(())
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

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RandomProvinceNameCapture {
    id: u16,
    name_hex: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RandomNationNameCapture {
    slot: u8,
    name_hex: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RandomZoneNameCapture {
    ordinal: u16,
    status_code: i16,
    display_name_hex: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
struct RandomGameNameCapture {
    provinces: Vec<RandomProvinceNameCapture>,
    nations: Vec<RandomNationNameCapture>,
    zones: Vec<RandomZoneNameCapture>,
}

/// Replay an accepted random setup and compare its mapped-flavor names with retail.
pub fn compare_random_game_names(scenario: &str) -> anyhow::Result<()> {
    let runtime = run_runtime(scenario)?;
    let setup: RandomGameSetupCapture = runtime.capture("random_game_setup")?;
    let mut expected: RandomGameNameCapture = runtime.capture("random_game_names")?;
    let mut marker_crt = RetailCrtRng::from_state(1);
    let _ = marker_crt.next_rand();
    let preview = generate_random_setup_preview(
        setup.planet_seed.as_bytes(),
        setup.topology.topology(),
        marker_crt,
    )?;
    let names = RetailAssets::open(runtime.game_dir())?.random_game_names()?;
    let actual = create_random_game(
        &preview,
        setup.nation,
        setup.difficulty,
        &setup.country_name,
        setup.localized_names,
        1,
        &names,
    );
    expected.zones.sort_by_key(|zone| zone.ordinal);
    let actual = RandomGameNameCapture {
        provinces: ProvinceId::all()
            .filter(|&id| !actual.map().provinces[id].linked_tiles.is_empty())
            .map(|id| RandomProvinceNameCapture {
                id: id.get(),
                name_hex: retail_text_hex(&actual.map().provinces[id].name),
            })
            .collect(),
        nations: imperialism_core::NationId::all()
            .filter_map(|nation| {
                actual
                    .nations()
                    .display_name(nation)
                    .map(|name| RandomNationNameCapture {
                        slot: nation.get(),
                        name_hex: retail_text_hex(name),
                    })
            })
            .collect(),
        zones: actual
            .ocean()
            .zones
            .iter()
            .enumerate()
            .map(|(ordinal, zone)| {
                let zone = match zone {
                    ZoneKind::Zone(zone) => zone,
                    ZoneKind::PortZone(port) => &port.zone,
                };
                RandomZoneNameCapture {
                    ordinal: u16::try_from(ordinal).expect("zone ordinal fits u16"),
                    status_code: zone.status_code.expect("fresh zone has a status code"),
                    display_name_hex: retail_text_hex(&zone.display_name),
                }
            })
            .collect(),
    };
    if let Some(difference) = first_serialized_difference(&expected, &actual)? {
        anyhow::bail!(
            "random-game name mismatch at {}: C++={:?}, Rust={:?}",
            difference.path,
            difference.original,
            difference.reimplementation
        );
    }
    Ok(())
}

fn retail_text_hex(text: &str) -> String {
    text.chars()
        .flat_map(|ch| {
            let byte = u8::try_from(ch).expect("mapped flavor text is Latin-1");
            [
                char::from_digit(u32::from(byte >> 4), 16).unwrap(),
                char::from_digit(u32::from(byte & 0x0f), 16).unwrap(),
            ]
        })
        .collect()
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
    use serde_json::json;

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
}
