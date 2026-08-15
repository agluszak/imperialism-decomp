use crate::random_map::generate_coarse_random_map;
#[cfg(feature = "differential-trace")]
use crate::random_map::trace_coarse_random_map;
use crate::{
    EXPANDED_MAP_HEIGHT, EXPANDED_MAP_WIDTH, MapGeometry, MapTopology, OceanRoute, OceanZoneId,
    ProvinceId, RANDOM_MAP_CLASS_COUNT, RetailCrtRng, RetailLcg, RiverSegment, TerrainKind, TileId,
    TileOwnerTag, hash_retail_scenario_tag,
};
use serde::{Deserialize, Deserializer, Serialize};

mod features;
mod regions;
mod templates;
#[cfg(feature = "differential-trace")]
mod trace;

#[cfg(feature = "differential-trace")]
pub use trace::{
    RandomMapTerrainAttemptTrace, RandomMapTerrainStageTrace, RandomMapTerrainTrace,
    trace_random_map_terrain,
};

use features::place_terrain_features;
use regions::{
    apply_scenario_keyword_override, generate_water_region_ids, rotate_map_columns,
    validate_seed_candidates,
};
use templates::randomize_templates_and_smooth;
#[cfg(feature = "differential-trace")]
use trace::{summarize_keyword_stage, summarize_stage};

const TILE_COUNT: usize = EXPANDED_MAP_WIDTH * EXPANDED_MAP_HEIGHT;
const PLAINS: i8 = 0;
const FOREST: i8 = 1;
const HILLS: i8 = 2;
const MOUNTAIN: i8 = 3;
const SWAMP: i8 = 4;
const WATER: i8 = 5;
const DESERT: i8 = 6;
const FARMLAND: i8 = 7;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RandomMapTuning {
    pub desert_quota: i32,
    pub mountain_quota: i32,
    pub hills_quota: i32,
    pub forest_quota: i32,
    pub swamp_quota: i32,
    pub river_count: i32,
    pub region_seed_rows: i32,
    pub region_seed_columns: i32,
}

impl RandomMapTuning {
    pub fn from_scenario_tag(tag: &[u8]) -> Self {
        let mut result = Self {
            desert_quota: 200,
            mountain_quota: 150,
            hills_quota: 250,
            forest_quota: 250,
            swamp_quota: 150,
            river_count: 10,
            region_seed_rows: 14,
            region_seed_columns: 8,
        };
        let mut budget = 1_000;
        let mut armed = false;
        let mut index = 0;
        while let Some(&byte) = tag.get(index) {
            if byte == 0 {
                break;
            }
            if !armed && byte == b'@' {
                index += 1;
                let Some(&after_at) = tag.get(index) else {
                    break;
                };
                if after_at == b'^' {
                    index += 1;
                    let Some(&after_caret) = tag.get(index) else {
                        break;
                    };
                    armed = after_caret == b'>';
                }
            }
            if armed {
                match tag[index] {
                    b'D' => result.desert_quota = 300,
                    b'd' => result.desert_quota = 100,
                    b'M' => result.mountain_quota = 300,
                    b'm' => result.mountain_quota = 100,
                    b'H' => result.hills_quota = 500,
                    b'h' => result.hills_quota = 100,
                    b'F' => result.forest_quota = 500,
                    b'f' => result.forest_quota = 100,
                    b'S' => result.swamp_quota = 300,
                    b's' => result.swamp_quota = 100,
                    b'P' => budget = 750,
                    b'p' => budget = 1_500,
                    b'R' => result.river_count = 20,
                    b'r' => result.river_count = 5,
                    b'c' => {
                        result.region_seed_rows = 18;
                        result.region_seed_columns = 10;
                    }
                    b'C' => {
                        result.region_seed_rows = 10;
                        result.region_seed_columns = 6;
                    }
                    _ => {}
                }
            }
            index += 1;
        }
        let sum = result.swamp_quota
            + result.hills_quota
            + result.forest_quota
            + result.desert_quota
            + result.mountain_quota;
        if sum != budget {
            result.desert_quota = budget * result.desert_quota / sum;
            result.mountain_quota = budget * result.mountain_quota / sum;
            result.hills_quota = budget * result.hills_quota / sum;
            result.forest_quota = budget * result.forest_quota / sum;
            result.swamp_quota = budget * result.swamp_quota / sum;
        }
        result
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct GeneratedTerrainTileScratch {
    pub terrain_kind: i8,
    pub river_sprite_code: u8,
    pub owner_nation: i8,
    pub gate_flag: i8,
    pub province_index: i16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedTerrainTile {
    pub terrain: TerrainKind,
    pub river: Option<RiverSegment>,
    pub owner: Option<TileOwnerTag>,
    pub gate: Option<GenerationGate>,
    pub province: Option<ProvinceId>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct GenerationGate(i8);
impl GenerationGate {
    /// Recovered generation subtype code used only by the random-game post-pass.
    pub(crate) const fn code(self) -> i8 {
        self.0
    }

    #[cfg(test)]
    pub(crate) const fn get(self) -> i8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedProvince {
    pub owner: TileOwnerTag,
    pub region_class: u8,
}

/// The final terrain map used to create a game. The supplied [`RetailLcg`] has
/// advanced through every rejected attempt when this value is returned.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GeneratedMap {
    tiles: Box<[GeneratedTerrainTile]>,
    provinces: Box<[GeneratedProvince]>,
    seed_candidate_tiles: [TileId; RANDOM_MAP_CLASS_COUNT],
    pub(crate) ocean_routes: Vec<OceanRoute>,
    pub(crate) ocean_zone_links: Vec<[OceanZoneId; 2]>,
}

impl GeneratedMap {
    fn from_parts(
        tiles: Box<[GeneratedTerrainTile]>,
        provinces: Box<[GeneratedProvince]>,
        seed_candidate_tiles: [TileId; RANDOM_MAP_CLASS_COUNT],
        ocean_routes: Vec<OceanRoute>,
        ocean_zone_links: Vec<[OceanZoneId; 2]>,
    ) -> Self {
        assert_eq!(
            tiles.len(),
            crate::STRATEGIC_TILE_COUNT,
            "accepted generated maps have the strategic tile count"
        );
        Self {
            tiles,
            provinces,
            seed_candidate_tiles,
            ocean_routes,
            ocean_zone_links,
        }
    }

    pub fn tile(&self, tile: TileId) -> GeneratedTerrainTile {
        self.tiles[usize::from(tile.get())]
    }

    pub fn tiles(&self) -> &[GeneratedTerrainTile] {
        &self.tiles
    }

    pub fn provinces(&self) -> &[GeneratedProvince] {
        &self.provinces
    }

    pub const fn seed_candidate_tiles(&self) -> &[TileId; RANDOM_MAP_CLASS_COUNT] {
        &self.seed_candidate_tiles
    }
}

impl<'de> Deserialize<'de> for GeneratedMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedGeneratedMap {
            tiles: Box<[GeneratedTerrainTile]>,
            provinces: Box<[GeneratedProvince]>,
            seed_candidate_tiles: [TileId; RANDOM_MAP_CLASS_COUNT],
            ocean_routes: Vec<OceanRoute>,
            ocean_zone_links: Vec<[OceanZoneId; 2]>,
        }

        let map = SerializedGeneratedMap::deserialize(deserializer)?;
        if map.tiles.len() != crate::STRATEGIC_TILE_COUNT {
            return Err(serde::de::Error::custom(format!(
                "generated map has {} tiles; expected {}",
                map.tiles.len(),
                crate::STRATEGIC_TILE_COUNT
            )));
        }
        Ok(Self::from_parts(
            map.tiles,
            map.provinces,
            map.seed_candidate_tiles,
            map.ocean_routes,
            map.ocean_zone_links,
        ))
    }
}

/// The generated map preview retained by the random-game setup screen.
///
/// `final_map_lcg` is the state after every rejected and accepted map-generation
/// attempt. `sea_zone_marker_crt` is the separate CRT stream at the point where
/// that retained map assigns its sea-zone markers. Accepting the setup can
/// therefore preserve both retail RNG results without regenerating the preview.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RandomSetupPreview {
    /// Retail `TMapMgr::scenarioTagText`, retained exactly from the accepted setup seed.
    pub scenario_tag: String,
    /// The topology used for the retained map. Accept must not be able to
    /// commit a different topology than the one it previews.
    pub topology: MapTopology,
    pub map: GeneratedMap,
    pub final_map_lcg: u32,
    pub sea_zone_marker_crt: RetailCrtRng,
}

/// A retail setup seed needs the original clock-derived fallback when its
/// signed-byte hash is zero.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RandomSetupPreviewError {
    #[error("the retail random-map seed hash is zero and requires a clock-derived fallback")]
    ClockSeedRequired,
}

pub fn generate_random_map(
    scenario_tag: &[u8],
    topology: MapTopology,
    rng: &mut RetailLcg,
) -> GeneratedMap {
    let tuning = RandomMapTuning::from_scenario_tag(scenario_tag);
    generate_random_map_impl(
        scenario_tag,
        topology,
        tuning,
        rng,
        #[cfg(feature = "differential-trace")]
        None,
    )
}

/// Generates the random-map setup preview from an explicit retail seed.
///
/// Retail hashes the seed text, then advances its map-generation LCG once
/// before the first generation attempt. A zero hash takes the retail
/// clock-derived fallback path, which this deterministic API intentionally
/// requires its caller to handle explicitly.
pub fn generate_random_setup_preview(
    seed: &[u8],
    topology: MapTopology,
    sea_zone_marker_crt: RetailCrtRng,
) -> Result<RandomSetupPreview, RandomSetupPreviewError> {
    let mut rng = retail_random_setup_lcg(seed)?;
    Ok(generate_random_setup_preview_from_lcg(
        seed,
        topology,
        &mut rng,
        sea_zone_marker_crt,
    ))
}

/// Generates a setup preview using the clock-derived value retail supplies
/// when the seed's signed-byte hash is zero.
///
/// Callers without a clock value can use [`generate_random_setup_preview`],
/// which makes the fallback requirement explicit. The setup screen owns the
/// clock value, so it uses this exact branch instead of substituting a made-up
/// seed.
pub fn generate_random_setup_preview_with_clock_seed(
    seed: &[u8],
    topology: MapTopology,
    clock_seed: u32,
    sea_zone_marker_crt: RetailCrtRng,
) -> RandomSetupPreview {
    let mut rng = retail_random_setup_lcg_with_clock_seed(seed, clock_seed);
    generate_random_setup_preview_from_lcg(seed, topology, &mut rng, sea_zone_marker_crt)
}

fn generate_random_setup_preview_from_lcg(
    seed: &[u8],
    topology: MapTopology,
    rng: &mut RetailLcg,
    sea_zone_marker_crt: RetailCrtRng,
) -> RandomSetupPreview {
    let map = generate_random_map(seed, topology, rng);
    RandomSetupPreview {
        scenario_tag: String::from_utf8(seed.to_vec())
            .expect("random setup seed text is valid UTF-8"),
        topology,
        map,
        final_map_lcg: rng.state(),
        sea_zone_marker_crt,
    }
}

fn retail_random_setup_lcg(seed: &[u8]) -> Result<RetailLcg, RandomSetupPreviewError> {
    retail_random_setup_lcg_from_hash(hash_retail_scenario_tag(seed))
}

fn retail_random_setup_lcg_from_hash(seed: i32) -> Result<RetailLcg, RandomSetupPreviewError> {
    if seed == 0 {
        return Err(RandomSetupPreviewError::ClockSeedRequired);
    }
    Ok(retail_random_setup_lcg_from_seed_state(seed as u32))
}

fn retail_random_setup_lcg_with_clock_seed(seed: &[u8], clock_seed: u32) -> RetailLcg {
    retail_random_setup_lcg_from_seed_state(random_setup_map_seed_state(
        hash_retail_scenario_tag(seed),
        clock_seed,
    ))
}

const fn random_setup_map_seed_state(seed_hash: i32, clock_seed: u32) -> u32 {
    if seed_hash == 0 {
        clock_seed
    } else {
        seed_hash as u32
    }
}

fn retail_random_setup_lcg_from_seed_state(seed: u32) -> RetailLcg {
    let mut rng = RetailLcg::from_state(seed);
    rng.advance();
    rng
}

fn generate_random_map_impl(
    scenario_tag: &[u8],
    topology: MapTopology,
    tuning: RandomMapTuning,
    rng: &mut RetailLcg,
    #[cfg(feature = "differential-trace")] mut attempts: Option<
        &mut Vec<RandomMapTerrainAttemptTrace>,
    >,
) -> GeneratedMap {
    let geometry = MapGeometry::new(topology);
    loop {
        #[cfg(feature = "differential-trace")]
        let (coarse_map, coarse_trace) = if attempts.is_some() {
            let trace = trace_coarse_random_map(rng);
            (trace.final_map(), Some(trace))
        } else {
            (generate_coarse_random_map(rng), None)
        };
        #[cfg(not(feature = "differential-trace"))]
        let coarse_map = generate_coarse_random_map(rng);

        let (expanded_tiles, provinces) = coarse_map.expanded_seed_data();
        let mut tiles = expanded_tiles
            .iter()
            .map(|tile| GeneratedTerrainTileScratch {
                terrain_kind: tile.terrain_kind,
                river_sprite_code: 0,
                owner_nation: tile.owner_nation,
                gate_flag: -1,
                province_index: tile.province_index,
            })
            .collect::<Vec<_>>();

        #[cfg(feature = "differential-trace")]
        let after_expansion = attempts
            .as_ref()
            .map(|_| summarize_stage(&tiles, rng.state()));
        randomize_templates_and_smooth(&mut tiles, &coarse_map, geometry, rng);
        #[cfg(feature = "differential-trace")]
        let after_templates = attempts
            .as_ref()
            .map(|_| summarize_stage(&tiles, rng.state()));
        place_terrain_features(&mut tiles, geometry, tuning, rng);
        #[cfg(feature = "differential-trace")]
        let after_features = attempts
            .as_ref()
            .map(|_| summarize_stage(&tiles, rng.state()));
        #[allow(unused_variables)]
        let rotation_column = rotate_map_columns(&mut tiles);
        #[cfg(feature = "differential-trace")]
        let after_rotation = attempts
            .as_ref()
            .map(|_| summarize_stage(&tiles, rng.state()));
        generate_water_region_ids(
            &mut tiles,
            geometry,
            tuning.region_seed_rows,
            tuning.region_seed_columns,
            rng,
        );
        #[cfg(feature = "differential-trace")]
        let after_water_regions = attempts
            .as_ref()
            .map(|_| summarize_stage(&tiles, rng.state()));
        // `AssignOrCompactCityRegionIdsAndRebuildBorders(0)` tail: border quads → span
        // links → MergeSmallCityRegionsAndCompactIds. No LCG draws.
        let water_merge =
            crate::random_map_water_merge::merge_small_water_regions(&mut tiles, geometry);
        debug_assert_eq!(
            water_merge.region_count,
            tiles
                .iter()
                .filter(|tile| tile.terrain_kind == WATER)
                .map(|tile| i32::from(tile.owner_nation as u8) - 0x17)
                .max()
                .unwrap_or(-1)
                + 1
        );
        apply_scenario_keyword_override(&mut tiles, scenario_tag, rng);
        #[cfg(feature = "differential-trace")]
        let after_keyword = attempts
            .as_ref()
            .map(|_| summarize_keyword_stage(&tiles, rng.state()));
        let (accepted, seed_candidate_tiles) = validate_seed_candidates(&tiles, geometry, rng);
        #[cfg(feature = "differential-trace")]
        if let Some(attempts) = &mut attempts {
            attempts.push(RandomMapTerrainAttemptTrace {
                coarse_generation: coarse_trace.expect("trace collection selects a coarse trace"),
                after_expansion: after_expansion.expect("trace collection summarizes expansion"),
                after_templates: after_templates.expect("trace collection summarizes templates"),
                after_features: after_features.expect("trace collection summarizes features"),
                after_rotation: after_rotation.expect("trace collection summarizes rotation"),
                after_water_regions: after_water_regions
                    .expect("trace collection summarizes water regions"),
                after_keyword: after_keyword.expect("trace collection summarizes scenario keyword"),
                map_lcg_after_validation: rng.state(),
                rotation_column,
                seed_candidate_tiles: seed_candidate_tiles.map(|tile| i32::from(tile.get())),
                accepted,
            });
        }
        if accepted {
            return GeneratedMap::from_parts(
                tiles.into_iter().map(normalize_generated_tile).collect(),
                provinces
                    .into_iter()
                    .map(|province| GeneratedProvince {
                        owner: TileOwnerTag::new(
                            u8::try_from(province.owner_nation)
                                .expect("accepted province owner is nonnegative"),
                        ),
                        region_class: u8::try_from(province.region_class)
                            .expect("accepted province region class is nonnegative"),
                    })
                    .collect(),
                seed_candidate_tiles,
                water_merge.routes,
                water_merge.zone_links,
            );
        }
    }
}

fn normalize_generated_tile(tile: GeneratedTerrainTileScratch) -> GeneratedTerrainTile {
    GeneratedTerrainTile {
        terrain: TerrainKind::from_retail(tile.terrain_kind)
            .expect("accepted generator terrain is semantic"),
        river: RiverSegment::from_connection_code(tile.river_sprite_code),
        owner: u8::try_from(tile.owner_nation).ok().map(TileOwnerTag::new),
        gate: (tile.gate_flag != -1).then_some(GenerationGate(tile.gate_flag)),
        province: u16::try_from(tile.province_index)
            .ok()
            .and_then(ProvinceId::try_new),
    }
}

fn full_neighbor(geometry: MapGeometry, tile: usize, direction: usize) -> Option<usize> {
    let direction = crate::HexDirection::ALL[direction];
    geometry
        .neighbor(TileId::new(tile as u16), direction)
        .map(|tile| usize::from(tile.get()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn final_tile_hash(tiles: &[GeneratedTerrainTile]) -> u32 {
        tiles.iter().fold(0x811c_9dc5, |hash, tile| {
            let province = tile
                .province
                .map_or(-1, |province| province.get() as i16)
                .to_le_bytes();
            [
                tile.terrain.retail() as u8,
                tile.river.map_or(0, RiverSegment::connection_code),
                tile.owner.map_or(-1, |owner| owner.get() as i8) as u8,
                tile.gate.map_or(-1, GenerationGate::get) as u8,
                province[0],
                province[1],
            ]
            .into_iter()
            .fold(hash, |hash, byte| {
                (hash ^ u32::from(byte)).wrapping_mul(0x0100_0193)
            })
        })
    }

    #[test]
    fn parses_retail_defaults_and_case_sensitive_option_modifiers() {
        assert_eq!(
            RandomMapTuning::from_scenario_tag(b"earth"),
            RandomMapTuning {
                desert_quota: 200,
                mountain_quota: 150,
                hills_quota: 250,
                forest_quota: 250,
                swamp_quota: 150,
                river_count: 10,
                region_seed_rows: 14,
                region_seed_columns: 8,
            }
        );
        assert_eq!(
            RandomMapTuning::from_scenario_tag(b"@^>DMHFS PRc"),
            RandomMapTuning {
                desert_quota: 118,
                mountain_quota: 118,
                hills_quota: 197,
                forest_quota: 197,
                swamp_quota: 118,
                river_count: 20,
                region_seed_rows: 18,
                region_seed_columns: 10,
            }
        );
        assert_eq!(
            RandomMapTuning::from_scenario_tag(b"prefix @^>dmhfs prC"),
            RandomMapTuning {
                desert_quota: 300,
                mountain_quota: 300,
                hills_quota: 300,
                forest_quota: 300,
                swamp_quota: 300,
                river_count: 5,
                region_seed_rows: 10,
                region_seed_columns: 6,
            }
        );
        assert_eq!(
            RandomMapTuning::from_scenario_tag(b"@@^>D"),
            RandomMapTuning::from_scenario_tag(b"earth")
        );
    }

    #[test]
    fn wrapping_and_bounded_maps_generate_without_panicking() {
        for topology in [MapTopology::Wrapping, MapTopology::Bounded] {
            for seed in [1_u32, 2, 9] {
                let mut rng = RetailLcg::from_state(seed);
                let generated = generate_random_map(b"ordinary", topology, &mut rng);
                assert_eq!(generated.tiles().len(), TILE_COUNT);
                assert_eq!(generated.provinces().len(), 120);
            }
        }
    }

    #[test]
    fn seed_one_generates_the_retail_final_map_and_rng_state() {
        let mut rng = RetailLcg::from_state(3_122_877_655);
        let generated = generate_random_map(b"ordinary", MapTopology::Wrapping, &mut rng);
        assert_eq!(generated.provinces().len(), 120);
        assert_eq!(generated.tiles().len(), TILE_COUNT);
        let mut terrain_counts = [0_u32; 8];
        for tile in generated.tiles() {
            terrain_counts[tile.terrain as usize] += 1;
        }
        assert_eq!(terrain_counts, [440, 252, 250, 156, 150, 4_538, 343, 351]);
        assert_eq!(
            generated.seed_candidate_tiles(),
            &[
                2_987, 4_153, 2_044, 1_666, 3_319, 284, 259, 1_162, 245, 1_529, 1_863, 1_994,
                1_698, 2_838, 2_013, 3_775, 4_732, 2_836, 2_680, 3_813, 3_833, 4_060, 4_608,
            ]
            .map(TileId::new)
        );
        // Includes post-merge water owner tags from AssignOrCompactCityRegionIdsAndRebuildBorders.
        assert_eq!(final_tile_hash(generated.tiles()), 0xdf9d_e868);
        assert!(!generated.ocean_routes.is_empty());
        assert!(generated.ocean_routes.iter().all(|route| {
            route.start_column != route.end_column || route.start_row != route.end_row
        }));
        assert_eq!(rng.state(), 0x46a4_5026);
    }

    #[test]
    fn generated_map_preserves_region_classes_outside_the_terrain_domain() {
        let mut rng = RetailLcg::from_state(9);
        let generated = generate_random_map(b"ordinary", MapTopology::Wrapping, &mut rng);
        assert!(
            generated
                .provinces()
                .iter()
                .any(|province| province.region_class > TerrainKind::Farmland as u8)
        );
    }

    #[test]
    fn setup_preview_hashes_then_advances_the_retail_map_lcg() {
        let topology = MapTopology::Wrapping;
        let mut expected_rng = RetailLcg::from_state(3_122_877_655);
        let expected = generate_random_map(b"ordinary", topology, &mut expected_rng);

        assert_eq!(
            retail_random_setup_lcg(b"ordinary").unwrap().state(),
            3_122_877_655
        );
        let sea_zone_marker_crt = RetailCrtRng::from_state(1);
        let preview =
            generate_random_setup_preview(b"ordinary", topology, sea_zone_marker_crt).unwrap();
        assert_eq!(preview.map, expected);
        assert_eq!(preview.final_map_lcg, expected_rng.state());
        assert_eq!(
            generate_random_setup_preview_with_clock_seed(
                b"ordinary",
                topology,
                1,
                sea_zone_marker_crt,
            ),
            preview
        );
    }

    #[test]
    fn setup_preview_requires_a_clock_seed_for_a_zero_hash() {
        assert_eq!(
            retail_random_setup_lcg_from_hash(0),
            Err(RandomSetupPreviewError::ClockSeedRequired)
        );
        assert_eq!(random_setup_map_seed_state(0, 0x1234_5678), 0x1234_5678);
        assert_eq!(random_setup_map_seed_state(-1, 0x1234_5678), u32::MAX);
    }
}
