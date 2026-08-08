#[cfg(feature = "differential-trace")]
use crate::random_map::trace_coarse_random_map;
use crate::{
    CoarseMap, EXPANDED_MAP_HEIGHT, EXPANDED_MAP_WIDTH, ExpandedProvinceSeed, MapGeometry,
    RANDOM_MAP_CLASS_COUNT, RetailLcg, RetailTopologyByte, TileId, generate_coarse_random_map,
};
use serde::{Deserialize, Serialize};

const TILE_COUNT: usize = EXPANDED_MAP_WIDTH * EXPANDED_MAP_HEIGHT;
const PLAINS: i8 = 0;
const FOREST: i8 = 1;
const HILLS: i8 = 2;
const MOUNTAIN: i8 = 3;
const SWAMP: i8 = 4;
const WATER: i8 = 5;
const DESERT: i8 = 6;
const FARMLAND: i8 = 7;
const RIVER_CONNECTION: [[u8; 6]; 6] = [
    [0, 0, 1, 2, 3, 0],
    [0, 0, 0, 4, 5, 6],
    [1, 0, 0, 0, 7, 8],
    [2, 4, 0, 0, 0, 9],
    [3, 5, 7, 0, 0, 0],
    [0, 6, 8, 9, 0, 0],
];

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
pub struct GeneratedTerrainTile {
    pub terrain_kind: i8,
    pub river_sprite_code: u8,
    pub owner_nation: i8,
    pub gate_flag: i8,
    pub province_index: i16,
}

/// The final terrain map used to create a game. The supplied [`RetailLcg`] has
/// advanced through every rejected attempt when this value is returned.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GeneratedMap {
    pub tiles: Vec<GeneratedTerrainTile>,
    pub provinces: Vec<ExpandedProvinceSeed>,
    pub seed_candidate_tiles: [i32; RANDOM_MAP_CLASS_COUNT],
}

#[cfg(feature = "differential-trace")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RandomMapTerrainAttemptTrace {
    pub coarse_generation: crate::random_map::CoarseMapTrace,
    pub after_expansion: RandomMapTerrainStageTrace,
    pub after_templates: RandomMapTerrainStageTrace,
    pub after_features: RandomMapTerrainStageTrace,
    pub after_rotation: RandomMapTerrainStageTrace,
    pub after_water_regions: RandomMapTerrainStageTrace,
    pub after_keyword: RandomMapTerrainStageTrace,
    pub map_lcg_after_validation: u32,
    pub rotation_column: usize,
    pub seed_candidate_tiles: [i32; RANDOM_MAP_CLASS_COUNT],
    pub accepted: bool,
}

#[cfg(feature = "differential-trace")]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RandomMapTerrainStageTrace {
    pub map_lcg: u32,
    pub tile_hash: u32,
    pub terrain_counts: [u32; 8],
    pub river_tile_count: u32,
}

/// Test-only stage record emitted by the native differential harness. Normal
/// generation returns [`GeneratedMap`] instead.
#[cfg(feature = "differential-trace")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RandomMapTerrainTrace {
    pub tuning: RandomMapTuning,
    pub initial_map_lcg: u32,
    pub attempts: Vec<RandomMapTerrainAttemptTrace>,
    pub final_map_lcg: u32,
}

#[cfg(feature = "differential-trace")]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RandomMapTerrainCapture {
    pub scenario_tag: String,
    pub retail_topology: RetailTopologyByte,
    pub generation: RandomMapTerrainTrace,
}

pub fn generate_random_map(
    scenario_tag: &[u8],
    topology: RetailTopologyByte,
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

#[cfg(feature = "differential-trace")]
pub fn trace_random_map_terrain(
    scenario_tag: &[u8],
    topology: RetailTopologyByte,
    rng: &mut RetailLcg,
) -> RandomMapTerrainTrace {
    let tuning = RandomMapTuning::from_scenario_tag(scenario_tag);
    let initial_map_lcg = rng.state();
    let mut attempts = Vec::new();
    let _map = generate_random_map_impl(scenario_tag, topology, tuning, rng, Some(&mut attempts));
    RandomMapTerrainTrace {
        tuning,
        initial_map_lcg,
        attempts,
        final_map_lcg: rng.state(),
    }
}

fn generate_random_map_impl(
    scenario_tag: &[u8],
    topology: RetailTopologyByte,
    tuning: RandomMapTuning,
    rng: &mut RetailLcg,
    #[cfg(feature = "differential-trace")] mut attempts: Option<
        &mut Vec<RandomMapTerrainAttemptTrace>,
    >,
) -> GeneratedMap {
    let geometry = MapGeometry::new(topology.wraps_horizontally());
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
            .map(|tile| GeneratedTerrainTile {
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
                seed_candidate_tiles,
                accepted,
            });
        }
        if accepted {
            return GeneratedMap {
                tiles,
                provinces,
                seed_candidate_tiles,
            };
        }
    }
}

#[cfg(feature = "differential-trace")]
fn summarize_stage(tiles: &[GeneratedTerrainTile], map_lcg: u32) -> RandomMapTerrainStageTrace {
    summarize_stage_with_water_ownership(tiles, map_lcg, true)
}

#[cfg(feature = "differential-trace")]
fn summarize_keyword_stage(
    tiles: &[GeneratedTerrainTile],
    map_lcg: u32,
) -> RandomMapTerrainStageTrace {
    summarize_stage_with_water_ownership(tiles, map_lcg, false)
}

#[cfg(feature = "differential-trace")]
fn summarize_stage_with_water_ownership(
    tiles: &[GeneratedTerrainTile],
    map_lcg: u32,
    include_water_ownership: bool,
) -> RandomMapTerrainStageTrace {
    let mut tile_hash = 0x811c_9dc5_u32;
    let mut terrain_counts = [0_u32; 8];
    let mut river_tile_count = 0;
    for tile in tiles {
        let owner = if include_water_ownership || tile.terrain_kind != WATER {
            tile.owner_nation
        } else {
            -1
        };
        let province_index = if include_water_ownership || tile.terrain_kind != WATER {
            tile.province_index
        } else {
            -1
        };
        let province = province_index.to_le_bytes();
        for byte in [
            tile.terrain_kind as u8,
            tile.river_sprite_code,
            owner as u8,
            tile.gate_flag as u8,
            province[0],
            province[1],
        ] {
            tile_hash = (tile_hash ^ u32::from(byte)).wrapping_mul(0x0100_0193);
        }
        if let Ok(terrain) = usize::try_from(tile.terrain_kind)
            && let Some(count) = terrain_counts.get_mut(terrain)
        {
            *count += 1;
        }
        if tile.river_sprite_code != 0 {
            river_tile_count += 1;
        }
    }
    RandomMapTerrainStageTrace {
        map_lcg,
        tile_hash,
        terrain_counts,
        river_tile_count,
    }
}

fn randomize_templates_and_smooth(
    tiles: &mut [GeneratedTerrainTile],
    coarse: &CoarseMap,
    geometry: MapGeometry,
    rng: &mut RetailLcg,
) {
    for coarse_index in 0..378_i32 {
        let base = coarse_class(coarse, coarse_index);
        let class1 = coarse_class(coarse, coarse_neighbor(coarse_index, 1));
        let class2 = coarse_class(coarse, coarse_neighbor(coarse_index, 2));
        let class3 = coarse_class(coarse, coarse_neighbor(coarse_index, 3));
        randomize_template_banks(tiles, coarse_index, base, class1, class3, class2, rng);
    }
    smooth_ownership(tiles, geometry, rng);
}

fn randomize_template_banks(
    tiles: &mut [GeneratedTerrainTile],
    coarse_index: i32,
    base: i16,
    class3: i16,
    class4: i16,
    class5: i16,
    rng: &mut RetailLcg,
) {
    let cell = fine_cell_base(coarse_index);
    if class3 != base {
        match rng.next_sample_15() % 5 {
            1 => copy_tile(tiles, cell + 111, cell + 112),
            2 => copy_tile(tiles, cell + 112, cell + 111),
            _ => {}
        }
        match rng.next_sample_15() % 5 {
            1 => copy_tile(tiles, cell + 219, cell + 220),
            2 => copy_tile(tiles, cell + 220, cell + 219),
            _ => {}
        }
    }
    if class4 != base {
        let destination = cell + 324 + i32::from((rng.advance() >> 12) & 1 != 0);
        match rng.next_sample_15() % 7 {
            0 | 1 | 3 | 5 => copy_tile(tiles, destination, destination + 108),
            2 | 4 | 6 => copy_tile(tiles, destination + 108, destination),
            _ => unreachable!(),
        }
    }
    if class5 != base {
        let destination = cell + 326 + i32::from((rng.advance() >> 12) & 1 != 0);
        match rng.next_sample_15() % 7 {
            0 | 1 | 3 | 5 => copy_tile(tiles, destination, destination + 108),
            2 | 4 | 6 => copy_tile(tiles, destination + 108, destination),
            _ => unreachable!(),
        }
    }
}

fn smooth_ownership(
    tiles: &mut [GeneratedTerrainTile],
    geometry: MapGeometry,
    rng: &mut RetailLcg,
) {
    for tile_index in 108..TILE_COUNT - 108 {
        let owner = tiles[tile_index].owner_nation;
        let mut same_owner_count = 0;
        let mut differing_neighbor = None;
        for direction in 0..6 {
            let neighbor = full_neighbor(geometry, tile_index, direction);
            let neighbor_owner = neighbor.map_or(-1, |index| tiles[index].owner_nation);
            if neighbor_owner == owner {
                same_owner_count += 1;
            } else if neighbor_owner != -1 {
                differing_neighbor = neighbor;
            }
        }
        let replace = match same_owner_count {
            0 => true,
            1 => rng.next_sample_15() & 1 != 0,
            2 => rng.next_sample_15() & 4 == 0,
            _ => false,
        };
        if replace && let Some(neighbor) = differing_neighbor {
            tiles[tile_index] = tiles[neighbor];
        }
    }
    for tile_index in 108..TILE_COUNT - 108 {
        let owner = tiles[tile_index].owner_nation;
        let has_same_owner = (0..6).any(|direction| {
            full_neighbor(geometry, tile_index, direction)
                .is_some_and(|neighbor| tiles[neighbor].owner_nation == owner)
        });
        if !has_same_owner {
            let direction = (rng.next_sample_15() % 6) as usize;
            let neighbor = full_neighbor(geometry, tile_index, direction)
                .expect("retail isolated-tile copy selected an out-of-grid neighbor");
            tiles[tile_index] = tiles[neighbor];
        }
    }
}

fn place_terrain_features(
    tiles: &mut [GeneratedTerrainTile],
    geometry: MapGeometry,
    tuning: RandomMapTuning,
    rng: &mut RetailLcg,
) {
    let mut mountains = tuning.mountain_quota;
    while mountains > 0 {
        let retry_budget = (rng.next_sample_15() % 12) as i32 + 3;
        let tile = loop {
            let candidate = (rng.next_sample_15() % TILE_COUNT as u32) as i32;
            if tiles[candidate as usize].terrain_kind == PLAINS {
                break candidate;
            }
        };
        let direction = (rng.next_sample_15() % 6) as i32;
        mountains -= seed_mountain_range(tiles, geometry, tile, retry_budget, direction, rng);
    }

    let mut hills = tuning.hills_quota;
    for source in 0..TILE_COUNT {
        if tiles[source].terrain_kind != MOUNTAIN {
            continue;
        }
        for direction in 0..6 {
            if let Some(neighbor) = full_neighbor(geometry, source, direction)
                && tiles[neighbor].terrain_kind == PLAINS
                && rng.next_sample_15() % 100 < 40
            {
                tiles[neighbor].terrain_kind = HILLS;
                hills -= 1;
            }
        }
    }
    while hills > 0 {
        let tile = (rng.next_sample_15() % TILE_COUNT as u32) as usize;
        if tiles[tile].terrain_kind == PLAINS {
            tiles[tile].terrain_kind = HILLS;
            hills -= 1;
        }
    }

    create_deserts(tiles, geometry, rng);

    let original_forest_quota = tuning.forest_quota;
    let mut forest = original_forest_quota;
    let mut urgent = false;
    while forest > 0 {
        let tile = (rng.next_sample_15() % TILE_COUNT as u32) as i32;
        forest -= place_forest(tiles, geometry, tile, 7, urgent, rng);
        if forest < original_forest_quota * 2 / 3 {
            urgent = true;
        }
    }

    let mut swamp = tuning.swamp_quota;
    while swamp > 0 {
        let tile = loop {
            let candidate = (rng.next_sample_15() % TILE_COUNT as u32) as usize;
            if tiles[candidate].terrain_kind == PLAINS {
                break candidate;
            }
        };
        let clear = (0..6).all(|direction| {
            full_neighbor(geometry, tile, direction)
                .is_none_or(|neighbor| tiles[neighbor].terrain_kind != DESERT)
        });
        if clear {
            tiles[tile].terrain_kind = SWAMP;
            swamp -= 1;
        }
    }

    for tile in tiles.iter_mut() {
        if tile.terrain_kind == PLAINS && rng.next_sample_15() % 100 < 45 {
            tile.terrain_kind = FARMLAND;
        }
    }
    create_rivers(tiles, geometry, tuning.river_count, rng);
}

fn seed_mountain_range(
    tiles: &mut [GeneratedTerrainTile],
    geometry: MapGeometry,
    tile_index: i32,
    retry_budget: i32,
    direction: i32,
    rng: &mut RetailLcg,
) -> i32 {
    if !(0..=TILE_COUNT as i32).contains(&tile_index) {
        return 0;
    }
    let tile = usize::try_from(tile_index).expect("retail mountain tile index became negative");
    if tiles[tile].terrain_kind != PLAINS
        || (0..6).any(|dir| {
            full_neighbor(geometry, tile, dir)
                .is_some_and(|neighbor| tiles[neighbor].terrain_kind == WATER)
        })
    {
        return 0;
    }
    tiles[tile].terrain_kind = MOUNTAIN;
    let roll = rng.next_sample_15() % 100;
    let threshold = if direction == 1 || direction == 4 {
        39
    } else {
        59
    };
    let upper = if direction == 1 || direction == 4 {
        70
    } else {
        80
    };
    let mut next_direction = direction;
    if roll > threshold {
        next_direction = if roll < upper {
            if direction == 0 { 5 } else { direction - 1 }
        } else if direction == 5 {
            0
        } else {
            direction + 1
        };
    }
    let next_tile = full_neighbor(geometry, tile, next_direction as usize);
    let mut placed = 1;
    if retry_budget != 1
        && let Some(next_tile) = next_tile
    {
        placed += seed_mountain_range(
            tiles,
            geometry,
            next_tile as i32,
            retry_budget - 1,
            direction,
            rng,
        );
    }
    placed
}

fn create_deserts(tiles: &mut [GeneratedTerrainTile], geometry: MapGeometry, rng: &mut RetailLcg) {
    let mut remaining = 250;
    let mut chance_step: i32 = 5;
    let mut upper_row = 0;
    let mut lower_row = 59;
    let mut chance = 120;
    while chance > 90 && remaining > 0 {
        remaining -= desert_ring(tiles, geometry, upper_row, chance, false, rng);
        remaining -= desert_ring(tiles, geometry, lower_row, chance, false, rng);
        upper_row += 1;
        lower_row -= 1;
        chance -= 5;
    }
    if remaining > 0 {
        let mut row = 25;
        while row > 4 && remaining > 0 {
            let neighbor_chance = (chance_step.abs_diff(7) as i32 + 12) * 5;
            remaining -= desert_ring(tiles, geometry, row, neighbor_chance, true, rng);
            remaining -= desert_ring(
                tiles,
                geometry,
                chance_step + 30,
                neighbor_chance,
                true,
                rng,
            );
            chance_step += 2;
            row -= 2;
        }
    }
}

// Retail advances this record pointer linearly while wrapping a separate logical column.
#[allow(clippy::explicit_counter_loop)]
fn desert_ring(
    tiles: &mut [GeneratedTerrainTile],
    geometry: MapGeometry,
    row: i32,
    chance: i32,
    spreads: bool,
    rng: &mut RetailLcg,
) -> i32 {
    let row_start = row as usize * EXPANDED_MAP_WIDTH;
    let Some(mut column) =
        (0..EXPANDED_MAP_WIDTH).find(|column| tiles[row_start + column].terrain_kind == WATER)
    else {
        return 0;
    };
    let mut pointer_tile = row_start + column;
    let mut marked = 0;
    let mut in_land = false;
    for _ in 0..107 {
        column += 1;
        pointer_tile += 1;
        if column == EXPANDED_MAP_WIDTH {
            column = 0;
        }
        let tile = pointer_tile;
        if !in_land && tiles[tile].terrain_kind != WATER {
            in_land = true;
        }
        if in_land {
            if tiles[tile].terrain_kind == PLAINS {
                if rng.next_sample_15() % 100 < chance as u32 {
                    tiles[tile].terrain_kind = DESERT;
                    tiles[tile].gate_flag = if spreads { 11 } else { 12 };
                    marked += 1;
                    if spreads {
                        let logical_tile = row_start + column;
                        for direction in [5, 3] {
                            let neighbor = full_neighbor(geometry, logical_tile, direction)
                                .expect("retail desert band selected an invalid neighbor");
                            if tiles[neighbor].terrain_kind == PLAINS
                                && rng.next_sample_15() % 100 < chance as u32
                            {
                                tiles[neighbor].terrain_kind = DESERT;
                                // Retail writes the source tile's +0x13 again here.
                                tiles[tile].gate_flag = 11;
                                marked += 1;
                            }
                        }
                    }
                }
            } else if tiles[tile].terrain_kind == WATER {
                in_land = false;
            }
        }
    }
    marked
}

fn place_forest(
    tiles: &mut [GeneratedTerrainTile],
    geometry: MapGeometry,
    tile_index: i32,
    retry_budget: i32,
    urgent: bool,
    rng: &mut RetailLcg,
) -> i32 {
    let tile = usize::try_from(tile_index).expect("retail forest tile index became negative");
    if tiles[tile].terrain_kind != PLAINS
        || (0..6).any(|direction| {
            full_neighbor(geometry, tile, direction)
                .is_some_and(|neighbor| tiles[neighbor].terrain_kind == DESERT)
        })
    {
        return 0;
    }
    tiles[tile].terrain_kind = FOREST;
    tiles[tile].gate_flag = if urgent { 15 } else { 13 };
    let mut remaining = retry_budget - 1;
    for direction in 0..6 {
        let neighbor = full_neighbor(geometry, tile, direction)
            .expect("retail forest spread selected an invalid neighbor");
        if rng.next_sample_15() % 100 < 70 && remaining != 0 {
            remaining -= place_forest(tiles, geometry, neighbor as i32, 1, urgent, rng);
        }
    }
    retry_budget - remaining
}

fn create_rivers(
    tiles: &mut [GeneratedTerrainTile],
    geometry: MapGeometry,
    river_count: i32,
    rng: &mut RetailLcg,
) {
    let mut remaining = river_count;
    let mut attempts = 5_000_000;
    while remaining != 0 {
        let tile = loop {
            let candidate = (rng.next_sample_15() % TILE_COUNT as u32) as usize;
            attempts -= 1;
            if attempts == 0 {
                return;
            }
            if tiles[candidate].terrain_kind == MOUNTAIN {
                break candidate;
            }
        };
        let first_direction = (rng.next_sample_15() % 5) as usize;
        let mut direction = first_direction;
        loop {
            direction = if direction == 5 { 0 } else { direction + 1 };
            let neighbor = full_neighbor(geometry, tile, direction)
                .expect("retail river start selected an invalid neighbor");
            if tiles[neighbor].terrain_kind != MOUNTAIN || direction == first_direction {
                break;
            }
        }
        if direction != first_direction
            && grow_river(tiles, geometry, tile, direction, 6, 0, true, rng)
        {
            remaining -= 1;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn grow_river(
    tiles: &mut [GeneratedTerrainTile],
    geometry: MapGeometry,
    tile: usize,
    incoming_direction: usize,
    outgoing_direction: usize,
    depth: i32,
    started_on_hills: bool,
    rng: &mut RetailLcg,
) -> bool {
    let terrain = tiles[tile].terrain_kind;
    let began_on_hills = terrain == HILLS;
    if tiles[tile].river_sprite_code != 0
        || (terrain == MOUNTAIN && depth != 0)
        || (terrain == HILLS && !started_on_hills)
    {
        return false;
    }
    if terrain == WATER {
        if depth < 5 {
            return false;
        }
        tiles[tile].river_sprite_code = outgoing_direction as u8 + 0x10;
        return true;
    }
    let mut opposite = outgoing_direction;
    let mut next_direction = incoming_direction;
    if outgoing_direction < 6 {
        opposite = (outgoing_direction + 3) % 6;
        loop {
            next_direction = (incoming_direction + 7 - (rng.next_sample_15() % 3) as usize) % 6;
            if RIVER_CONNECTION[next_direction][opposite] != 0 {
                break;
            }
        }
    }
    let neighbor = full_neighbor(geometry, tile, next_direction)
        .expect("retail river recursion selected an invalid neighbor");
    if !grow_river(
        tiles,
        geometry,
        neighbor,
        incoming_direction,
        next_direction,
        depth + 1,
        began_on_hills,
        rng,
    ) {
        return false;
    }
    tiles[tile].river_sprite_code = if depth == 0 {
        next_direction as u8 + 10
    } else {
        RIVER_CONNECTION[next_direction][opposite]
    };
    true
}

fn rotate_map_columns(tiles: &mut [GeneratedTerrainTile]) -> usize {
    let counts = (0..EXPANDED_MAP_WIDTH)
        .map(|column| {
            (0..EXPANDED_MAP_HEIGHT)
                .filter(|row| tiles[row * EXPANDED_MAP_WIDTH + column].terrain_kind == WATER)
                .count()
        })
        .collect::<Vec<_>>();
    let mut window = [counts[105], counts[106], counts[107]];
    let mut total = window.iter().sum::<usize>();
    let mut position = 0;
    let mut best_density = -1_i32;
    let mut best_column = 0;
    for (column, count) in counts.iter().copied().enumerate() {
        total += count;
        if best_density < total as i32 {
            best_column = column;
            best_density = total as i32;
        }
        total -= window[position];
        window[position] = count;
        position = (position + 1) % 3;
    }
    if counts[best_column] == 0 {
        let mut left = (best_column + 107) % 108;
        let mut right = (best_column + 1) % 108;
        while counts[left] == 0 {
            left = (left + 107) % 108;
        }
        while counts[right] == 0 {
            right = (right + 1) % 108;
        }
        left = (left + 1) % 108;
        right = (right + 107) % 108;
        best_column = if right < left {
            ((left + 108 + right) / 2) % 108
        } else {
            (right + left) / 2
        };
    }
    let source = tiles.to_vec();
    for destination_column in 0..EXPANDED_MAP_WIDTH {
        let source_column = (best_column + 107 + destination_column) % 108;
        for row in 0..EXPANDED_MAP_HEIGHT {
            tiles[row * 108 + destination_column] = source[row * 108 + source_column];
        }
    }
    best_column
}

/// Runs the water-region seed and flood subpass that retail places between map rotation and
/// keyword overrides. The later border/span/merge work remains a separate generation slice, but
/// this subpass must live here because it owns both the water owner codes and the intervening LCG
/// draws observed by every keyword and final seed-candidate validation.
fn generate_water_region_ids(
    tiles: &mut [GeneratedTerrainTile],
    geometry: MapGeometry,
    region_rows: i32,
    region_columns: i32,
    rng: &mut RetailLcg,
) {
    let mut labels = tiles
        .iter()
        .map(|tile| {
            if tile.terrain_kind == WATER {
                -1_i16
            } else {
                -2_i16
            }
        })
        .collect::<Vec<_>>();
    let mut region_count = 0_i16;
    if region_rows > 0 {
        let mut row_base = 0;
        for _row_index in 0..region_rows {
            if region_columns > 0 {
                let mut column_base = 0;
                for column_index in 0..region_columns {
                    let first = rng.advance();
                    let second = rng.advance();
                    let mut column =
                        row_base / region_rows + 2 + ((first >> 12) & 0x7fff) as i32 % 5;
                    let mut row =
                        column_base / region_columns + 2 + ((second >> 12) & 0x7fff) as i32 % 5;
                    if column_index & 1 != 0 {
                        column += region_rows / 2;
                        if column > 107 {
                            column -= 108;
                        }
                    }
                    let mut radius = 0;
                    let mut ring = 1;
                    let mut direction = 0;
                    step_water_seed(&mut row, &mut column, 4, geometry.wraps_horizontally());
                    step_water_seed(
                        &mut row,
                        &mut column,
                        direction,
                        geometry.wraps_horizontally(),
                    );
                    while ring < 3 {
                        let tile = if (0..60).contains(&row) && (0..108).contains(&column) {
                            Some((column + row * 108) as usize)
                        } else {
                            None
                        };
                        if tile.is_some_and(|tile| labels[tile] == -1) {
                            labels[tile.unwrap()] = region_count;
                            region_count += 1;
                            break;
                        }
                        radius += 1;
                        if ring <= radius {
                            radius = 0;
                            direction += 1;
                            if direction > 5 {
                                ring += 1;
                                direction = 0;
                                step_water_seed(
                                    &mut row,
                                    &mut column,
                                    4,
                                    geometry.wraps_horizontally(),
                                );
                            }
                        }
                        step_water_seed(
                            &mut row,
                            &mut column,
                            direction,
                            geometry.wraps_horizontally(),
                        );
                    }
                    column_base += 108;
                }
            }
            row_base += 108;
        }
    }

    loop {
        let mut changed = 0;
        for tile in 0..TILE_COUNT {
            if labels[tile] == -1 {
                for direction in 0..6 {
                    if let Some(neighbor) = full_neighbor(geometry, tile, direction) {
                        let label = labels[neighbor];
                        if (0..0x400).contains(&label) {
                            labels[tile] = label + 0x400;
                            changed += 1;
                        }
                    }
                }
            }
        }
        for label in &mut labels {
            if *label > 0x3ff {
                *label -= 0x400;
            }
        }
        if changed == 0 {
            break;
        }
    }
    for (tile, label) in tiles.iter_mut().zip(labels) {
        if label >= 0 {
            tile.owner_nation = (label + 23) as i8;
        }
    }
}

fn step_water_seed(
    row: &mut i32,
    column: &mut i32,
    direction: i32,
    wraps_horizontally: bool,
) -> bool {
    if direction == 4 || (direction > 2 && *row & 1 == 0) {
        *column -= 1;
        if *column < 0 {
            if !wraps_horizontally {
                return false;
            }
            *column = 107;
        }
    } else if direction == 1 || (direction < 3 && *row & 1 != 0) {
        *column += 1;
        if *column > 107 {
            if !wraps_horizontally {
                return false;
            }
            *column = 0;
        }
    }
    if direction == 5 || direction == 0 {
        *row -= 1;
        if *row < 0 {
            return false;
        }
    } else if direction == 3 || direction == 2 {
        *row += 1;
        if *row > 59 {
            return false;
        }
    }
    true
}

fn apply_scenario_keyword_override(
    tiles: &mut [GeneratedTerrainTile],
    tag: &[u8],
    rng: &mut RetailLcg,
) {
    enum Override {
        Ninety(i8, Option<i8>),
        Mirkwood,
        Eighty(i8),
        Eclectia,
    }
    let override_kind = if keyword_matches(tag, b"Dune") {
        Some(Override::Ninety(DESERT, None))
    } else if keyword_matches(tag, b"Congo") {
        Some(Override::Ninety(FOREST, Some(13)))
    } else if keyword_matches(tag, b"Mirkwood") {
        Some(Override::Mirkwood)
    } else if keyword_matches(tag, b"Yucatan") || keyword_matches(tag, b"Siberia") {
        Some(Override::Ninety(FOREST, Some(15)))
    } else if keyword_matches(tag, b"Antarctica") {
        Some(Override::Ninety(DESERT, Some(12)))
    } else if keyword_matches(tag, b"Kansas") {
        Some(Override::Ninety(PLAINS, None))
    } else if keyword_matches(tag, b"Eden") {
        Some(Override::Ninety(FARMLAND, None))
    } else if keyword_matches(tag, b"Everglades") {
        Some(Override::Eighty(SWAMP))
    } else if keyword_matches(tag, b"Nepal") {
        Some(Override::Eighty(MOUNTAIN))
    } else if keyword_matches(tag, b"Scotland") {
        Some(Override::Eighty(HILLS))
    } else if keyword_matches(tag, b"Eclectia") {
        Some(Override::Eclectia)
    } else {
        None
    };
    let Some(override_kind) = override_kind else {
        return;
    };
    for tile in tiles {
        let bucket = {
            let mut value = tile.owner_nation % 7;
            if value > 4 {
                value += 1;
            }
            value
        };
        if tile.terrain_kind == WATER {
            continue;
        }
        match override_kind {
            Override::Ninety(terrain, gate) => {
                if !rng.next_sample_15().is_multiple_of(10) {
                    tile.terrain_kind = terrain;
                    if let Some(gate) = gate {
                        tile.gate_flag = gate;
                    }
                }
            }
            Override::Mirkwood => {
                if !rng.next_sample_15().is_multiple_of(10) {
                    tile.terrain_kind = FOREST;
                    tile.gate_flag = (((!((rng.advance() >> 12) as u8) & 1) << 1) | 13) as i8;
                }
            }
            Override::Eighty(terrain) => {
                if !rng.next_sample_15().is_multiple_of(5) {
                    tile.terrain_kind = terrain;
                }
            }
            Override::Eclectia => {
                if !rng.next_sample_15().is_multiple_of(5) {
                    tile.terrain_kind = bucket;
                    if bucket == FOREST {
                        tile.gate_flag = 15;
                    }
                }
            }
        }
    }
}

fn validate_seed_candidates(
    tiles: &[GeneratedTerrainTile],
    geometry: MapGeometry,
    rng: &mut RetailLcg,
) -> (bool, [i32; RANDOM_MAP_CLASS_COUNT]) {
    let mut found = [false; RANDOM_MAP_CLASS_COUNT];
    let mut candidates = [0; RANDOM_MAP_CLASS_COUNT];
    for (tile_index, tile) in tiles.iter().enumerate() {
        let class = tile.owner_nation;
        if !(0..RANDOM_MAP_CLASS_COUNT as i8).contains(&class) || found[class as usize] {
            continue;
        }
        let mut has_candidate = false;
        for direction in 0..6 {
            let Some(neighbor) = full_neighbor(geometry, tile_index, direction) else {
                continue;
            };
            if tiles[neighbor].terrain_kind != WATER {
                continue;
            }
            has_candidate = true;
            for water_direction in 0..6 {
                if let Some(water_neighbor) = full_neighbor(geometry, neighbor, water_direction) {
                    let neighbor_class = tiles[water_neighbor].owner_nation;
                    if neighbor_class < RANDOM_MAP_CLASS_COUNT as i8 && neighbor_class != class {
                        has_candidate = false;
                        break;
                    }
                }
            }
            if has_candidate {
                let slot = &mut candidates[class as usize];
                if *slot == 0 || rng.next_sample_15() % 5 == 3 {
                    *slot = neighbor as i32;
                }
                break;
            }
        }
        if has_candidate && matches!(tile.terrain_kind, PLAINS | FARMLAND | FOREST | DESERT) {
            found[class as usize] = true;
        }
    }
    (found.into_iter().all(|value| value), candidates)
}

fn keyword_matches(text: &[u8], keyword: &[u8]) -> bool {
    text.starts_with(keyword) && matches!(text.get(keyword.len()).copied().unwrap_or(0), 0 | b' ')
}

fn full_neighbor(geometry: MapGeometry, tile: usize, direction: usize) -> Option<usize> {
    let direction = crate::HexDirection::ALL[direction];
    geometry
        .neighbor(TileId::new(tile as u16), direction)
        .map(|tile| usize::from(tile.get()))
}

fn coarse_class(coarse: &CoarseMap, index: i32) -> i16 {
    coarse
        .grid
        .flattened()
        .nth(index as usize)
        .map(i16::from)
        .expect("retail coarse neighbor index is valid")
}

fn coarse_neighbor(cell: i32, direction: usize) -> i32 {
    const EVEN: [i32; 6] = [1, 1, 1, 0, -1, 0];
    const ODD: [i32; 6] = [0, 1, 0, -1, -1, -1];
    const ROW: [i32; 6] = [-1, 0, 1, 1, 0, -1];
    let row = cell / 27;
    let mut column = cell % 27
        + if row & 1 == 0 {
            EVEN[direction]
        } else {
            ODD[direction]
        };
    column = column.rem_euclid(27);
    let row = row + ROW[direction];
    let result = column + row * 27;
    if !(0..405).contains(&result) {
        -1
    } else {
        result
    }
}

fn fine_cell_base(coarse_index: i32) -> i32 {
    let row = coarse_index / 27;
    let column = coarse_index % 27;
    column * 4 + row * 4 * 108 - if row & 1 != 0 { 2 } else { 0 }
}

fn copy_tile(tiles: &mut [GeneratedTerrainTile], destination: i32, source: i32) {
    let source = tiles[usize::try_from(source).expect("retail template source became negative")];
    tiles[usize::try_from(destination).expect("retail template destination became negative")] =
        source;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn final_tile_hash(tiles: &[GeneratedTerrainTile]) -> u32 {
        tiles.iter().fold(0x811c_9dc5, |hash, tile| {
            let province = tile.province_index.to_le_bytes();
            [
                tile.terrain_kind as u8,
                tile.river_sprite_code,
                tile.owner_nation as u8,
                tile.gate_flag as u8,
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
    fn keyword_matching_requires_exact_case_and_a_retail_boundary() {
        assert!(keyword_matches(b"Dune", b"Dune"));
        assert!(keyword_matches(b"Dune @^>d", b"Dune"));
        assert!(!keyword_matches(b"dune", b"Dune"));
        assert!(!keyword_matches(b"Dunes", b"Dune"));
        assert!(!keyword_matches(b"prefix Dune", b"Dune"));
    }

    #[test]
    fn keyword_overrides_preserve_conditional_draw_order() {
        let original = [
            GeneratedTerrainTile {
                terrain_kind: PLAINS,
                river_sprite_code: 0,
                owner_nation: 0,
                gate_flag: -1,
                province_index: 0,
            },
            GeneratedTerrainTile {
                terrain_kind: PLAINS,
                river_sprite_code: 0,
                owner_nation: 1,
                gate_flag: -1,
                province_index: 1,
            },
            GeneratedTerrainTile {
                terrain_kind: PLAINS,
                river_sprite_code: 0,
                owner_nation: 6,
                gate_flag: -1,
                province_index: 2,
            },
            GeneratedTerrainTile {
                terrain_kind: WATER,
                river_sprite_code: 0,
                owner_nation: 23,
                gate_flag: -1,
                province_index: -1,
            },
        ];

        let mut dune_tiles = original;
        let mut dune_rng = RetailLcg::from_state(2);
        apply_scenario_keyword_override(&mut dune_tiles, b"Dune", &mut dune_rng);
        assert_eq!(
            dune_tiles.map(|tile| tile.terrain_kind),
            [DESERT, DESERT, PLAINS, WATER]
        );
        assert_eq!(dune_rng.state(), 0xd54a_6449);

        let mut mirkwood_tiles = original;
        let mut mirkwood_rng = RetailLcg::from_state(2);
        apply_scenario_keyword_override(&mut mirkwood_tiles, b"Mirkwood", &mut mirkwood_rng);
        assert_eq!(
            mirkwood_tiles.map(|tile| (tile.terrain_kind, tile.gate_flag)),
            [(FOREST, 13), (PLAINS, -1), (FOREST, 13), (WATER, -1)]
        );
        assert_eq!(mirkwood_rng.state(), 0x56ce_5f37);

        let mut eclectia_tiles = original;
        let mut eclectia_rng = RetailLcg::from_state(2);
        apply_scenario_keyword_override(&mut eclectia_tiles, b"Eclectia", &mut eclectia_rng);
        assert_eq!(
            eclectia_tiles.map(|tile| (tile.terrain_kind, tile.gate_flag)),
            [(PLAINS, -1), (FOREST, 15), (PLAINS, -1), (WATER, -1)]
        );
        assert_eq!(eclectia_rng.state(), 0xd54a_6449);
    }

    #[test]
    fn seed_one_generates_the_retail_final_map_and_rng_state() {
        let mut rng = RetailLcg::from_state(3_122_877_655);
        let generated = generate_random_map(
            b"ordinary",
            RetailTopologyByte::from_retail_byte(0),
            &mut rng,
        );
        assert_eq!(generated.provinces.len(), 120);
        assert_eq!(generated.tiles.len(), TILE_COUNT);
        let mut terrain_counts = [0_u32; 8];
        for tile in &generated.tiles {
            terrain_counts[usize::try_from(tile.terrain_kind).unwrap()] += 1;
        }
        assert_eq!(terrain_counts, [440, 252, 250, 156, 150, 4_538, 343, 351]);
        assert_eq!(
            generated.seed_candidate_tiles,
            [
                2_987, 4_153, 2_044, 1_666, 3_319, 284, 259, 1_162, 245, 1_529, 1_863, 1_994,
                1_698, 2_838, 2_013, 3_775, 4_732, 2_836, 2_680, 3_813, 3_833, 4_060, 4_608,
            ]
        );
        assert_eq!(final_tile_hash(&generated.tiles), 0xbcd9_91d8);
        assert_eq!(rng.state(), 0x46a4_5026);
    }

    #[cfg(feature = "differential-trace")]
    #[test]
    fn trace_preserves_retail_stage_boundaries_when_requested() {
        let mut rng = RetailLcg::from_state(3_122_877_655);
        let trace = trace_random_map_terrain(
            b"ordinary",
            RetailTopologyByte::from_retail_byte(0),
            &mut rng,
        );
        let final_attempt = trace.attempts.last().unwrap();
        assert_eq!(trace.initial_map_lcg, 0xba23_54d7);
        assert_eq!(trace.attempts.len(), 1);
        assert_eq!(
            final_attempt.after_keyword,
            RandomMapTerrainStageTrace {
                map_lcg: 0xd938_b2f4,
                tile_hash: 0x099d_e4c5,
                terrain_counts: [440, 252, 250, 156, 150, 4_538, 343, 351],
                river_tile_count: 72,
            }
        );
        assert!(final_attempt.accepted);
        assert_eq!(final_attempt.rotation_column, 26);
        assert_eq!(final_attempt.map_lcg_after_validation, 0x46a4_5026);
        assert_eq!(trace.final_map_lcg, 0x46a4_5026);
        assert_eq!(rng.state(), trace.final_map_lcg);
    }
}
