use crate::{EXPANDED_MAP_WIDTH, MapGeometry, RetailLcg};

use super::{
    DESERT, FARMLAND, FOREST, GeneratedTerrainTileScratch, HILLS, MOUNTAIN, PLAINS,
    RandomMapTuning, SWAMP, TILE_COUNT, WATER, full_neighbor,
};

const RIVER_CONNECTION: [[u8; 6]; 6] = [
    [0, 0, 1, 2, 3, 0],
    [0, 0, 0, 4, 5, 6],
    [1, 0, 0, 0, 7, 8],
    [2, 4, 0, 0, 0, 9],
    [3, 5, 7, 0, 0, 0],
    [0, 6, 8, 9, 0, 0],
];

pub(super) fn place_terrain_features(
    tiles: &mut [GeneratedTerrainTileScratch],
    geometry: MapGeometry,
    tuning: RandomMapTuning,
    rng: &mut RetailLcg,
) {
    let mut mountains = tuning.mountain_quota;
    while mountains > 0 {
        let retry_budget = (rng.next_sample_15() % 12) as i32 + 3;
        let tile = loop {
            let candidate = (rng.next_sample_15() % TILE_COUNT as u32) as usize;
            if tiles[candidate].terrain_kind == PLAINS {
                break candidate;
            }
        };
        let direction = (rng.next_sample_15() % 6) as usize;
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
        let tile = (rng.next_sample_15() % TILE_COUNT as u32) as usize;
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
    tiles: &mut [GeneratedTerrainTileScratch],
    geometry: MapGeometry,
    tile: usize,
    retry_budget: i32,
    direction: usize,
    rng: &mut RetailLcg,
) -> i32 {
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
    let next_tile = full_neighbor(geometry, tile, next_direction);
    let mut placed = 1;
    if retry_budget != 1
        && let Some(next_tile) = next_tile
    {
        placed += seed_mountain_range(tiles, geometry, next_tile, retry_budget - 1, direction, rng);
    }
    placed
}

fn create_deserts(
    tiles: &mut [GeneratedTerrainTileScratch],
    geometry: MapGeometry,
    rng: &mut RetailLcg,
) {
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
    tiles: &mut [GeneratedTerrainTileScratch],
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
                            let Some(neighbor) = full_neighbor(geometry, logical_tile, direction)
                            else {
                                continue;
                            };
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
    tiles: &mut [GeneratedTerrainTileScratch],
    geometry: MapGeometry,
    tile: usize,
    retry_budget: i32,
    urgent: bool,
    rng: &mut RetailLcg,
) -> i32 {
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
        let neighbor = full_neighbor(geometry, tile, direction);
        // Retail always draws, then spreads when the roll hits, even if the hex
        // neighbor is off the north or south edge.
        if rng.next_sample_15() % 100 < 70
            && remaining != 0
            && let Some(neighbor) = neighbor
        {
            remaining -= place_forest(tiles, geometry, neighbor, 1, urgent, rng);
        }
    }
    retry_budget - remaining
}

fn create_rivers(
    tiles: &mut [GeneratedTerrainTileScratch],
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
            let mountain_neighbor = full_neighbor(geometry, tile, direction)
                .is_some_and(|neighbor| tiles[neighbor].terrain_kind == MOUNTAIN);
            if !mountain_neighbor || direction == first_direction {
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
    tiles: &mut [GeneratedTerrainTileScratch],
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
    let Some(neighbor) = full_neighbor(geometry, tile, next_direction) else {
        return false;
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MapTopology;

    #[test]
    fn north_edge_forest_spread_still_draws_for_off_map_neighbors() {
        let geometry = MapGeometry::new(MapTopology::Wrapping);
        let mut tiles = vec![
            GeneratedTerrainTileScratch {
                terrain_kind: PLAINS,
                river_sprite_code: 0,
                owner_nation: 0,
                gate_flag: -1,
                province_index: 0,
            };
            TILE_COUNT
        ];
        let mut rng = RetailLcg::from_state(1);
        assert_eq!(place_forest(&mut tiles, geometry, 0, 1, false, &mut rng), 1);
        let mut expected = RetailLcg::from_state(1);
        for _ in 0..6 {
            let _ = expected.next_sample_15();
        }
        assert_eq!(rng, expected);
        assert_eq!(tiles[0].terrain_kind, FOREST);
    }
}
