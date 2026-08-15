use crate::{
    EXPANDED_MAP_HEIGHT, EXPANDED_MAP_WIDTH, MapGeometry, RANDOM_MAP_CLASS_COUNT, RetailLcg, TileId,
};

use super::{
    DESERT, FARMLAND, FOREST, GeneratedTerrainTileScratch, HILLS, MOUNTAIN, PLAINS, SWAMP,
    TILE_COUNT, WATER, full_neighbor,
};

pub(super) fn rotate_map_columns(tiles: &mut [GeneratedTerrainTileScratch]) -> usize {
    let counts: [usize; EXPANDED_MAP_WIDTH] = std::array::from_fn(|column| {
        (0..EXPANDED_MAP_HEIGHT)
            .filter(|row| tiles[row * EXPANDED_MAP_WIDTH + column].terrain_kind == WATER)
            .count()
    });
    let mut window = [
        counts[EXPANDED_MAP_WIDTH - 3],
        counts[EXPANDED_MAP_WIDTH - 2],
        counts[EXPANDED_MAP_WIDTH - 1],
    ];
    let mut total = window.iter().sum::<usize>();
    let mut position = 0;
    let mut best_density = 0;
    let mut best_column = 0;
    for (column, count) in counts.iter().copied().enumerate() {
        total += count;
        if best_density < total {
            best_column = column;
            best_density = total;
        }
        total -= window[position];
        window[position] = count;
        position = (position + 1) % 3;
    }
    if counts[best_column] == 0 {
        let mut left = (best_column + EXPANDED_MAP_WIDTH - 1) % EXPANDED_MAP_WIDTH;
        let mut right = (best_column + 1) % EXPANDED_MAP_WIDTH;
        while counts[left] == 0 {
            left = (left + EXPANDED_MAP_WIDTH - 1) % EXPANDED_MAP_WIDTH;
        }
        while counts[right] == 0 {
            right = (right + 1) % EXPANDED_MAP_WIDTH;
        }
        left = (left + 1) % EXPANDED_MAP_WIDTH;
        right = (right + EXPANDED_MAP_WIDTH - 1) % EXPANDED_MAP_WIDTH;
        best_column = if right < left {
            ((left + EXPANDED_MAP_WIDTH + right) / 2) % EXPANDED_MAP_WIDTH
        } else {
            (right + left) / 2
        };
    }
    let source = tiles.to_vec();
    for destination_column in 0..EXPANDED_MAP_WIDTH {
        let source_column =
            (best_column + EXPANDED_MAP_WIDTH - 1 + destination_column) % EXPANDED_MAP_WIDTH;
        for row in 0..EXPANDED_MAP_HEIGHT {
            tiles[row * EXPANDED_MAP_WIDTH + destination_column] =
                source[row * EXPANDED_MAP_WIDTH + source_column];
        }
    }
    best_column
}

/// Runs the water-region seed and flood subpass that retail places between map rotation and
/// keyword overrides. Border/span/merge follows immediately in [`generate_random_map_impl`];
/// this subpass must live here because it owns both the water owner codes and the intervening LCG
/// draws observed by every keyword and final seed-candidate validation.
pub(super) fn generate_water_region_ids(
    tiles: &mut [GeneratedTerrainTileScratch],
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
                        if let Some(tile) = tile
                            && labels[tile] == -1
                        {
                            labels[tile] = region_count;
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

fn step_water_seed(row: &mut i32, column: &mut i32, direction: i32, wraps_horizontally: bool) {
    if direction == 4 || (direction > 2 && *row & 1 == 0) {
        *column -= 1;
        if *column < 0 {
            if !wraps_horizontally {
                return;
            }
            *column = 107;
        }
    } else if direction == 1 || (direction < 3 && *row & 1 != 0) {
        *column += 1;
        if *column > 107 {
            if !wraps_horizontally {
                return;
            }
            *column = 0;
        }
    }
    if direction == 5 || direction == 0 {
        *row -= 1;
    } else if direction == 3 || direction == 2 {
        *row += 1;
    }
}

pub(super) fn apply_scenario_keyword_override(
    tiles: &mut [GeneratedTerrainTileScratch],
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

pub(super) fn validate_seed_candidates(
    tiles: &[GeneratedTerrainTileScratch],
    geometry: MapGeometry,
    rng: &mut RetailLcg,
) -> (bool, [TileId; RANDOM_MAP_CLASS_COUNT]) {
    let mut found = [false; RANDOM_MAP_CLASS_COUNT];
    let mut candidates = [TileId::new(0); RANDOM_MAP_CLASS_COUNT];
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
                if slot.get() == 0 || rng.next_sample_15() % 5 == 3 {
                    *slot = TileId::new(neighbor as u16);
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

#[cfg(test)]
mod tests {
    use super::*;

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
            GeneratedTerrainTileScratch {
                terrain_kind: PLAINS,
                river_sprite_code: 0,
                owner_nation: 0,
                gate_flag: -1,
                province_index: 0,
            },
            GeneratedTerrainTileScratch {
                terrain_kind: PLAINS,
                river_sprite_code: 0,
                owner_nation: 1,
                gate_flag: -1,
                province_index: 1,
            },
            GeneratedTerrainTileScratch {
                terrain_kind: PLAINS,
                river_sprite_code: 0,
                owner_nation: 6,
                gate_flag: -1,
                province_index: 2,
            },
            GeneratedTerrainTileScratch {
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
}
