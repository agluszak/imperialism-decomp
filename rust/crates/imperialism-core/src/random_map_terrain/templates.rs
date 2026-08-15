use crate::random_map::CoarseMap;
use crate::{MapGeometry, RetailLcg};

use super::{GeneratedTerrainTileScratch, TILE_COUNT, full_neighbor};

pub(super) fn randomize_templates_and_smooth(
    tiles: &mut [GeneratedTerrainTileScratch],
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
    tiles: &mut [GeneratedTerrainTileScratch],
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
    tiles: &mut [GeneratedTerrainTileScratch],
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
            if let Some(neighbor) = full_neighbor(geometry, tile_index, direction) {
                tiles[tile_index] = tiles[neighbor];
            }
        }
    }
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

fn copy_tile(tiles: &mut [GeneratedTerrainTileScratch], destination: i32, source: i32) {
    let source = tiles[usize::try_from(source).expect("retail template source became negative")];
    tiles[usize::try_from(destination).expect("retail template destination became negative")] =
        source;
}
