use imperialism_core::*;
use imperialism_formats::*;

use super::{RIVER_MASK_TRANSPARENT_INDEX, TILE_SIZE, VIEWPORT_TILE_SPAN};

// Source-byte offsets into retail's 51-cell strategic terrain strip.
const BASE_LAND_OFFSETS: [[u16; 2]; 16] = [
    [0x140, 0x140],
    [0, 0],
    [0x200, 0x200],
    [0x240, 0x240],
    [0x300, 0x300],
    [0x1c0, 0x1c0],
    [0x3c0, 0x3c0],
    [0x700, 0x700],
    [0x080, 0x080],
    [0x0c0, 0x2c0],
    [0x100, 0x100],
    [0x180, 0x180],
    [0xb80, 0xb80],
    [0x040, 0x040],
    [0, 0],
    [0xc00, 0xc00],
];
pub(super) const BASE_WATER_OFFSETS: [u16; 8] = [0x140, 0x980, 0x9c0, 0xa00, 0xa40, 0, 0, 0];
const PRIMARY_TRANSITION_OFFSETS: [[u16; 5]; 16] = [
    [0x140, 0x140, 0, 0, 0],
    [0, 0, 0, 0, 0],
    [0x280, 0x280, 0, 0, 0],
    [0x340, 0x340, 0, 0, 0],
    [0x300, 0x300, 0, 0, 0],
    [0x680, 0x680, 0, 0, 0],
    [0x940, 0x940, 0, 0, 0],
    [0x740, 0x740, 0, 0, 0],
    [0x440, 0x440, 0, 0, 0],
    [0x4c0, 0x780, 0, 0, 0],
    [0x540, 0x540, 0, 0, 0],
    [0x640, 0x6c0, 0x900, 0x380, 0xbc0],
    [0xbc0, 0, 0, 0, 0x400],
    [0x400, 0, 0, 0, 0],
    [0, 0, 0, 0, 0xc40],
    [0xc40, 0, 0, 0, 0],
];
const SECONDARY_TRANSITION_OFFSETS: [[u16; 2]; 16] = [
    [0, 0],
    [0, 0],
    [0, 0],
    [0, 0],
    [0, 0],
    [0, 0],
    [0, 0],
    [0x800, 0x800],
    [0x480, 0x480],
    [0x500, 0x7c0],
    [0, 0],
    [0, 0],
    [0, 0],
    [0, 0],
    [0, 0],
    [0, 0],
];
pub(super) fn compose_strategic_base_tile(
    state: &GameState,
    tile: TileId,
    terrain_pictures: &[IndexedPicture],
    river_masks: &[IndexedPicture],
) -> Vec<u8> {
    let tile_state = state.map()[tile];
    let center_column = {
        let (_, origin_column) = state.map().geometry().row_column(state.map_view_origin());
        (i32::from(origin_column) + VIEWPORT_TILE_SPAN / 2)
            .rem_euclid(i32::from(STRATEGIC_MAP_WIDTH))
    };
    let (_, tile_column) = state.map().geometry().row_column(tile);
    // Retail's stored flag is inverted: this seam substitution belongs to Rust's bounded map.
    let wrapped_seam = state.map().topology == MapTopology::Bounded
        && ((tile_column == 0 && center_column > 54)
            || (tile_column == STRATEGIC_MAP_WIDTH - 1 && center_column < 54));
    if wrapped_seam {
        return terrain_pictures[frame_for_offset(0xc80)].pixels.clone();
    }

    let rendering = tile_state.rendering;
    let base_offset = if tile_state.terrain == TerrainKind::Water {
        let variant = if rendering.coast_or_secondary_mask != 0 {
            0
        } else {
            usize::from(rendering.sprite_variant)
        };
        BASE_WATER_OFFSETS[variant]
    } else {
        let subtype = usize::try_from(tile_state.gate)
            .expect("rendered land tile subtype must not be negative");
        let variant = if tile_state.terrain == TerrainKind::Mountain {
            usize::from(rendering.sprite_variant)
        } else {
            0
        };
        BASE_LAND_OFFSETS[subtype][variant]
    };
    let mut pixels = terrain_pictures[frame_for_offset(base_offset)]
        .pixels
        .clone();

    if tile_state.terrain != TerrainKind::Water {
        let subtype = usize::try_from(tile_state.gate)
            .expect("rendered land tile subtype must not be negative");
        let variant = usize::from(rendering.sprite_variant);
        for direction in 0..6 {
            let direction_bit = 1 << direction;
            let transition_offset = if rendering.transition_mask & direction_bit != 0 {
                PRIMARY_TRANSITION_OFFSETS[subtype][variant]
            } else if rendering.coast_or_secondary_mask & direction_bit != 0
                && tile_state.terrain != TerrainKind::Desert
            {
                SECONDARY_TRANSITION_OFFSETS[subtype][variant]
            } else {
                continue;
            };
            let source = &terrain_pictures[frame_for_offset(transition_offset)].pixels;
            copy_transition_wedge(direction, source, &mut pixels);
        }
    }

    if tile_state.terrain == TerrainKind::Water && rendering.coast_or_secondary_mask != 0 {
        compose_water_coast_corners(rendering, terrain_pictures, &mut pixels);
    } else if let Some(river_sprite) = rendering.river_sprite {
        compose_river(river_sprite, river_masks, &mut pixels);
    }
    pixels
}

fn compose_water_coast_corners(
    rendering: TileRendering,
    terrain_pictures: &[IndexedPicture],
    pixels: &mut [u8],
) {
    let adjacency_mask = rendering.coast_or_secondary_mask;
    let river_sprite = rendering.river_sprite.map(RiverSprite::retail);
    for corner in 0..6 {
        let previous_direction = (corner + 5) % 6;
        let corner_bits = (1 << previous_direction) | (1 << corner);
        if adjacency_mask & corner_bits == 0 {
            continue;
        }
        let variant = coast_corner_variant(adjacency_mask, corner);
        if variant == 0 {
            continue;
        }
        let frame = if uses_river_mouth_coast_frame(corner, river_sprite) {
            let extra_variant = usize::from(
                variant == 1 && matches!(river_sprite, Some(0x33 | 0x36 | 0x39 | 0x3a)),
            );
            usize::from(variant) + 41 + extra_variant * 3
        } else if rendering.sprite_variant & (1 << corner) != 0 {
            usize::from(variant) + 32
        } else {
            usize::from(variant) + 21
        };
        copy_coast_corner(corner, &terrain_pictures[frame].pixels, pixels);
    }
}

pub(super) fn coast_corner_variant(adjacency_mask: u8, corner: usize) -> u8 {
    // Retail's 64x7 lookup table is this adjacent-bit rule plus one explicit zero entry.
    if adjacency_mask == 0x05 && corner == 1 {
        return 0;
    }
    let previous_direction = (corner + 5) % 6;
    let previous = adjacency_mask & (1 << previous_direction) != 0;
    let current = adjacency_mask & (1 << corner) != 0;
    match (previous, current) {
        (false, false) => 0,
        (true, true) => 1,
        (false, true) if corner & 1 == 0 => 2,
        (true, false) if previous_direction & 1 == 0 => 2,
        _ => 3,
    }
}

pub(super) fn uses_river_mouth_coast_frame(corner: usize, river_sprite: Option<u8>) -> bool {
    matches!(
        (corner, river_sprite),
        (1, Some(0x33 | 0x34))
            | (2, Some(0x35 | 0x36))
            | (3, Some(0x36 | 0x37))
            | (4, Some(0x37 | 0x39))
            | (5, Some(0x38 | 0x3a))
    )
}

fn compose_river(river_sprite: RiverSprite, river_masks: &[IndexedPicture], pixels: &mut [u8]) {
    let mut normalized = river_sprite.retail();
    if normalized > 0x1a {
        normalized -= 0x10;
    }
    let mask = usize::from(normalized - 0x0b);
    apply_tile_mask(&river_masks[mask].pixels, pixels);
}

pub(super) fn apply_tile_mask(source: &[u8], pixels: &mut [u8]) {
    for (&source_pixel, destination_pixel) in source.iter().zip(pixels) {
        if source_pixel != RIVER_MASK_TRANSPARENT_INDEX {
            *destination_pixel = source_pixel;
        }
    }
}
pub(super) fn frame_for_offset(offset: u16) -> usize {
    assert_eq!(offset % TILE_SIZE as u16, 0);
    usize::from(offset / TILE_SIZE as u16)
}

fn copy_transition_wedge(direction: usize, source: &[u8], destination: &mut [u8]) {
    match direction {
        0 => {
            for row in 0x20..0x40 {
                copy_tile_span(source, destination, row, 0x20, row - 0x1f);
            }
        }
        1 => {
            for row in 1..0x20 {
                copy_tile_span(source, destination, row, 0x40 - row, row);
            }
            for row in 0x20..0x3f {
                copy_tile_span(source, destination, row, row + 1, 0x3f - row);
            }
        }
        2 => {
            for row in 0..0x20 {
                copy_tile_span(source, destination, row, 0x20, 0x20 - row);
            }
        }
        3 => {
            for row in 0..0x20 {
                copy_tile_span(source, destination, row, row, 0x20 - row);
            }
        }
        4 => {
            for row in 0..0x20 {
                copy_tile_span(source, destination, row, 0, row + 1);
            }
            for row in 0x20..0x40 {
                copy_tile_span(source, destination, row, 0, 0x40 - row);
            }
        }
        5 => {
            for row in 0x21..0x40 {
                copy_tile_span(source, destination, row, 0x40 - row, row - 0x20);
            }
        }
        _ => unreachable!("strategic tile has six transition directions"),
    }
}

fn copy_coast_corner(corner: usize, source: &[u8], destination: &mut [u8]) {
    match corner {
        0 => {
            for row in 0x20..0x40 {
                let half_row = (row - 0x20) / 2;
                copy_tile_span(source, destination, row, 0x1f - half_row, 2 + half_row * 2);
            }
        }
        1 => {
            for row in 0x20..0x40 {
                let first_column = 0x20 + (row - 0x20) / 2;
                copy_tile_span(source, destination, row, first_column, 0x40 - first_column);
            }
        }
        2 => {
            for row in 0..0x20 {
                let mut first_column = 0x30 - (row / 8) * 4;
                if row & 2 != 0 {
                    first_column -= 1;
                }
                copy_tile_span(source, destination, row, first_column, 0x40 - first_column);
            }
        }
        3 => {
            for row in 0..0x20 {
                let first_column = 0x10 + row / 2;
                let pair_in_group = (row / 2) & 3;
                let end_column = 0x30 + ((4 - pair_in_group) & 3);
                copy_tile_span(
                    source,
                    destination,
                    row,
                    first_column,
                    end_column - first_column,
                );
            }
        }
        4 => {
            for row in 0..0x20 {
                copy_tile_span(source, destination, row, 0, 0x10 + row / 2);
            }
        }
        5 => {
            for row in 0x20..0x40 {
                copy_tile_span(source, destination, row, 0, 0x20 - (row - 0x20) / 2);
            }
        }
        _ => unreachable!("strategic tile has six coast corners"),
    }
}

fn copy_tile_span(
    source: &[u8],
    destination: &mut [u8],
    dib_row: usize,
    first_column: usize,
    pixel_count: usize,
) {
    // Retail's atlas and map surface are positive-height DIBs, so its span routines count rows
    // bottom-up. IndexedPicture normalizes both to top-down order.
    let row = TILE_SIZE as usize - 1 - dib_row;
    let start = row * TILE_SIZE as usize + first_column;
    destination[start..start + pixel_count].copy_from_slice(&source[start..start + pixel_count]);
}
