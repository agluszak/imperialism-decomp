use imperialism_core::*;
use imperialism_formats::IndexedPicture;

use crate::ui::retail_palette::major_nation_palette;
use crate::ui::retail_raster::IndexedRasterExt;

pub(super) const CITY_BORDER_PALETTE: u8 = 0x13;
pub(super) const MINOR_NATION_BORDER_PALETTE: u8 = 0x0a;
pub(super) fn compose_strategic_borders(
    state: &GameState,
    tile: TileId,
    pixels: &mut IndexedPicture,
) {
    let tile_state = state.map()[tile];
    if tile_state.owner_border_mask != 0 {
        if tile_state.terrain != TerrainKind::Water {
            draw_nation_border_segments(state, tile, pixels);
        } else if tile_state.rendering.coast_or_secondary_mask != 0 {
            draw_sea_zone_borders(state, tile, pixels);
        }
    }
    if tile_state.terrain != TerrainKind::Water && tile_state.city_border_mask != 0 {
        draw_city_border_segments(state, tile, pixels);
    }
}

fn draw_nation_border_segments(state: &GameState, tile: TileId, pixels: &mut IndexedPicture) {
    let mask = state.map()[tile].owner_border_mask;
    let owner = border_palette(state.map()[tile].owner_nation);
    for_each_land_border_segment(state, tile, mask, |relation, neighbor| {
        draw_border(pixels, relation, owner, neighbor_palette(state, neighbor));
    });
}

fn draw_city_border_segments(state: &GameState, tile: TileId, pixels: &mut IndexedPicture) {
    let mask = state.map()[tile].city_border_mask;
    for_each_land_border_segment(state, tile, mask, |relation, _neighbor| {
        draw_guide_pattern(pixels, relation, 0, CITY_BORDER_PALETTE, 1);
    });
}

fn for_each_land_border_segment(
    state: &GameState,
    tile: TileId,
    mask: u8,
    mut visit: impl FnMut(u8, Option<TileId>),
) {
    let neighbors = HexDirectionTable::from_array(state.map().geometry().neighbors(tile));
    let direction1 = mask & 2 != 0;

    if direction1 {
        if mask & 1 == 0 {
            visit(2, neighbors[HexDirection::East]);
        } else {
            visit(1, neighbors[HexDirection::East]);
            if mask & 0x40 != 0 {
                visit(3, neighbors[HexDirection::NorthEast]);
            }
        }
        if mask & 4 == 0 {
            visit(6, neighbors[HexDirection::East]);
        } else {
            visit(7, neighbors[HexDirection::SouthEast]);
            if mask & 0x80 != 0 {
                visit(5, neighbors[HexDirection::SouthEast]);
            }
        }
    }

    if mask & 1 != 0 {
        visit(0, neighbors[HexDirection::NorthEast]);
        if !direction1 {
            visit(3, neighbors[HexDirection::NorthEast]);
        }
    }
    if mask & 4 != 0 {
        visit(9, neighbors[HexDirection::SouthEast]);
        if !direction1 {
            visit(5, neighbors[HexDirection::SouthEast]);
        }
    }

    if neighbor_is_water(state, neighbors[HexDirection::NorthEast])
        && mask & 0x20 != 0
        && !direction1
    {
        visit(0, neighbors[HexDirection::NorthWest]);
        visit(3, neighbors[HexDirection::NorthWest]);
    }
    if neighbor_is_water(state, neighbors[HexDirection::SouthEast]) && mask & 8 != 0 && !direction1
    {
        visit(5, neighbors[HexDirection::SouthWest]);
        visit(9, neighbors[HexDirection::SouthWest]);
    }
}

fn draw_sea_zone_borders(state: &GameState, tile: TileId, pixels: &mut IndexedPicture) {
    let neighbors = HexDirectionTable::from_array(state.map().geometry().neighbors(tile));
    let pairs = [
        (HexDirection::SouthWest, HexDirection::SouthEast),
        (HexDirection::SouthEast, HexDirection::East),
        (HexDirection::West, HexDirection::SouthWest),
        (HexDirection::NorthWest, HexDirection::NorthEast),
        (HexDirection::NorthEast, HexDirection::East),
        (HexDirection::West, HexDirection::NorthWest),
    ];
    for (index, (first, second)) in pairs.into_iter().enumerate() {
        if !land_tiles_have_different_owners(state, neighbors[first], neighbors[second]) {
            continue;
        }
        let first_color = neighbor_palette(state, neighbors[first]);
        let second_color = neighbor_palette(state, neighbors[second]);
        match index {
            0 => {
                stroke_guide(pixels, (0x16, 0x40), &[(0x16, 0x38)], first_color, 2);
                stroke_guide(pixels, (0x1a, 0x40), &[(0x1a, 0x38)], second_color, 2);
                stroke_guide(
                    pixels,
                    (0x18, 0x40),
                    &[(0x18, 0x38)],
                    CITY_BORDER_PALETTE,
                    1,
                );
            }
            1 => {
                stroke_guide(
                    pixels,
                    (0x36, 0x40),
                    &[(0x36, 0x36), (0x31, 0x2e)],
                    first_color,
                    2,
                );
                stroke_guide(
                    pixels,
                    (0x39, 0x40),
                    &[(0x39, 0x36), (0x34, 0x2a)],
                    second_color,
                    2,
                );
                stroke_guide(
                    pixels,
                    (0x38, 0x40),
                    &[(0x38, 0x36), (0x33, 0x2c)],
                    CITY_BORDER_PALETTE,
                    1,
                );
            }
            2 => {
                stroke_guide(pixels, (0x16, 0x40), &[(0x16, 0x38)], first_color, 2);
                stroke_guide(pixels, (0x19, 0x40), &[(0x19, 0x38)], second_color, 2);
                stroke_guide(
                    pixels,
                    (0x18, 0x40),
                    &[(0x18, 0x38)],
                    CITY_BORDER_PALETTE,
                    1,
                );
            }
            3 => {
                stroke_guide(pixels, (0x16, 0), &[(0x16, 8)], first_color, 2);
                stroke_guide(pixels, (0x1a, 0), &[(0x1a, 8)], second_color, 2);
                stroke_guide(pixels, (0x18, 0), &[(0x18, 8)], CITY_BORDER_PALETTE, 1);
            }
            4 => {
                stroke_guide(pixels, (0x36, 0), &[(0x36, 8)], first_color, 2);
                stroke_guide(pixels, (0x3a, 0), &[(0x3a, 8)], second_color, 2);
                stroke_guide(pixels, (0x38, 0), &[(0x38, 8)], CITY_BORDER_PALETTE, 1);
            }
            5 => {
                stroke_guide(pixels, (0x16, 0), &[(0x16, 8)], first_color, 2);
                stroke_guide(pixels, (0x1a, 0), &[(0x1a, 8)], second_color, 2);
                stroke_guide(pixels, (0x18, 0), &[(0x18, 8)], CITY_BORDER_PALETTE, 1);
            }
            _ => {}
        }
    }
}

fn land_tiles_have_different_owners(
    state: &GameState,
    first: Option<TileId>,
    second: Option<TileId>,
) -> bool {
    let Some(first) = first else {
        return false;
    };
    let Some(second) = second else {
        return false;
    };
    let first = state.map()[first];
    let second = state.map()[second];
    first.terrain != TerrainKind::Water
        && second.terrain != TerrainKind::Water
        && first.owner_nation != second.owner_nation
}

fn neighbor_is_water(state: &GameState, neighbor: Option<TileId>) -> bool {
    neighbor.is_some_and(|neighbor| state.map()[neighbor].terrain == TerrainKind::Water)
}

fn neighbor_palette(state: &GameState, neighbor: Option<TileId>) -> u8 {
    border_palette(neighbor.and_then(|neighbor| state.map()[neighbor].owner_nation))
}

fn border_palette(owner: Option<TileOwnerTag>) -> u8 {
    owner
        .and_then(TileOwnerTag::nation)
        .and_then(MajorNationId::from_nation)
        .map(major_nation_palette)
        .unwrap_or(MINOR_NATION_BORDER_PALETTE)
}

pub(super) fn draw_border(pixels: &mut IndexedPicture, relation: u8, nation_a: u8, nation_b: u8) {
    draw_guide_pattern(pixels, relation, 1, nation_a, 2);
    draw_guide_pattern(pixels, relation, 2, nation_b, 2);
}

fn draw_guide_pattern(
    pixels: &mut IndexedPicture,
    relation: u8,
    variant: i32,
    color: u8,
    pen: i32,
) {
    let families: &[u8] = match relation {
        4 => &[1, 3],
        8 => &[7, 5],
        _ => std::slice::from_ref(&relation),
    };
    for &family in families {
        for path in guide_paths(family, variant) {
            stroke_guide(pixels, path.origin, path.points, color, pen);
        }
    }
}

struct GuidePath {
    origin: (i32, i32),
    points: &'static [(i32, i32)],
}

fn guide_paths(relation: u8, variant: i32) -> &'static [GuidePath] {
    match (relation, variant) {
        (0, 0) => &[GuidePath {
            origin: (0x18, 0),
            points: &[(0x20, 9), (0x26, 6), (0x2c, 8)],
        }],
        (0, 1) => &[GuidePath {
            origin: (0x16, 0),
            points: &[(0x1e, 10), (0x26, 8), (0x2c, 10)],
        }],
        (0, 2) => &[GuidePath {
            origin: (0x1a, 0),
            points: &[(0x22, 6), (0x26, 4), (0x2c, 6)],
        }],
        (1, 0) => &[GuidePath {
            origin: (0x2c, 8),
            points: &[(0x36, 0xd), (0x34, 0x14), (0x3a, 0x19), (0x38, 0x20)],
        }],
        (1, 1) => &[GuidePath {
            origin: (0x2c, 10),
            points: &[(0x34, 0xf), (0x31, 0x14), (0x38, 0x19), (0x36, 0x20)],
        }],
        (1, 2) => &[GuidePath {
            origin: (0x2c, 6),
            points: &[(0x37, 0xb), (0x36, 0x13), (0x3c, 0x19), (0x3a, 0x20)],
        }],
        (2, 0) => &[GuidePath {
            origin: (0x38, 0),
            points: &[(0x36, 9), (0x3a, 0x12), (0x36, 0x19), (0x38, 0x20)],
        }],
        (2, 1) => &[GuidePath {
            origin: (0x36, 0),
            points: &[(0x34, 9), (0x38, 0x12), (0x34, 0x19), (0x36, 0x20)],
        }],
        (2, 2) => &[GuidePath {
            origin: (0x3a, 0),
            points: &[(0x38, 9), (0x3c, 0x12), (0x38, 0x19), (0x3a, 0x20)],
        }],
        (3, 0) => &[GuidePath {
            origin: (0x2c, 8),
            points: &[(0x38, 0)],
        }],
        (3, 1) => &[GuidePath {
            origin: (0x2c, 10),
            points: &[(0x39, 0)],
        }],
        (3, 2) => &[GuidePath {
            origin: (0x2c, 5),
            points: &[(0x37, -3)],
        }],
        (5, 0) => &[GuidePath {
            origin: (0x2c, 0x38),
            points: &[(0x39, 0x40)],
        }],
        (5, 1) => &[GuidePath {
            origin: (0x2c, 0x36),
            points: &[(0x39, 0x3e)],
        }],
        (5, 2) => &[GuidePath {
            origin: (0x2c, 0x3a),
            points: &[(0x3a, 0x42)],
        }],
        (6, 0) => &[GuidePath {
            origin: (0x38, 0x20),
            points: &[(0x36, 0x29), (0x3a, 0x32), (0x36, 0x39), (0x38, 0x40)],
        }],
        (6, 1) => &[GuidePath {
            origin: (0x36, 0x20),
            points: &[(0x34, 0x29), (0x38, 0x32), (0x34, 0x39), (0x36, 0x40)],
        }],
        (6, 2) => &[GuidePath {
            origin: (0x3a, 0x20),
            points: &[(0x38, 0x29), (0x3c, 0x32), (0x38, 0x39), (0x3a, 0x40)],
        }],
        (7, 0) => &[GuidePath {
            origin: (0x2c, 0x38),
            points: &[(0x36, 0x33), (0x34, 0x2c), (0x3a, 0x27), (0x38, 0x20)],
        }],
        (7, 1) => &[GuidePath {
            origin: (0x2c, 0x36),
            points: &[(0x34, 0x31), (0x30, 0x2c), (0x37, 0x27), (0x36, 0x20)],
        }],
        (7, 2) => &[GuidePath {
            origin: (0x2c, 0x3a),
            points: &[(0x37, 0x35), (0x36, 0x2d), (0x3c, 0x27), (0x3a, 0x20)],
        }],
        (9, 0) => &[GuidePath {
            origin: (0x18, 0x40),
            points: &[(0x1a, 0x3b), (0x24, 0x36), (0x2a, 0x38), (0x2c, 0x38)],
        }],
        (9, 1) => &[GuidePath {
            origin: (0x16, 0x3f),
            points: &[(0x18, 0x39), (0x24, 0x33), (0x2a, 0x36), (0x2c, 0x36)],
        }],
        (9, 2) => &[GuidePath {
            origin: (0x1a, 0x40),
            points: &[(0x1c, 0x3b), (0x24, 0x38), (0x2a, 0x3a), (0x2c, 0x3a)],
        }],
        _ => &[],
    }
}

fn stroke_guide(
    pixels: &mut IndexedPicture,
    origin: (i32, i32),
    points: &[(i32, i32)],
    color: u8,
    pen: i32,
) {
    pixels.stroke_polyline_gdi(
        std::iter::once(origin.into()).chain(points.iter().copied().map(Into::into)),
        color,
        pen,
    );
}
