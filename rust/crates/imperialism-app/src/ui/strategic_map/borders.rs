use imperialism_core::*;

use super::TILE_SIZE;

pub(super) const CITY_BORDER_PALETTE: u8 = 0x13;
pub(super) const MINOR_NATION_BORDER_PALETTE: u8 = 0x0a;
pub(super) const MAJOR_NATION_BORDER_PALETTES: [u8; MajorNationId::COUNT as usize] =
    [0x16, 0x2a, 0x22, 0x1c, 0x2b, 0x1e, 0x2e];
pub(super) fn compose_strategic_borders(state: &GameState, tile: TileId, pixels: &mut [u8]) {
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

fn draw_nation_border_segments(state: &GameState, tile: TileId, pixels: &mut [u8]) {
    let mask = state.map()[tile].owner_border_mask;
    let owner = border_palette(state.map()[tile].owner_nation);
    let neighbors = state.map().geometry().neighbors(tile);
    let direction1 = mask & 2 != 0;

    if direction1 {
        let east = neighbor_palette(state, neighbors[HexDirection::East as usize]);
        if mask & 1 == 0 {
            draw_border(pixels, 2, owner, east);
        } else {
            draw_border(pixels, 1, owner, east);
            if mask & 0x40 != 0 {
                let north_east =
                    neighbor_palette(state, neighbors[HexDirection::NorthEast as usize]);
                draw_border(pixels, 3, owner, north_east);
            }
        }
        if mask & 4 == 0 {
            draw_border(pixels, 6, owner, east);
        } else {
            let south_east = neighbor_palette(state, neighbors[HexDirection::SouthEast as usize]);
            draw_border(pixels, 7, owner, south_east);
            if mask & 0x80 != 0 {
                draw_border(pixels, 5, owner, south_east);
            }
        }
    }

    if mask & 1 != 0 {
        let north_east = neighbor_palette(state, neighbors[HexDirection::NorthEast as usize]);
        draw_border(pixels, 0, owner, north_east);
        if !direction1 {
            draw_border(pixels, 3, owner, north_east);
        }
    }
    if mask & 4 != 0 {
        let south_east = neighbor_palette(state, neighbors[HexDirection::SouthEast as usize]);
        draw_border(pixels, 9, owner, south_east);
        if !direction1 {
            draw_border(pixels, 5, owner, south_east);
        }
    }

    if state.map()[tile].terrain == TerrainKind::Water {
        return;
    }
    if neighbor_is_water(state, neighbors[HexDirection::NorthEast as usize])
        && mask & 0x20 != 0
        && !direction1
    {
        let north_west = neighbor_palette(state, neighbors[HexDirection::NorthWest as usize]);
        draw_border(pixels, 0, owner, north_west);
        draw_border(pixels, 3, owner, north_west);
    }
    if neighbor_is_water(state, neighbors[HexDirection::SouthEast as usize])
        && mask & 8 != 0
        && !direction1
    {
        let south_west = neighbor_palette(state, neighbors[HexDirection::SouthWest as usize]);
        draw_border(pixels, 5, owner, south_west);
        draw_border(pixels, 9, owner, south_west);
    }
}

fn draw_city_border_segments(state: &GameState, tile: TileId, pixels: &mut [u8]) {
    let mask = state.map()[tile].city_border_mask;
    let neighbors = state.map().geometry().neighbors(tile);
    let direction1 = mask & 2 != 0;

    if direction1 {
        if mask & 1 == 0 {
            draw_guide_pattern(pixels, 2, 0, CITY_BORDER_PALETTE, 1);
        } else {
            draw_guide_pattern(pixels, 1, 0, CITY_BORDER_PALETTE, 1);
            if mask & 0x40 != 0 {
                draw_guide_pattern(pixels, 3, 0, CITY_BORDER_PALETTE, 1);
            }
        }
        if mask & 4 == 0 {
            draw_guide_pattern(pixels, 6, 0, CITY_BORDER_PALETTE, 1);
        } else {
            draw_guide_pattern(pixels, 7, 0, CITY_BORDER_PALETTE, 1);
            if mask & 0x80 != 0 {
                draw_guide_pattern(pixels, 5, 0, CITY_BORDER_PALETTE, 1);
            }
        }
    }

    if mask & 1 != 0 {
        draw_guide_pattern(pixels, 0, 0, CITY_BORDER_PALETTE, 1);
        if !direction1 {
            draw_guide_pattern(pixels, 3, 0, CITY_BORDER_PALETTE, 1);
        }
    }
    if mask & 4 != 0 {
        draw_guide_pattern(pixels, 9, 0, CITY_BORDER_PALETTE, 1);
        if !direction1 {
            draw_guide_pattern(pixels, 5, 0, CITY_BORDER_PALETTE, 1);
        }
    }

    if state.map()[tile].terrain == TerrainKind::Water {
        return;
    }
    if neighbor_is_water(state, neighbors[HexDirection::NorthEast as usize])
        && mask & 0x20 != 0
        && !direction1
    {
        draw_guide_pattern(pixels, 0, 0, CITY_BORDER_PALETTE, 1);
        draw_guide_pattern(pixels, 3, 0, CITY_BORDER_PALETTE, 1);
    }
    if neighbor_is_water(state, neighbors[HexDirection::SouthEast as usize])
        && mask & 8 != 0
        && !direction1
    {
        draw_guide_pattern(pixels, 5, 0, CITY_BORDER_PALETTE, 1);
        draw_guide_pattern(pixels, 9, 0, CITY_BORDER_PALETTE, 1);
    }
}

fn draw_sea_zone_borders(state: &GameState, tile: TileId, pixels: &mut [u8]) {
    let neighbors = state.map().geometry().neighbors(tile);
    let pairs = [
        (HexDirection::SouthWest, HexDirection::SouthEast),
        (HexDirection::SouthEast, HexDirection::East),
        (HexDirection::West, HexDirection::SouthWest),
        (HexDirection::NorthWest, HexDirection::NorthEast),
        (HexDirection::NorthEast, HexDirection::East),
        (HexDirection::West, HexDirection::NorthWest),
    ];
    for (index, (first, second)) in pairs.into_iter().enumerate() {
        if !land_tiles_have_different_owners(
            state,
            neighbors[first as usize],
            neighbors[second as usize],
        ) {
            continue;
        }
        let first_color = neighbor_palette(state, neighbors[first as usize]);
        let second_color = neighbor_palette(state, neighbors[second as usize]);
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
        .map(|nation| MAJOR_NATION_BORDER_PALETTES[usize::from(nation.get())])
        .unwrap_or(MINOR_NATION_BORDER_PALETTE)
}

pub(super) fn draw_border(pixels: &mut [u8], relation: u8, nation_a: u8, nation_b: u8) {
    draw_guide_pattern(pixels, relation, 1, nation_a, 2);
    draw_guide_pattern(pixels, relation, 2, nation_b, 2);
}

fn draw_guide_pattern(pixels: &mut [u8], relation: u8, variant: i32, color: u8, pen: i32) {
    match relation {
        0 => draw_guide_set_a(pixels, variant, color, pen),
        1 => draw_guide_set_b(pixels, variant, color, pen),
        2 => draw_guide_set_c(pixels, variant, color, pen),
        3 => draw_guide_set_d(pixels, variant, color, pen),
        4 => draw_guide_set_tile(pixels, variant, color, pen),
        5 => draw_guide_set_e(pixels, variant, color, pen),
        6 => draw_guide_set_f(pixels, variant, color, pen),
        7 => draw_guide_set_g(pixels, variant, color, pen),
        8 => draw_guide_set_h(pixels, variant, color, pen),
        9 => draw_guide_set_i(pixels, variant, color, pen),
        _ => {}
    }
}

fn draw_guide_set_a(pixels: &mut [u8], variant: i32, color: u8, pen: i32) {
    if variant == 0 {
        stroke_guide(
            pixels,
            (0x18, 0),
            &[(0x20, 9), (0x26, 6), (0x2c, 8)],
            color,
            pen,
        );
        return;
    }
    if variant == 1 {
        stroke_guide(
            pixels,
            (0x16, 0),
            &[(0x1e, 10), (0x26, 8), (0x2c, 10)],
            color,
            pen,
        );
        return;
    }
    if variant == 2 {
        stroke_guide(
            pixels,
            (0x1a, 0),
            &[(0x22, 6), (0x26, 4), (0x2c, 6)],
            color,
            pen,
        );
    }
}

fn draw_guide_set_b(pixels: &mut [u8], variant: i32, color: u8, pen: i32) {
    if variant == 0 {
        stroke_guide(
            pixels,
            (0x2c, 8),
            &[(0x36, 0xd), (0x34, 0x14), (0x3a, 0x19), (0x38, 0x20)],
            color,
            pen,
        );
        return;
    }
    if variant == 1 {
        stroke_guide(
            pixels,
            (0x2c, 10),
            &[(0x34, 0xf), (0x31, 0x14), (0x38, 0x19), (0x36, 0x20)],
            color,
            pen,
        );
        return;
    }
    if variant == 2 {
        stroke_guide(
            pixels,
            (0x2c, 6),
            &[(0x37, 0xb), (0x36, 0x13), (0x3c, 0x19), (0x3a, 0x20)],
            color,
            pen,
        );
    }
}

fn draw_guide_set_c(pixels: &mut [u8], variant: i32, color: u8, pen: i32) {
    let (x1, x2, x3) = if variant == 1 {
        (0x36, 0x34, 0x38)
    } else if variant == 2 {
        (0x3a, 0x38, 0x3c)
    } else {
        (0x38, 0x36, 0x3a)
    };
    stroke_guide(
        pixels,
        (x1, 0),
        &[(x2, 9), (x3, 0x12), (x2, 0x19), (x1, 0x20)],
        color,
        pen,
    );
}

fn draw_guide_set_d(pixels: &mut [u8], variant: i32, color: u8, pen: i32) {
    if variant == 1 {
        stroke_guide(pixels, (0x2c, 10), &[(0x39, 0)], color, pen);
        return;
    }
    if variant == 2 {
        stroke_guide(pixels, (0x2c, 5), &[(0x37, -3)], color, pen);
        return;
    }
    stroke_guide(pixels, (0x2c, 8), &[(0x38, 0)], color, pen);
}

fn draw_guide_set_tile(pixels: &mut [u8], variant: i32, color: u8, pen: i32) {
    draw_guide_set_b(pixels, variant, color, pen);
    draw_guide_set_d(pixels, variant, color, pen);
}

fn draw_guide_set_e(pixels: &mut [u8], variant: i32, color: u8, pen: i32) {
    if variant == 1 {
        stroke_guide(pixels, (0x2c, 0x36), &[(0x39, 0x3e)], color, pen);
        return;
    }
    if variant == 2 {
        stroke_guide(pixels, (0x2c, 0x3a), &[(0x3a, 0x42)], color, pen);
        return;
    }
    stroke_guide(pixels, (0x2c, 0x38), &[(0x39, 0x40)], color, pen);
}

fn draw_guide_set_f(pixels: &mut [u8], variant: i32, color: u8, pen: i32) {
    let (x1, x2, x3) = if variant == 1 {
        (0x36, 0x34, 0x38)
    } else if variant == 2 {
        (0x3a, 0x38, 0x3c)
    } else {
        (0x38, 0x36, 0x3a)
    };
    stroke_guide(
        pixels,
        (x1, 0x20),
        &[(x2, 0x29), (x3, 0x32), (x2, 0x39), (x1, 0x40)],
        color,
        pen,
    );
}

fn draw_guide_set_g(pixels: &mut [u8], variant: i32, color: u8, pen: i32) {
    if variant == 0 {
        stroke_guide(
            pixels,
            (0x2c, 0x38),
            &[(0x36, 0x33), (0x34, 0x2c), (0x3a, 0x27), (0x38, 0x20)],
            color,
            pen,
        );
        return;
    }
    if variant == 1 {
        stroke_guide(
            pixels,
            (0x2c, 0x36),
            &[(0x34, 0x31), (0x30, 0x2c), (0x37, 0x27), (0x36, 0x20)],
            color,
            pen,
        );
        return;
    }
    if variant == 2 {
        stroke_guide(
            pixels,
            (0x2c, 0x3a),
            &[(0x37, 0x35), (0x36, 0x2d), (0x3c, 0x27), (0x3a, 0x20)],
            color,
            pen,
        );
    }
}

fn draw_guide_set_h(pixels: &mut [u8], variant: i32, color: u8, pen: i32) {
    draw_guide_set_g(pixels, variant, color, pen);
    draw_guide_set_e(pixels, variant, color, pen);
}

fn draw_guide_set_i(pixels: &mut [u8], variant: i32, color: u8, pen: i32) {
    if variant == 0 {
        stroke_guide(
            pixels,
            (0x18, 0x40),
            &[(0x1a, 0x3b), (0x24, 0x36), (0x2a, 0x38), (0x2c, 0x38)],
            color,
            pen,
        );
        return;
    }
    if variant == 1 {
        stroke_guide(
            pixels,
            (0x16, 0x3f),
            &[(0x18, 0x39), (0x24, 0x33), (0x2a, 0x36), (0x2c, 0x36)],
            color,
            pen,
        );
        return;
    }
    if variant == 2 {
        stroke_guide(
            pixels,
            (0x1a, 0x40),
            &[(0x1c, 0x3b), (0x24, 0x38), (0x2a, 0x3a), (0x2c, 0x3a)],
            color,
            pen,
        );
    }
}

fn stroke_guide(pixels: &mut [u8], origin: (i32, i32), points: &[(i32, i32)], color: u8, pen: i32) {
    let mut x = origin.0;
    let mut y = origin.1;
    for &(next_x, next_y) in points {
        draw_pen_line(pixels, (x, y), (next_x, next_y), color, pen);
        x = next_x;
        y = next_y;
    }
}

fn draw_pen_line(pixels: &mut [u8], start: (i32, i32), end: (i32, i32), color: u8, pen: i32) {
    let offset = pen / 2;
    let x0 = start.0 + offset;
    let y0 = start.1 + offset;
    let x1 = end.0 + offset;
    let y1 = end.1 + offset;
    let dx = (x1 - x0).abs();
    let dy = (y1 - y0).abs();
    let sx = (x1 - x0).signum();
    let sy = (y1 - y0).signum();
    let mut err = dx - dy;
    let mut x = x0;
    let mut y = y0;
    loop {
        if x == x1 && y == y1 {
            break;
        }
        stamp_pen(pixels, x, y, color, pen);
        let twice_err = err * 2;
        if twice_err > -dy {
            err -= dy;
            x += sx;
        }
        if twice_err < dx {
            err += dx;
            y += sy;
        }
    }
}

fn stamp_pen(pixels: &mut [u8], x: i32, y: i32, color: u8, pen: i32) {
    for row in 0..pen {
        for column in 0..pen {
            put_tile_pixel(pixels, x + column, y + row, color);
        }
    }
}

fn put_tile_pixel(pixels: &mut [u8], x: i32, y: i32, color: u8) {
    if (0..TILE_SIZE).contains(&x) && (0..TILE_SIZE).contains(&y) {
        pixels[y as usize * TILE_SIZE as usize + x as usize] = color;
    }
}
