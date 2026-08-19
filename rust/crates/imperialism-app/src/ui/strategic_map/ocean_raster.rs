//! Retail `TOceanDialog::Draw` indexed-pixel compositor.

use super::map_interaction::{MapInteractionMode, OceanViewport, StrategicInteraction};
use super::{VIEWPORT_HEIGHT, VIEWPORT_WIDTH};
use imperialism_core::*;
use imperialism_formats::IndexedPicture;

const OCEAN_TILE: i32 = 16;
const OCEAN_FILL: u8 = 0x1a;
const BOUNDED_MAP_BLANK: u8 = 0x16;
const OWNER_PALETTE: [u8; 24] = [
    0xf3, 0x2a, 0x25, 0x1d, 0xf6, 0x8c, 0xbd, 0x0a, 0x0b, 0x0d, 0x29, 0xde, 0xdf, 0xfa, 0x2c, 0x31,
    0x33, 0x41, 0x48, 0xd0, 0xcd, 0xce, 0xcf, OCEAN_FILL,
];
const BORDER_PALETTE: [u8; 24] = [
    0x15, 0x2d, 0x1e, 0x1c, 0x30, 0xae, 0xca, 0x7d, 0x7d, 0x7d, 0x7d, 0xe2, 0xe2, 0xe2, 0xe2, 0x51,
    0x51, 0x51, 0x51, 0xf0, 0xf0, 0xf0, 0xf0, 0xc6,
];
const VERTICAL_OFFSETS: [[i32; 16]; 3] = [
    [5, 6, 7, 11, 5, 6, 7, 8, 10, 11, 12, 13, 2, 3, 4, 5],
    [2, 3, 9, 13, 2, 11, 12, 13, 2, 3, 4, 5, 10, 11, 12, 13],
    [4, 8, 10, 12, 3, 4, 9, 10, 6, 7, 8, 9, 6, 7, 8, 9],
];
const DIAGONAL_OFFSETS: [[i32; 8]; 3] = [
    [4, 5, 2, 2, 5, 5, 5, 5],
    [3, 3, 3, 4, 4, 4, 3, 4],
    [2, 2, 5, 5, 2, 3, 2, 2],
];

pub(super) struct OceanRenderAssets {
    base_a: IndexedPicture,
    base_b: IndexedPicture,
    visited: IndexedPicture,
    active: Vec<IndexedPicture>,
}

impl OceanRenderAssets {
    pub(super) fn load(mut picture: impl FnMut(i16) -> IndexedPicture) -> Self {
        Self {
            base_a: picture(1422),
            base_b: picture(1423),
            visited: picture(807),
            active: (0..21).map(|offset| picture(1401 + offset)).collect(),
        }
    }

    fn active(&self, nation: MajorNationId, variant: usize) -> &IndexedPicture {
        &self.active[variant * MajorNationId::COUNT + nation.get()]
    }
}

pub(super) struct OceanRaster {
    pixels: Vec<u8>,
}

impl OceanRaster {
    pub(super) fn compose(
        state: &GameState,
        ocean: &OceanViewport,
        interaction: &StrategicInteraction,
        hovered: Option<TileId>,
        assets: &OceanRenderAssets,
    ) -> Self {
        let mut pixels = draw_base_ownership_and_borders(state, ocean);
        draw_improvements(&mut pixels, state, ocean, assets);
        draw_unit_overlays(&mut pixels, state, ocean, assets);
        draw_routes(&mut pixels, state, ocean);
        draw_selection(&mut pixels, state, ocean, interaction, hovered);
        Self { pixels }
    }

    pub(super) fn pixels(&self) -> &[u8] {
        &self.pixels
    }
}

fn draw_base_ownership_and_borders(state: &GameState, ocean: &OceanViewport) -> Vec<u8> {
    let mut indices = vec![OCEAN_FILL; VIEWPORT_WIDTH * VIEWPORT_HEIGHT];
    let geometry = state.map().geometry();
    let bounded = !geometry.wraps_horizontally();
    let blank_wrapped_left = bounded && (ocean.origin.x < 2 || ocean.origin.x > 100);
    let blank_wrapped_right = bounded && ocean.origin.x <= 100 && ocean.origin.x > 70;
    for row_delta in 0..28 {
        let row = ocean.origin.y + row_delta;
        if !(0..STRATEGIC_MAP_HEIGHT).contains(&row) {
            continue;
        }
        for column_delta in 0..=32 {
            let screen_x = column_delta * OCEAN_TILE - if row & 1 == 0 { 8 } else { 0 };
            let screen_y = row_delta * OCEAN_TILE;
            let unwrapped_column = ocean.origin.x + column_delta;
            let column = if unwrapped_column >= STRATEGIC_MAP_WIDTH {
                if blank_wrapped_right {
                    fill_ocean_cell(&mut indices, screen_x, screen_y, BOUNDED_MAP_BLANK);
                    continue;
                }
                unwrapped_column - STRATEGIC_MAP_WIDTH
            } else if blank_wrapped_left && unwrapped_column > 60 {
                fill_ocean_cell(&mut indices, screen_x, screen_y, BOUNDED_MAP_BLANK);
                continue;
            } else {
                unwrapped_column
            };
            let Some(tile) = geometry.tile(MapPosition::new(row, column)) else {
                continue;
            };
            let tile_state = state.map()[tile];
            let owner = ocean_owner(tile_state.owner_nation);
            let water = tile_state.terrain == TerrainKind::Water;
            if !water {
                fill_ocean_cell(&mut indices, screen_x, screen_y, OWNER_PALETTE[owner]);
            }
            if screen_x >= 0 {
                draw_ocean_borders(
                    state,
                    tile,
                    screen_x,
                    screen_y,
                    owner,
                    tile_state.province,
                    water,
                    &mut indices,
                );
            }
        }
    }
    indices
}

fn ocean_owner(owner: Option<TileContext>) -> usize {
    owner.map_or(23, |owner| owner.to_retail_tag().min(23) as usize)
}

fn draw_improvements(
    indices: &mut [u8],
    state: &GameState,
    ocean: &OceanViewport,
    assets: &OceanRenderAssets,
) {
    let active = NationId::as_major(state.turn().active_nation).map(|nation| {
        let status = &state.technology().research_status_by_nation[nation];
        let variant = if status[Technology::MarineEngineering]
            == TechnologyResearchStatus::Researched
        {
            2
        } else if status[Technology::AdvancedIronWorking] == TechnologyResearchStatus::Researched {
            1
        } else {
            0
        };
        assets.active(nation, variant)
    });
    let geometry = state.map().geometry();
    let bounded = !geometry.wraps_horizontally();
    let blank_wrapped_left = bounded && (ocean.origin.x < 2 || ocean.origin.x > 100);
    let blank_wrapped_right = bounded && ocean.origin.x <= 100 && ocean.origin.x > 70;

    for row_delta in 0..28 {
        let row = ocean.origin.y + row_delta;
        if !(0..STRATEGIC_MAP_HEIGHT).contains(&row) {
            continue;
        }
        for column_delta in 0..=32 {
            let unwrapped_column = ocean.origin.x + column_delta;
            let column = if unwrapped_column >= STRATEGIC_MAP_WIDTH {
                if blank_wrapped_right {
                    continue;
                }
                unwrapped_column - STRATEGIC_MAP_WIDTH
            } else if blank_wrapped_left && unwrapped_column > 60 {
                continue;
            } else {
                unwrapped_column
            };
            let Some(tile) = geometry.tile(MapPosition::new(row, column)) else {
                continue;
            };
            let tile_state = state.map()[tile];
            let flags = tile_state.flags.bits();
            if tile_state.action.is_none()
                && tile_state.per_tile_visited <= 0
                && (flags & 3 == 0 || tile_state.gate == 0)
                && flags & 4 == 0
            {
                continue;
            }
            let (picture, source_x) =
                if tile_state.action.is_some_and(|action| action.retail() >= 2) {
                    let Some(active) = active else {
                        continue;
                    };
                    (active, tile_state.action.unwrap().retail() * 16)
                } else if tile_state.per_tile_visited > 0 {
                    (
                        &assets.visited,
                        i32::from(tile_state.per_tile_visited - 1) * 16,
                    )
                } else {
                    let source_x = ocean_improvement_source_x(&tile_state);
                    if source_x < 1024 {
                        (&assets.base_a, source_x)
                    } else {
                        (&assets.base_b, source_x - 1024)
                    }
                };
            let screen_x = column_delta * OCEAN_TILE - if row & 1 == 0 { 8 } else { 0 };
            let screen_y = row_delta * OCEAN_TILE;
            blit_ocean_sprite(indices, picture, source_x, screen_x, screen_y);
        }
    }
}

fn ocean_improvement_source_x(tile: &TileState) -> i32 {
    let owner = tile
        .owner_nation
        .map(TileContext::to_retail_tag)
        .unwrap_or(23);
    if tile.flags.contains(TileFlags::BASE_TRANSPORT) {
        return if owner < 7 {
            i32::from(owner + 0x16) * 16
        } else {
            0x1d * 16
        };
    }
    if tile.flags.contains(TileFlags::CITY_MARKER) {
        return if owner < 7 {
            i32::from(owner * 2 + 0x40) * 16
        } else {
            0x4e * 16
        };
    }
    if tile.flags.contains(TileFlags::PORT) {
        return if owner < 7 {
            i32::from(owner + 0x26) * 16
        } else {
            0x2d * 16
        };
    }
    0
}

fn blit_ocean_sprite(
    indices: &mut [u8],
    picture: &IndexedPicture,
    source_x: i32,
    destination_x: i32,
    destination_y: i32,
) {
    for y in 0..16 {
        for x in 0..16 {
            let source = source_x + x;
            if source < 0 || source >= picture.width as i32 || y >= picture.height as i32 {
                continue;
            }
            let color = picture.pixels[y as usize * picture.width as usize + source as usize];
            if color != 0x10 {
                put_ocean_pixel(indices, destination_x + x, destination_y + y, color);
            }
        }
    }
}

fn draw_routes(indices: &mut [u8], state: &GameState, ocean: &OceanViewport) {
    let viewport_column_x2 = ocean.origin.x * 2 + 1;
    for route in &state.ocean().routes {
        let mut start_x = (route.start_column - viewport_column_x2 + 216).rem_euclid(216);
        let mut end_x = (route.end_column - viewport_column_x2 + 216).rem_euclid(216);
        if (start_x - end_x).abs() > 108 {
            if start_x > 108 {
                start_x -= 216;
            } else if end_x > 108 {
                end_x -= 216;
            }
        }
        draw_ocean_line(
            indices,
            start_x * 8,
            (route.start_row - ocean.origin.y) * 16,
            end_x * 8,
            (route.end_row - ocean.origin.y) * 16,
            BORDER_PALETTE[23],
        );
    }
}

fn draw_unit_overlays(
    indices: &mut [u8],
    state: &GameState,
    ocean: &OceanViewport,
    assets: &OceanRenderAssets,
) {
    for (_, civilian) in state.civilian_units() {
        let Some(tile) = civilian.location().tile() else {
            continue;
        };
        let Some((x, y)) = ocean_tile_screen_origin(state.map().geometry(), tile, ocean) else {
            continue;
        };
        fill_ocean_cell(
            indices,
            x,
            y,
            OWNER_PALETTE[ocean_owner(state.map()[tile].owner_nation)],
        );
        blit_ocean_sprite(indices, &assets.base_a, 0xe0, x, y);
    }

    let mut drawn_provinces = Vec::new();
    for (_, unit) in state.military_units() {
        let Some(province) = unit.stationed_province() else {
            continue;
        };
        if drawn_provinces.contains(&province) {
            continue;
        }
        drawn_provinces.push(province);
        let Some(tile) = state.map().provinces[province].city_tile() else {
            continue;
        };
        let Some((x, y)) = ocean_tile_screen_origin(state.map().geometry(), tile, ocean) else {
            continue;
        };
        fill_ocean_cell(
            indices,
            x,
            y,
            OWNER_PALETTE[ocean_owner(state.map()[tile].owner_nation)],
        );
        let source_x = ocean_improvement_source_x(&state.map()[tile]);
        if source_x < 1024 {
            blit_ocean_sprite(indices, &assets.base_a, source_x, x, y);
        } else {
            blit_ocean_sprite(indices, &assets.base_b, source_x - 1024, x, y);
        }
    }
}

fn ocean_tile_screen_origin(
    geometry: MapGeometry,
    tile: TileId,
    ocean: &OceanViewport,
) -> Option<(i32, i32)> {
    let MapPosition { row, column } = geometry.position(tile);
    let x = (column - ocean.origin.x).rem_euclid(108) * 16 - if row & 1 == 0 { 8 } else { 0 };
    let y = (row - ocean.origin.y) * 16;
    (x < VIEWPORT_WIDTH as i32 && x + 16 > 0 && y < VIEWPORT_HEIGHT as i32 && y + 16 > 0)
        .then_some((x, y))
}

fn draw_ocean_line(indices: &mut [u8], mut x0: i32, mut y0: i32, x1: i32, y1: i32, color: u8) {
    let dx = (x1 - x0).abs();
    let sx = if x0 < x1 { 1 } else { -1 };
    let dy = -(y1 - y0).abs();
    let sy = if y0 < y1 { 1 } else { -1 };
    let mut error = dx + dy;
    loop {
        put_ocean_pixel(indices, x0, y0, color);
        if x0 == x1 && y0 == y1 {
            break;
        }
        let doubled = error * 2;
        if doubled >= dy {
            error += dy;
            x0 += sx;
        }
        if doubled <= dx {
            error += dx;
            y0 += sy;
        }
    }
}

fn draw_selection(
    indices: &mut [u8],
    state: &GameState,
    ocean: &OceanViewport,
    interaction: &StrategicInteraction,
    hovered: Option<TileId>,
) {
    if interaction.mode != MapInteractionMode::Civilian {
        return;
    }
    let (Some(unit), Some(hovered)) = (interaction.civilian, hovered) else {
        return;
    };
    let Some(civilian) = state.civilian_unit(unit) else {
        return;
    };
    let action = state.civilian_tile_action(unit, hovered);
    if matches!(
        action,
        CivilianTileAction::None | CivilianTileAction::Blocked | CivilianTileAction::SelectUnit
    ) {
        return;
    }
    draw_ocean_tile_frame(indices, state.map().geometry(), hovered, ocean);
    if civilian.unit_type() != CivilianUnitKind::Engineer
        || action != CivilianTileAction::EngineerSameTile
        || state.map()[hovered].region.is_some()
    {
        return;
    }
    let owner = TileContext::from(state.turn().active_nation);
    for neighbor in state
        .map()
        .geometry()
        .neighbors(hovered)
        .into_iter()
        .flatten()
    {
        let tile = state.map()[neighbor];
        if tile.region.is_none()
            && (tile.terrain == TerrainKind::Water || tile.owner_nation == Some(owner))
        {
            draw_ocean_tile_frame(indices, state.map().geometry(), neighbor, ocean);
        }
    }
}

fn draw_ocean_tile_frame(
    indices: &mut [u8],
    geometry: MapGeometry,
    tile: TileId,
    ocean: &OceanViewport,
) {
    let Some((x, y)) = ocean_tile_screen_origin(geometry, tile, ocean) else {
        return;
    };
    for offset in 0..16 {
        put_ocean_pixel(indices, x + offset, y, 0x20);
        put_ocean_pixel(indices, x + offset, y + 15, 0x20);
        put_ocean_pixel(indices, x, y + offset, 0x20);
        put_ocean_pixel(indices, x + 15, y + offset, 0x20);
    }
}

fn draw_ocean_borders(
    state: &GameState,
    tile: TileId,
    x: i32,
    y: i32,
    owner: usize,
    province: Option<ProvinceId>,
    water: bool,
    indices: &mut [u8],
) {
    let geometry = state.map().geometry();
    let neighbors = geometry.neighbors(tile);
    let owners = neighbors.map(|neighbor| {
        neighbor
            .map(|neighbor| ocean_owner(state.map()[neighbor].owner_nation) as i32)
            .unwrap_or(-1)
    });
    let provinces =
        neighbors.map(|neighbor| neighbor.and_then(|neighbor| state.map()[neighbor].province));
    let current = BORDER_PALETTE[owner];
    let mut put = |local_x: i32, local_y: i32, color: u8| {
        put_ocean_pixel(indices, x + local_x, y + local_y, color);
    };

    if owners[4] < 0 || owners[4] == owner as i32 {
        if province != provinces[4] {
            for py in 0..16 {
                put(0, py, current);
            }
        }
    } else {
        let neighbor = owners[4] as usize;
        let border = BORDER_PALETTE[neighbor];
        let pattern = (tile.get() % 4) * 4;
        if owners[5] == owners[4] {
            put(0, 0, OWNER_PALETTE[neighbor]);
            put(1, 0, border);
            put(0, 1, border);
            put(1, 1, current);
        } else {
            put(0, 0, current);
            put(0, 1, current);
        }
        for offset in 0..4 {
            let a = VERTICAL_OFFSETS[0][pattern + offset];
            let b = VERTICAL_OFFSETS[1][pattern + offset];
            let c = VERTICAL_OFFSETS[2][pattern + offset];
            put(0, c, current);
            put(0, b, border);
            put(1, b, current);
            if water {
                put(0, a, current);
                put(1, c, current);
                put(2, b, current);
            }
        }
        if owners[3] == owners[4] {
            put(0, 14, border);
            put(1, 14, current);
            put(0, 15, border);
            put(1, 15, OWNER_PALETTE[neighbor]);
        } else {
            put(0, 14, current);
            put(0, 15, current);
        }
    }

    if owners[1] >= 0 && owners[1] != owner as i32 {
        let neighbor = owners[1] as usize;
        let border = BORDER_PALETTE[neighbor];
        let neighbor_tile = neighbors[1].unwrap();
        let pattern = (neighbor_tile.get() % 4) * 4;
        if owners[0] == owners[1] {
            put(14, 0, border);
            put(15, 0, OWNER_PALETTE[owners[4].max(0) as usize]);
            put(15, 1, border);
            put(14, 1, current);
        } else {
            put(15, 0, current);
            put(15, 1, current);
        }
        for offset in 0..4 {
            let a = VERTICAL_OFFSETS[0][pattern + offset];
            let b = VERTICAL_OFFSETS[1][pattern + offset];
            let c = VERTICAL_OFFSETS[2][pattern + offset];
            put(15, c, current);
            put(15, b, border);
            put(14, b, current);
            if water {
                put(15, a, current);
                put(14, c, current);
                put(13, b, current);
            }
        }
        if owners[2] == owners[1] {
            put(15, 14, border);
            put(14, 14, current);
            put(15, 15, border);
            put(14, 15, OWNER_PALETTE[owners[4].max(0) as usize]);
        } else {
            put(15, 14, current);
            put(15, 15, current);
        }
    }

    draw_upper_edge(
        &mut put, tile, neighbors, owners, province, provinces, owner, water, false,
    );
    draw_upper_edge(
        &mut put, tile, neighbors, owners, province, provinces, owner, water, true,
    );
    draw_lower_edge(&mut put, tile, neighbors, owners, owner, water, true);
    draw_lower_edge(&mut put, tile, neighbors, owners, owner, water, false);
}

fn draw_upper_edge(
    put: &mut impl FnMut(i32, i32, u8),
    tile: TileId,
    neighbors: [Option<TileId>; 6],
    owners: [i32; 6],
    province: Option<ProvinceId>,
    provinces: [Option<ProvinceId>; 6],
    owner: usize,
    water: bool,
    right: bool,
) {
    let direction = if right { 0 } else { 5 };
    let base_x = if right { 8 } else { 0 };
    let current = BORDER_PALETTE[owner];
    if owners[direction] < 0 || owners[direction] == owner as i32 {
        if province != provinces[direction] {
            for px in 0..8 {
                put(base_x + px, 0, current);
            }
        }
        return;
    }
    let neighbor = owners[direction] as usize;
    let border = BORDER_PALETTE[neighbor];
    let pattern_tile = if right {
        neighbors[direction].unwrap()
    } else {
        tile
    };
    let pattern = (pattern_tile.get() % 4) * 2;
    if (!right && owners[5] != owners[4]) || (right && owners[5] != owner as i32) {
        put(base_x, 0, current);
        put(base_x + 1, 0, current);
    }
    for offset in 0..2 {
        let a = DIAGONAL_OFFSETS[0][pattern + offset];
        let b = DIAGONAL_OFFSETS[1][pattern + offset];
        let c = DIAGONAL_OFFSETS[2][pattern + offset];
        put(base_x + b, 0, current);
        put(base_x + a, 0, border);
        put(base_x + a, 1, current);
        if water {
            put(base_x + c, 0, current);
            put(base_x + b, 1, current);
            put(base_x + a, 2, current);
        }
    }
    if (!right && owners[0] != owner as i32) || (right && owners[0] != owners[1]) {
        put(base_x + 6, 0, current);
        put(base_x + 7, 0, current);
    }
}

fn draw_lower_edge(
    put: &mut impl FnMut(i32, i32, u8),
    tile: TileId,
    neighbors: [Option<TileId>; 6],
    owners: [i32; 6],
    owner: usize,
    water: bool,
    right: bool,
) {
    let direction = if right { 2 } else { 3 };
    if owners[direction] < 0 || owners[direction] == owner as i32 {
        return;
    }
    let base_x = if right { 8 } else { 0 };
    let current = BORDER_PALETTE[owner];
    let neighbor = owners[direction] as usize;
    let border = BORDER_PALETTE[neighbor];
    let pattern_tile = if right {
        neighbors[direction].unwrap()
    } else {
        tile
    };
    let pattern = (pattern_tile.get() % 4) * 2;
    if right || owners[3] != owners[4] {
        put(base_x, 15, current);
        put(base_x + 1, 15, current);
    }
    for offset in 0..2 {
        let a = DIAGONAL_OFFSETS[0][pattern + offset];
        let b = DIAGONAL_OFFSETS[1][pattern + offset];
        let c = DIAGONAL_OFFSETS[2][pattern + offset];
        put(base_x + b, 15, current);
        put(base_x + c, 15, border);
        put(base_x + c, 14, current);
        if water {
            put(base_x + a, 15, current);
            put(base_x + b, 14, current);
            put(base_x + c, 13, current);
        }
    }
    if (right && owners[2] != owners[1]) || (!right && owners[3] != owners[2]) {
        put(base_x + 6, 15, current);
        put(base_x + 7, 15, current);
    }
}

fn put_ocean_pixel(indices: &mut [u8], x: i32, y: i32, color: u8) {
    if (0..VIEWPORT_WIDTH as i32).contains(&x) && (0..VIEWPORT_HEIGHT as i32).contains(&y) {
        indices[y as usize * VIEWPORT_WIDTH + x as usize] = color;
    }
}

fn fill_ocean_cell(indices: &mut [u8], x: i32, y: i32, color: u8) {
    for dy in 0..OCEAN_TILE {
        let dest_y = y + dy;
        if !(0..VIEWPORT_HEIGHT as i32).contains(&dest_y) {
            continue;
        }
        for dx in 0..OCEAN_TILE {
            let dest_x = x + dx;
            if (0..VIEWPORT_WIDTH as i32).contains(&dest_x) {
                indices[dest_y as usize * VIEWPORT_WIDTH + dest_x as usize] = color;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::test_support::{beginning_of_game_parts_with, strategic_map_beginning_context};

    fn pixel(indices: &[u8], x: usize, y: usize) -> u8 {
        indices[y * VIEWPORT_WIDTH + x]
    }

    fn clear_map(parts: &mut GameStateParts) {
        for index in 0..STRATEGIC_TILE_COUNT {
            let tile = TileId::new(index);
            parts.map[tile].terrain = TerrainKind::Water;
            parts.map[tile].owner_nation = None;
            parts.map[tile].province = None;
        }
    }

    fn make_bounded(parts: &mut GameStateParts) {
        let tiles = TileId::all()
            .map(|tile| parts.map[tile])
            .collect::<Vec<_>>();
        parts.map = MapMgr::from_parts(MapTopology::Bounded, tiles, parts.map.provinces.clone());
    }

    #[test]
    fn political_map_fills_land_by_owner_and_leaves_water_as_ocean() {
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        clear_map(&mut parts);
        let land = parts.map.geometry().tile(MapPosition::new(2, 10)).unwrap();
        parts.map[land].terrain = TerrainKind::Plains;
        parts.map[land].owner_nation = Some(TileContext::from_retail_tag(3));
        let state = GameState::from_parts(parts);
        let indices = draw_base_ownership_and_borders(&state, &OceanViewport::default());

        assert_eq!(pixel(&indices, 160, 40), OWNER_PALETTE[3]);
        assert_eq!(pixel(&indices, 176, 40), OCEAN_FILL);
    }

    #[test]
    fn city_boundary_is_a_straight_owner_colored_edge() {
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        clear_map(&mut parts);
        let tile = parts.map.geometry().tile(MapPosition::new(2, 10)).unwrap();
        let west = parts
            .map
            .geometry()
            .neighbor(tile, HexDirection::West)
            .unwrap();
        parts.map[tile].terrain = TerrainKind::Plains;
        parts.map[tile].owner_nation = Some(TileContext::from_retail_tag(2));
        parts.map[tile].province = Some(ProvinceId::new(1));
        parts.map[west].terrain = TerrainKind::Plains;
        parts.map[west].owner_nation = Some(TileContext::from_retail_tag(2));
        parts.map[west].province = Some(ProvinceId::new(2));
        let state = GameState::from_parts(parts);
        let indices = draw_base_ownership_and_borders(&state, &OceanViewport::default());

        for y in 32..48 {
            assert_eq!(pixel(&indices, 152, y), BORDER_PALETTE[2]);
        }
    }

    #[test]
    fn different_owner_and_water_edges_use_the_retail_stipple_and_thickness() {
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        clear_map(&mut parts);
        let tile = parts.map.geometry().tile(MapPosition::new(2, 10)).unwrap();
        let west = parts
            .map
            .geometry()
            .neighbor(tile, HexDirection::West)
            .unwrap();
        parts.map[tile].owner_nation = Some(TileContext::from_retail_tag(1));
        parts.map[west].terrain = TerrainKind::Plains;
        parts.map[west].owner_nation = Some(TileContext::from_retail_tag(2));
        let state = GameState::from_parts(parts);
        let indices = draw_base_ownership_and_borders(&state, &OceanViewport::default());

        assert_eq!(pixel(&indices, 152, 38), BORDER_PALETTE[1]);
        assert_eq!(pixel(&indices, 153, 34), BORDER_PALETTE[1]);
        assert_eq!(pixel(&indices, 154, 34), BORDER_PALETTE[1]);
        assert_eq!(pixel(&indices, 152, 34), BORDER_PALETTE[2]);
    }

    #[test]
    fn wrapping_seam_uses_the_opposite_edge_neighbor() {
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        clear_map(&mut parts);
        assert!(parts.map.geometry().wraps_horizontally());
        let left = parts.map.geometry().tile(MapPosition::new(3, 0)).unwrap();
        let right = parts.map.geometry().tile(MapPosition::new(3, 107)).unwrap();
        parts.map[left].terrain = TerrainKind::Plains;
        parts.map[left].owner_nation = Some(TileContext::from_retail_tag(0));
        parts.map[right].terrain = TerrainKind::Plains;
        parts.map[right].owner_nation = Some(TileContext::from_retail_tag(1));
        let state = GameState::from_parts(parts);
        let indices = draw_base_ownership_and_borders(&state, &OceanViewport::default());

        assert_eq!(pixel(&indices, 0, 48), BORDER_PALETTE[0]);
        assert!(indices.contains(&BORDER_PALETTE[1]));
    }

    #[test]
    fn bounded_map_blanks_and_rejects_the_right_wrapped_cell() {
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        clear_map(&mut parts);
        make_bounded(&mut parts);
        let state = GameState::from_parts(parts);
        let ocean = OceanViewport {
            origin: bevy::math::IVec2::new(76, 0),
        };
        let indices = draw_base_ownership_and_borders(&state, &ocean);

        assert_eq!(pixel(&indices, 511, 4), BOUNDED_MAP_BLANK);
    }

    #[test]
    fn overlay_blit_preserves_retail_transparency_index() {
        let mut indices = vec![0x44; VIEWPORT_WIDTH * VIEWPORT_HEIGHT];
        let mut pixels = vec![0x10; 32 * 16];
        pixels[3 * 32 + 18] = 0x77;
        let picture = IndexedPicture {
            width: 32,
            height: 16,
            pixels,
        };
        blit_ocean_sprite(&mut indices, &picture, 16, 10, 20);
        assert_eq!(pixel(&indices, 12, 23), 0x77);
        assert_eq!(pixel(&indices, 11, 23), 0x44);
    }

    #[test]
    fn wrapped_routes_take_the_short_world_seam_path() {
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        parts.ocean.routes = vec![OceanRoute {
            start_column: 214,
            start_row: 2,
            end_column: 2,
            end_row: 2,
        }];
        let state = GameState::from_parts(parts);
        let ocean = OceanViewport::default();
        let mut indices = vec![0; VIEWPORT_WIDTH * VIEWPORT_HEIGHT];
        draw_routes(&mut indices, &state, &ocean);
        assert_eq!(pixel(&indices, 0, 32), BORDER_PALETTE[23]);
        assert_eq!(pixel(&indices, 8, 32), BORDER_PALETTE[23]);
        assert_eq!(pixel(&indices, 16, 32), 0);
        assert_eq!(pixel(&indices, 200, 32), 0);
    }
}
