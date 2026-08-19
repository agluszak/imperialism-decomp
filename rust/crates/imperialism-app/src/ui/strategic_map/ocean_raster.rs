//! Retail `TOceanDialog::Draw` indexed-pixel compositor.

use super::map_interaction::{MapInteractionMode, OceanViewport, StrategicInteraction};
use super::map_projection::{OCEAN_CELL_SIZE, OceanCell, OceanProjection, ProjectedTile};
use super::{VIEWPORT_HEIGHT, VIEWPORT_WIDTH};
use bevy::prelude::{IRect, IVec2};
use imperialism_core::*;
use imperialism_formats::IndexedPicture;

use crate::ui::retail_raster::{IndexedRasterExt, indexed_picture};

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
        &self.active[variant * usize::from(MajorNationId::COUNT) + usize::from(nation.get())]
    }
}

pub(super) fn compose_ocean_raster(
    state: &GameState,
    ocean: &OceanViewport,
    interaction: &StrategicInteraction,
    hovered: Option<TileId>,
    assets: &OceanRenderAssets,
) -> IndexedPicture {
    let projection = OceanProjection::new(state.map().geometry(), ocean);
    let cells = projection.visible_cells();
    let mut picture = draw_base_ownership_and_borders(state, &cells);
    draw_improvements(&mut picture, state, &cells, assets);
    draw_unit_overlays(&mut picture, state, &projection, assets);
    draw_routes(&mut picture, state, &projection);
    draw_selection(&mut picture, state, &projection, interaction, hovered);
    picture
}

fn ocean_cell(x: i32, y: i32) -> IRect {
    IRect::new(x, y, x + OCEAN_CELL_SIZE, y + OCEAN_CELL_SIZE)
}

fn blit_ocean_sprite(
    destination: &mut IndexedPicture,
    source: &IndexedPicture,
    source_x: i32,
    at: IVec2,
) {
    destination.blit_keyed(
        source,
        IRect::new(source_x, 0, source_x + OCEAN_CELL_SIZE, OCEAN_CELL_SIZE),
        at,
        0x10,
    );
}

fn draw_base_ownership_and_borders(state: &GameState, cells: &[OceanCell]) -> IndexedPicture {
    let mut picture = indexed_picture(VIEWPORT_WIDTH as i32, VIEWPORT_HEIGHT as i32, OCEAN_FILL);
    for &cell in cells {
        match cell {
            OceanCell::BoundedBlank { origin } => {
                picture.fill_rect(ocean_cell(origin.x, origin.y), BOUNDED_MAP_BLANK);
            }
            OceanCell::Tile(ProjectedTile { tile, origin }) => {
                let tile_state = state.map()[tile];
                let owner = ocean_owner(tile_state.owner_nation);
                let water = tile_state.terrain == TerrainKind::Water;
                if !water {
                    picture.fill_rect(ocean_cell(origin.x, origin.y), OWNER_PALETTE[owner]);
                }
                if origin.x >= 0 {
                    draw_ocean_borders(
                        state,
                        tile,
                        origin.x,
                        origin.y,
                        owner,
                        tile_state.province,
                        water,
                        &mut picture,
                    );
                }
            }
        }
    }
    picture
}

fn ocean_owner(owner: Option<TileOwnerTag>) -> usize {
    owner.map_or(23, |owner| usize::from(owner.get().min(23)))
}

fn draw_improvements(
    surface: &mut IndexedPicture,
    state: &GameState,
    cells: &[OceanCell],
    assets: &OceanRenderAssets,
) {
    let active = MajorNationId::from_nation(state.turn().active_nation).map(|nation| {
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
    for &cell in cells {
        let OceanCell::Tile(ProjectedTile { tile, origin }) = cell else {
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
        let (picture, source_x) = if tile_state.action.is_some_and(|action| action.retail() >= 2) {
            let Some(active) = active else {
                continue;
            };
            (active, i32::from(tile_state.action.unwrap().retail()) * 16)
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
        blit_ocean_sprite(surface, picture, source_x, origin);
    }
}

fn ocean_improvement_source_x(tile: &TileState) -> i32 {
    let owner = tile.owner_nation.map(TileOwnerTag::get).unwrap_or(23);
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

fn draw_routes(picture: &mut IndexedPicture, state: &GameState, projection: &OceanProjection) {
    for route in &state.ocean().routes {
        let (start, end) = projection.route_segment(
            route.start_column,
            route.start_row,
            route.end_column,
            route.end_row,
        );
        picture.line_bresenham_inclusive(start, end, BORDER_PALETTE[23]);
    }
}

fn draw_unit_overlays(
    picture: &mut IndexedPicture,
    state: &GameState,
    projection: &OceanProjection,
    assets: &OceanRenderAssets,
) {
    for (_, civilian) in state.civilian_units() {
        let Some(tile) = civilian.location().tile() else {
            continue;
        };
        let Some(origin) = projection.tile_origin(tile) else {
            continue;
        };
        picture.fill_rect(
            ocean_cell(origin.x, origin.y),
            OWNER_PALETTE[ocean_owner(state.map()[tile].owner_nation)],
        );
        blit_ocean_sprite(picture, &assets.base_a, 0xe0, origin);
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
        let Some(origin) = projection.tile_origin(tile) else {
            continue;
        };
        picture.fill_rect(
            ocean_cell(origin.x, origin.y),
            OWNER_PALETTE[ocean_owner(state.map()[tile].owner_nation)],
        );
        let source_x = ocean_improvement_source_x(&state.map()[tile]);
        if source_x < 1024 {
            blit_ocean_sprite(picture, &assets.base_a, source_x, origin);
        } else {
            blit_ocean_sprite(picture, &assets.base_b, source_x - 1024, origin);
        }
    }
}

fn draw_selection(
    picture: &mut IndexedPicture,
    state: &GameState,
    projection: &OceanProjection,
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
    draw_ocean_tile_frame(picture, projection, hovered);
    if civilian.unit_type() != CivilianUnitKind::Engineer
        || action != CivilianTileAction::EngineerSameTile
        || state.map()[hovered].region.is_some()
    {
        return;
    }
    let owner = TileOwnerTag::from_nation(state.turn().active_nation);
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
            draw_ocean_tile_frame(picture, projection, neighbor);
        }
    }
}

fn draw_ocean_tile_frame(picture: &mut IndexedPicture, projection: &OceanProjection, tile: TileId) {
    let Some(origin) = projection.tile_origin(tile) else {
        return;
    };
    picture.frame_rect(ocean_cell(origin.x, origin.y), 0x20);
}

fn draw_ocean_borders(
    state: &GameState,
    tile: TileId,
    x: i32,
    y: i32,
    owner: usize,
    province: Option<ProvinceId>,
    water: bool,
    picture: &mut IndexedPicture,
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
        picture.put(IVec2::new(x + local_x, y + local_y), color);
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
        let pattern = usize::from(tile.get() % 4) * 4;
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
        let pattern = usize::from(neighbor_tile.get() % 4) * 4;
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
    let pattern = usize::from(pattern_tile.get() % 4) * 2;
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
    let pattern = usize::from(pattern_tile.get() % 4) * 2;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::test_support::{beginning_of_game_parts_with, strategic_map_beginning_context};

    fn pixel(picture: &IndexedPicture, x: usize, y: usize) -> u8 {
        picture.pixels[y * VIEWPORT_WIDTH + x]
    }

    fn render_base(state: &GameState, ocean: &OceanViewport) -> IndexedPicture {
        let cells = OceanProjection::new(state.map().geometry(), ocean).visible_cells();
        draw_base_ownership_and_borders(state, &cells)
    }

    fn clear_map(parts: &mut GameStateParts) {
        for index in 0..STRATEGIC_TILE_COUNT {
            let tile = TileId::new(index as u16);
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
        let land = parts.map.geometry().tile(2, 10).unwrap();
        parts.map[land].terrain = TerrainKind::Plains;
        parts.map[land].owner_nation = Some(TileOwnerTag::new(3));
        let state = GameState::from_parts(parts);
        let indices = render_base(&state, &OceanViewport::default());

        assert_eq!(pixel(&indices, 160, 40), OWNER_PALETTE[3]);
        assert_eq!(pixel(&indices, 176, 40), OCEAN_FILL);
    }

    #[test]
    fn city_boundary_is_a_straight_owner_colored_edge() {
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        clear_map(&mut parts);
        let tile = parts.map.geometry().tile(2, 10).unwrap();
        let west = parts
            .map
            .geometry()
            .neighbor(tile, HexDirection::West)
            .unwrap();
        parts.map[tile].terrain = TerrainKind::Plains;
        parts.map[tile].owner_nation = Some(TileOwnerTag::new(2));
        parts.map[tile].province = Some(ProvinceId::new(1));
        parts.map[west].terrain = TerrainKind::Plains;
        parts.map[west].owner_nation = Some(TileOwnerTag::new(2));
        parts.map[west].province = Some(ProvinceId::new(2));
        let state = GameState::from_parts(parts);
        let indices = render_base(&state, &OceanViewport::default());

        for y in 32..48 {
            assert_eq!(pixel(&indices, 152, y), BORDER_PALETTE[2]);
        }
    }

    #[test]
    fn different_owner_and_water_edges_use_the_retail_stipple_and_thickness() {
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        clear_map(&mut parts);
        let tile = parts.map.geometry().tile(2, 10).unwrap();
        let west = parts
            .map
            .geometry()
            .neighbor(tile, HexDirection::West)
            .unwrap();
        parts.map[tile].owner_nation = Some(TileOwnerTag::new(1));
        parts.map[west].terrain = TerrainKind::Plains;
        parts.map[west].owner_nation = Some(TileOwnerTag::new(2));
        let state = GameState::from_parts(parts);
        let indices = render_base(&state, &OceanViewport::default());

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
        let left = parts.map.geometry().tile(3, 0).unwrap();
        let right = parts.map.geometry().tile(3, 107).unwrap();
        parts.map[left].terrain = TerrainKind::Plains;
        parts.map[left].owner_nation = Some(TileOwnerTag::new(0));
        parts.map[right].terrain = TerrainKind::Plains;
        parts.map[right].owner_nation = Some(TileOwnerTag::new(1));
        let state = GameState::from_parts(parts);
        let indices = render_base(&state, &OceanViewport::default());

        assert_eq!(pixel(&indices, 0, 48), BORDER_PALETTE[0]);
        assert!(indices.pixels.contains(&BORDER_PALETTE[1]));
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
        let indices = render_base(&state, &ocean);

        assert_eq!(pixel(&indices, 511, 4), BOUNDED_MAP_BLANK);
    }

    #[test]
    fn bounded_projection_hides_opposite_edge_overlay_tiles() {
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        make_bounded(&mut parts);
        let tile = parts.map.geometry().tile(3, 0).unwrap();
        let ocean = OceanViewport {
            origin: IVec2::new(76, 0),
        };
        let projection = OceanProjection::new(parts.map.geometry(), &ocean);

        assert_eq!(projection.tile_origin(tile), None);
        assert!(projection.visible_cells().iter().any(|cell| matches!(
            cell,
            OceanCell::BoundedBlank { origin }
                if origin.x + OCEAN_CELL_SIZE > VIEWPORT_WIDTH as i32
        )));
    }

    #[test]
    fn overlay_blit_preserves_retail_transparency_index() {
        let mut indices = indexed_picture(VIEWPORT_WIDTH as i32, VIEWPORT_HEIGHT as i32, 0x44);
        let mut pixels = vec![0x10; 32 * 16];
        pixels[3 * 32 + 18] = 0x77;
        let picture = IndexedPicture {
            width: 32,
            height: 16,
            pixels,
        };
        blit_ocean_sprite(&mut indices, &picture, 16, IVec2::new(10, 20));
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
        let mut indices = indexed_picture(VIEWPORT_WIDTH as i32, VIEWPORT_HEIGHT as i32, 0);
        let projection = OceanProjection::new(state.map().geometry(), &ocean);
        draw_routes(&mut indices, &state, &projection);
        assert_eq!(pixel(&indices, 0, 32), BORDER_PALETTE[23]);
        assert_eq!(pixel(&indices, 8, 32), BORDER_PALETTE[23]);
        assert_eq!(pixel(&indices, 16, 32), 0);
        assert_eq!(pixel(&indices, 200, 32), 0);
    }
}
