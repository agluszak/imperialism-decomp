use super::GameSession;
use super::RetailUiAssets;
use super::retail::RetailTree;
use super::retail_raster::IndexedSurface;
use crate::RetailAssetsResource;
use bevy::prelude::*;
use bevy::ui::RelativeCursorPosition;
use imperialism_core::*;
use imperialism_formats::*;

mod army_toolbar;
mod borders;
mod civilian_toolbar;
mod map_click;
mod map_interaction;
mod map_keys;
mod map_modals;
mod minimap;
mod navy_toolbar;
mod ocean_raster;
mod ocean_view;
mod overlays;
mod terrain;
mod units;

pub(crate) use army_toolbar::{bind_army_toolbar, register as register_army_toolbar};
use borders::compose_strategic_borders;
pub(crate) use civilian_toolbar::{bind_civilian_toolbar, register_civilian_toolbar};
pub(crate) use map_click::{on_strategic_map_click, register as register_map_click};
pub(crate) use map_interaction::{
    MapEdges, MapInteractionMode, MapProjection, MapTransition, MapZoomControl,
    StrategicInteraction, StrategicViewport, apply_map_transition,
};
pub(crate) use map_keys::register as register_map_keys;
pub(crate) use map_modals::register as register_map_modals;
pub(crate) use minimap::{bind_minimap, sync_minimap};
pub(crate) use navy_toolbar::{bind_navy_toolbar, register as register_navy_toolbar};
pub(crate) use ocean_view::{bind_ocean_view, register as register_ocean_view};
use overlays::{
    IMPROVEMENT_PICTURE_IDS, compose_strategic_improvements, compose_strategic_railways,
    town_transport_linked,
};
use terrain::{compose_strategic_base_tile, frame_for_offset};
pub(crate) use units::{animate_civilian_selection, animate_civilian_work, sync_strategic_units};

const MAP_TAG: FourCc = fourcc!("DLOG");
pub(super) const VIEWPORT_WIDTH: usize = 512;
pub(super) const VIEWPORT_HEIGHT: usize = 448;
pub(super) const TILE_SIZE: i32 = 64;
pub(super) const VIEWPORT_TILE_SPAN: i32 = 9;
const MAP_SELECTION_PALETTE_INDEX: u8 = 0x20;
const TERRAIN_ATLAS_FRAME_COUNT: usize = 51;
pub(super) const RIVER_MASK_PICTURE_COUNT: usize = 36;
pub(super) const RIVER_MASK_TRANSPARENT_INDEX: u8 = 0x10;

/// Facts that change the composed strategic-map bitmap. Session-wide Bevy change detection is broader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StrategicMapComposeKey {
    view_origin: TileId,
    topology: MapTopology,
    active_nation: NationId,
    selected_civilian: Option<CivilianUnitId>,
    hovered_tile: Option<TileId>,
    visible_tiles: u64,
}

#[derive(Component)]
pub(crate) struct StrategicSelectionCanvas {
    map: Entity,
    composed: Option<StrategicMapComposeKey>,
}

/// The bounded strategic map: retail bases, transitions, rivers, borders, and static infrastructure.
#[derive(Component)]
pub(crate) struct StrategicBaseTerrainCanvas {
    terrain_pictures: Vec<IndexedPicture>,
    river_masks: Vec<IndexedPicture>,
    improvement_pictures: Vec<IndexedPicture>,
    resource_icons: IndexedPicture,
    resource_overlays: IndexedPicture,
    composed: Option<StrategicMapComposeKey>,
}

#[derive(Clone, Copy)]
pub(super) struct StrategicMapSprites<'a> {
    pub(super) terrain: &'a [IndexedPicture],
    pub(super) river_masks: &'a [IndexedPicture],
    pub(super) improvements: &'a [IndexedPicture],
    pub(super) resource_icons: &'a IndexedPicture,
    pub(super) resource_overlays: &'a IndexedPicture,
}

pub(crate) fn bind_strategic_base_terrain(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    assets: &mut RetailUiAssets,
    session: &GameSession,
) -> Entity {
    let state = &session.game;
    let view_origin = session.map_view_origin;
    let map = tree.find(root, MAP_TAG);
    let terrain_pictures = load_strategic_terrain_pictures(assets);
    let river_masks = load_strategic_river_masks(assets);
    let improvement_pictures = load_strategic_improvement_pictures(assets);
    let resource_icons = load_picture(assets, 750);
    let resource_overlays = load_picture(assets, 751);
    let canvas = StrategicBaseTerrainCanvas {
        terrain_pictures,
        river_masks,
        improvement_pictures,
        resource_icons,
        resource_overlays,
        composed: Some(strategic_map_compose_key(state, view_origin, None, None)),
    };
    let image = compose_strategic_map(
        state,
        view_origin,
        canvas.sprites(),
        assets.default_dib_palette(),
    );
    let image = assets.add_image(image);
    commands.entity(map).insert((
        ImageNode::new(image),
        RelativeCursorPosition::default(),
        canvas,
        StrategicInteraction::default(),
        StrategicViewport::default(),
    ));
    units::bind_strategic_units(commands, map, assets, state, view_origin);
    bind_strategic_selection(commands, map, assets, state, view_origin);
    map
}

fn bind_strategic_selection(
    commands: &mut Commands,
    map: Entity,
    assets: &mut RetailUiAssets,
    state: &GameState,
    view_origin: TileId,
) {
    let image = assets.add_image(compose_strategic_selection(
        state,
        view_origin,
        None,
        None,
        assets.default_dib_palette(),
    ));
    commands.spawn((
        Node {
            position_type: PositionType::Absolute,
            left: px(0),
            top: px(0),
            width: px(VIEWPORT_WIDTH),
            height: px(VIEWPORT_HEIGHT),
            ..default()
        },
        ImageNode::new(image),
        ZIndex(3),
        Pickable::IGNORE,
        StrategicSelectionCanvas {
            map,
            composed: Some(strategic_map_compose_key(state, view_origin, None, None)),
        },
        ChildOf(map),
    ));
}

impl StrategicBaseTerrainCanvas {
    fn sprites(&self) -> StrategicMapSprites<'_> {
        StrategicMapSprites {
            terrain: &self.terrain_pictures,
            river_masks: &self.river_masks,
            improvements: &self.improvement_pictures,
            resource_icons: &self.resource_icons,
            resource_overlays: &self.resource_overlays,
        }
    }
}

pub(crate) fn sync_strategic_base_terrain(
    session: Res<GameSession>,
    retail_assets: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut maps: Query<(&mut StrategicBaseTerrainCanvas, &ImageNode)>,
) {
    for (mut canvas, image_node) in &mut maps {
        let key = strategic_map_compose_key(&session.game, session.map_view_origin, None, None);
        if canvas.composed == Some(key) {
            continue;
        }
        let image = compose_strategic_map(
            &session.game,
            session.map_view_origin,
            canvas.sprites(),
            retail_assets.assets().default_dib_palette(),
        );
        let Some(mut existing) = images.get_mut(&image_node.image) else {
            continue;
        };
        *existing = image;
        canvas.composed = Some(key);
    }
}

pub(crate) fn sync_strategic_selection(
    session: Res<GameSession>,
    retail_assets: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    maps: Query<(&StrategicInteraction, &RelativeCursorPosition)>,
    mut overlays: Query<(&mut StrategicSelectionCanvas, &ImageNode)>,
) {
    for (mut overlay, image_node) in &mut overlays {
        let Ok((selected, cursor)) = maps.get(overlay.map) else {
            continue;
        };
        let hovered =
            strategic_base_terrain_tile_at_cursor(&session.game, session.map_view_origin, cursor);
        let key = strategic_map_compose_key(
            &session.game,
            session.map_view_origin,
            selected.civilian,
            hovered,
        );
        if overlay.composed == Some(key) {
            continue;
        }
        let image = compose_strategic_selection(
            &session.game,
            session.map_view_origin,
            selected.civilian,
            hovered,
            retail_assets.assets().default_dib_palette(),
        );
        let Some(mut existing) = images.get_mut(&image_node.image) else {
            continue;
        };
        *existing = image;
        overlay.composed = Some(key);
    }
}

fn load_strategic_terrain_pictures(assets: &RetailUiAssets) -> Vec<IndexedPicture> {
    (0..TERRAIN_ATLAS_FRAME_COUNT)
        .map(|frame| {
            let picture_id = strategic_terrain_picture_id(frame);
            let picture = assets.indexed_picture(picture_id).unwrap_or_else(|error| {
                panic!("retail strategic terrain picture {picture_id} must load: {error}")
            });
            assert_eq!(
                (picture.width, picture.height),
                (TILE_SIZE as u32, TILE_SIZE as u32),
                "retail strategic terrain picture {picture_id} must be 64x64"
            );
            picture
        })
        .collect()
}

fn load_strategic_river_masks(assets: &RetailUiAssets) -> Vec<IndexedPicture> {
    (0..RIVER_MASK_PICTURE_COUNT)
        .map(|mask| {
            let picture_id = river_mask_picture_id(mask);
            let picture = assets.indexed_picture(picture_id).unwrap_or_else(|error| {
                panic!("retail strategic river mask {picture_id} must load: {error}")
            });
            assert_eq!(
                (picture.width, picture.height),
                (TILE_SIZE as u32, TILE_SIZE as u32),
                "retail strategic river mask {picture_id} must be 64x64"
            );
            picture
        })
        .collect()
}

fn strategic_terrain_picture_id(frame: usize) -> PictureId {
    let id = match frame {
        0..=41 => 10_000 + frame as i16,
        42..=45 => 10_094 + (frame - 42) as i16,
        46..=49 => 10_100 + (frame - 46) as i16,
        50 => 10_110,
        _ => panic!("strategic terrain atlas frame {frame} is out of range"),
    };
    PictureId::new(id)
}

fn load_strategic_improvement_pictures(assets: &RetailUiAssets) -> Vec<IndexedPicture> {
    IMPROVEMENT_PICTURE_IDS
        .iter()
        .map(|&id| load_tile_picture(assets, id))
        .collect()
}

fn load_picture(assets: &RetailUiAssets, id: i16) -> IndexedPicture {
    let picture_id = PictureId::new(id);
    assets.indexed_picture(picture_id).unwrap_or_else(|error| {
        panic!("retail strategic map picture {picture_id} must load: {error}")
    })
}

fn load_tile_picture(assets: &RetailUiAssets, id: i16) -> IndexedPicture {
    let picture = load_picture(assets, id);
    assert_eq!(
        (picture.width, picture.height),
        (TILE_SIZE as u32, TILE_SIZE as u32),
        "retail strategic map picture {id} must be 64x64"
    );
    picture
}

fn river_mask_picture_id(mask: usize) -> PictureId {
    let id = match mask {
        0..=15 => 10_048 + mask as i16,
        16..=23 => 10_086 + (mask - 16) as i16,
        24..=29 => 10_042 + (mask - 24) as i16,
        30..=35 => 10_080 + (mask - 30) as i16,
        _ => panic!("strategic river mask {mask} is out of range"),
    };
    PictureId::new(id)
}

fn compose_strategic_map(
    state: &GameState,
    view_origin: TileId,
    sprites: StrategicMapSprites<'_>,
    palette: &DibPalette,
) -> Image {
    let indices = compose_strategic_map_indices(state, view_origin, sprites);
    indexed_viewport_image(indices, palette)
}

fn compose_strategic_selection(
    state: &GameState,
    view_origin: TileId,
    selected_civilian: Option<CivilianUnitId>,
    hovered_tile: Option<TileId>,
    palette: &DibPalette,
) -> Image {
    let mut surface = IndexedSurface::new(VIEWPORT_WIDTH as i32, VIEWPORT_HEIGHT as i32, 0);
    if let (Some(unit), Some(tile)) = (selected_civilian, hovered_tile) {
        draw_civilian_hover_highlight(state, view_origin, unit, tile, &mut surface);
    }
    surface.to_keyed_image(palette, 0)
}

fn strategic_map_compose_key(
    state: &GameState,
    view_origin: TileId,
    selected_civilian: Option<CivilianUnitId>,
    hovered_tile: Option<TileId>,
) -> StrategicMapComposeKey {
    use std::hash::Hasher;

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for_each_visible_strategic_tile(state, view_origin, |tile, _screen_x, _screen_y| {
        hash_visible_tile_facts(state, tile, &mut hasher);
    });
    StrategicMapComposeKey {
        view_origin,
        topology: state.map().topology,
        active_nation: state.turn().active_nation,
        selected_civilian,
        hovered_tile,
        visible_tiles: hasher.finish(),
    }
}

/// `TMapDialog::RenderStrategicTileSelectionAndNeighborHighlights`: an actionable
/// civilian cursor frames its hovered tile. The engineer's same-tile construction
/// cursor also outlines the adjacent water or domestic non-city construction choices.
fn draw_civilian_hover_highlight(
    state: &GameState,
    view_origin: TileId,
    unit: CivilianUnitId,
    hovered: TileId,
    surface: &mut IndexedSurface,
) {
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

    let (x, y) = strategic_tile_screen_origin(state, view_origin, hovered);
    draw_frame(surface, x, y, MAP_SELECTION_PALETTE_INDEX);
    if civilian.unit_type() != CivilianUnitKind::Engineer
        || action != CivilianTileAction::EngineerSameTile
        || state.map()[hovered].region.is_some()
    {
        return;
    }
    let owner = TileOwnerTag::from_nation(state.turn().active_nation);
    let neighbors = state.map().geometry().neighbors(hovered).map(|neighbor| {
        neighbor.filter(|&neighbor| {
            let neighbor = state.map()[neighbor];
            neighbor.region.is_none()
                && (neighbor.terrain == TerrainKind::Water || neighbor.owner_nation == Some(owner))
        })
    });
    draw_city_site_neighbor_outline(state, view_origin, neighbors, surface);
}

fn hash_visible_tile_facts(state: &GameState, tile: TileId, hasher: &mut impl std::hash::Hasher) {
    use std::hash::Hash;

    let tile_state = state.map()[tile];
    tile.get().hash(hasher);
    tile_state.terrain.hash(hasher);
    tile_state.gate.hash(hasher);
    tile_state.recruit_search_visited.hash(hasher);
    tile_state.rendering.sprite_variant.hash(hasher);
    tile_state
        .rendering
        .river_sprite
        .map(RiverSprite::retail)
        .hash(hasher);
    tile_state.rendering.transition_mask.hash(hasher);
    tile_state.rendering.coast_or_secondary_mask.hash(hasher);
    tile_state.owner_nation.hash(hasher);
    tile_state.former_owner_nation.hash(hasher);
    tile_state.owner_border_mask.hash(hasher);
    tile_state.city_border_mask.hash(hasher);
    tile_state.flags.bits().hash(hasher);
    tile_state.transport_links.bits().hash(hasher);
    tile_state.pending_rail_links.bits().hash(hasher);
    tile_state.development.surface.get().hash(hasher);
    tile_state.development.extractive.get().hash(hasher);
    for nation in MajorNationId::all() {
        tile_state.development.resource_visible_to_majors[nation].hash(hasher);
    }
    tile_state.edge_resources.hash(hasher);
    town_transport_linked(state, tile).hash(hasher);
    if let Some(province) = tile_state.province {
        let province = &state.map().provinces[province];
        province.development_stage().hash(hasher);
        province.fort_level().hash(hasher);
    }
    for neighbor in state.map().geometry().neighbors(tile) {
        let Some(neighbor) = neighbor else {
            false.hash(hasher);
            continue;
        };
        true.hash(hasher);
        let neighbor = state.map()[neighbor];
        neighbor.owner_nation.hash(hasher);
        neighbor.terrain.hash(hasher);
    }
}

pub(super) fn for_each_visible_strategic_tile(
    state: &GameState,
    view_origin: TileId,
    mut visit: impl FnMut(TileId, i32, i32),
) {
    let (origin_row, origin_column) = state.map().geometry().row_column(view_origin);
    let origin_row = i32::from(origin_row);
    let origin_column = i32::from(origin_column);

    for row_delta in 0..=7 {
        let row = origin_row + row_delta;
        if !(0..i32::from(STRATEGIC_MAP_HEIGHT)).contains(&row) {
            continue;
        }
        let odd_row_offset = if row & 1 != 0 { TILE_SIZE / 2 } else { 0 };
        let screen_y = row_delta * TILE_SIZE;
        for column_delta in -1..=8 {
            let unwrapped_column = origin_column + column_delta;
            let screen_x = column_delta * TILE_SIZE + odd_row_offset;
            if screen_x >= VIEWPORT_WIDTH as i32 || screen_x + TILE_SIZE <= 0 {
                continue;
            }
            let column = normalize_map_column(unwrapped_column);
            let Some(tile) = state.map().geometry().tile(row as u16, column as u16) else {
                continue;
            };
            visit(tile, screen_x, screen_y);
        }
    }
}

pub(super) fn compose_strategic_map_indices(
    state: &GameState,
    view_origin: TileId,
    sprites: StrategicMapSprites<'_>,
) -> Vec<u8> {
    let mut surface = IndexedSurface::new(VIEWPORT_WIDTH as i32, VIEWPORT_HEIGHT as i32, 0);
    for_each_visible_strategic_tile(state, view_origin, |tile, screen_x, screen_y| {
        let tile_pixels = compose_strategic_tile(state, view_origin, tile, sprites);
        let tile_picture = IndexedPicture {
            width: TILE_SIZE as u32,
            height: TILE_SIZE as u32,
            pixels: tile_pixels,
        };
        surface.copy_rect(
            &tile_picture,
            IRect::new(0, 0, TILE_SIZE, TILE_SIZE),
            IVec2::new(screen_x, screen_y),
        );
    });
    surface.into_pixels()
}

pub(crate) fn compose_city_site_terrain(
    state: &GameState,
    view_origin: TileId,
    canvas: &StrategicBaseTerrainCanvas,
    nation: MajorNationId,
    highlighted_tile: Option<TileId>,
    palette: &DibPalette,
) -> Image {
    let mut surface = IndexedSurface::from_pixels(
        VIEWPORT_WIDTH as i32,
        VIEWPORT_HEIGHT as i32,
        compose_strategic_map_indices(state, view_origin, canvas.sprites()),
    );
    if let Some(tile) = highlighted_tile {
        draw_city_site_selection(state, view_origin, nation, tile, &mut surface);
    }
    surface.to_image(palette)
}

pub(super) fn draw_city_site_selection(
    state: &GameState,
    view_origin: TileId,
    nation: MajorNationId,
    tile: TileId,
    surface: &mut IndexedSurface,
) {
    let (x, y) = strategic_tile_screen_origin(state, view_origin, tile);
    draw_frame(surface, x, y, MAP_SELECTION_PALETTE_INDEX);

    let active_owner = TileOwnerTag::from_nation(nation.nation());
    let neighbors = state.map().geometry().neighbors(tile).map(|neighbor| {
        neighbor.filter(|&neighbor| {
            let neighbor = state.map()[neighbor];
            neighbor.terrain == TerrainKind::Water || neighbor.owner_nation == Some(active_owner)
        })
    });
    draw_city_site_neighbor_outline(state, view_origin, neighbors, surface);
}

fn draw_frame(surface: &mut IndexedSurface, x: i32, y: i32, color: u8) {
    surface.frame_rect(IRect::new(x, y, x + TILE_SIZE, y + TILE_SIZE), color);
}

fn draw_city_site_neighbor_outline(
    state: &GameState,
    view_origin: TileId,
    neighbors: [Option<TileId>; 6],
    viewport: &mut IndexedSurface,
) {
    const OUTLINE_COLOR: u8 = MAP_SELECTION_PALETTE_INDEX;
    for (index, neighbor) in neighbors.iter().copied().enumerate() {
        let Some(neighbor) = neighbor else {
            continue;
        };
        let (x, y) = strategic_tile_screen_origin(state, view_origin, neighbor);
        match index {
            0 => {
                draw_line(viewport, (x, y), (x + 63, y), OUTLINE_COLOR);
                draw_line(viewport, (x + 63, y), (x + 63, y + 63), OUTLINE_COLOR);
                if neighbors[5].is_none() {
                    draw_line(viewport, (x, y), (x, y + 63), OUTLINE_COLOR);
                }
                if neighbors[1].is_none() {
                    draw_line(viewport, (x + 32, y), (x + 32, y + 63), OUTLINE_COLOR);
                }
            }
            1 => {
                draw_line(viewport, (x + 32, y), (x + 63, y), OUTLINE_COLOR);
                draw_line(viewport, (x + 63, y), (x + 63, y + 63), OUTLINE_COLOR);
                draw_line(viewport, (x + 63, y + 63), (x + 32, y + 63), OUTLINE_COLOR);
                if neighbors[0].is_none() {
                    draw_line(viewport, (x, y), (x + 32, y), OUTLINE_COLOR);
                }
                if neighbors[2].is_none() {
                    draw_line(viewport, (x, y + 63), (x + 32, y + 63), OUTLINE_COLOR);
                }
            }
            2 => {
                draw_line(viewport, (x, y + 63), (x + 63, y + 63), OUTLINE_COLOR);
                draw_line(viewport, (x + 63, y + 63), (x + 63, y), OUTLINE_COLOR);
                if neighbors[3].is_none() {
                    draw_line(viewport, (x, y), (x, y + 63), OUTLINE_COLOR);
                }
                if neighbors[1].is_none() {
                    draw_line(viewport, (x + 32, y), (x + 63, y), OUTLINE_COLOR);
                }
            }
            3 => {
                draw_line(viewport, (x + 63, y + 63), (x, y + 63), OUTLINE_COLOR);
                draw_line(viewport, (x, y + 63), (x, y), OUTLINE_COLOR);
                if neighbors[2].is_none() {
                    draw_line(viewport, (x + 63, y), (x + 63, y + 63), OUTLINE_COLOR);
                }
                if neighbors[4].is_none() {
                    draw_line(viewport, (x, y), (x + 32, y), OUTLINE_COLOR);
                }
            }
            4 => {
                draw_line(viewport, (x + 32, y), (x, y), OUTLINE_COLOR);
                draw_line(viewport, (x, y), (x, y + 63), OUTLINE_COLOR);
                draw_line(viewport, (x, y + 63), (x + 32, y + 63), OUTLINE_COLOR);
                if neighbors[5].is_none() {
                    draw_line(viewport, (x + 32, y), (x + 63, y), OUTLINE_COLOR);
                }
                if neighbors[3].is_none() {
                    draw_line(viewport, (x + 32, y + 63), (x + 63, y + 63), OUTLINE_COLOR);
                }
            }
            5 => {
                draw_line(viewport, (x, y + 63), (x, y), OUTLINE_COLOR);
                draw_line(viewport, (x, y), (x + 63, y), OUTLINE_COLOR);
                if neighbors[0].is_none() {
                    draw_line(viewport, (x + 63, y), (x + 63, y + 63), OUTLINE_COLOR);
                }
                if neighbors[4].is_none() {
                    draw_line(viewport, (x, y + 63), (x + 32, y + 63), OUTLINE_COLOR);
                }
            }
            _ => unreachable!("strategic tile has six neighbors"),
        }
    }
}

pub(super) fn strategic_tile_screen_origin(
    state: &GameState,
    view_origin: TileId,
    tile: TileId,
) -> (i32, i32) {
    let (origin_row, origin_column) = state.map().geometry().row_column(view_origin);
    let (row, column) = state.map().geometry().row_column(tile);
    let y = (i32::from(row) - i32::from(origin_row)) * TILE_SIZE;
    let mut x = (i32::from(column) - i32::from(origin_column)) * TILE_SIZE;
    if row & 1 != 0 {
        x += TILE_SIZE / 2;
        if x >= 0x1ae0 {
            x -= 0x1b00;
        }
    }
    while x < -TILE_SIZE {
        x += 0x1b00;
    }
    (x, y)
}

fn draw_line(surface: &mut IndexedSurface, start: (i32, i32), end: (i32, i32), color: u8) {
    surface.line_to_gdi(start.into(), end.into(), color, 1);
}

pub(super) fn compose_strategic_tile(
    state: &GameState,
    view_origin: TileId,
    tile: TileId,
    sprites: StrategicMapSprites<'_>,
) -> Vec<u8> {
    let tile_state = state.map()[tile];
    let center_column = {
        let (_, origin_column) = state.map().geometry().row_column(view_origin);
        (i32::from(origin_column) + VIEWPORT_TILE_SPAN / 2)
            .rem_euclid(i32::from(STRATEGIC_MAP_WIDTH))
    };
    let (_, tile_column) = state.map().geometry().row_column(tile);
    // Retail's stored flag is inverted: this seam substitution belongs to Rust's bounded map.
    let wrapped_seam = state.map().topology == MapTopology::Bounded
        && ((tile_column == 0 && center_column > 54)
            || (tile_column == STRATEGIC_MAP_WIDTH - 1 && center_column < 54));
    let pixels = if wrapped_seam {
        sprites.terrain[frame_for_offset(0xc80)].pixels.clone()
    } else {
        compose_strategic_base_tile(
            state,
            view_origin,
            tile,
            sprites.terrain,
            sprites.river_masks,
        )
    };
    let mut surface = IndexedSurface::from_pixels(TILE_SIZE, TILE_SIZE, pixels);

    if !wrapped_seam {
        compose_strategic_borders(state, tile, &mut surface);
    }
    compose_strategic_railways(&tile_state, sprites.river_masks, &mut surface);
    compose_strategic_improvements(state, tile, sprites, &mut surface);
    surface.into_pixels()
}

fn normalize_map_column(column: i32) -> i32 {
    // Draw and ConvertPoint modulo the column even when the viewport itself is bounded.
    column.rem_euclid(i32::from(STRATEGIC_MAP_WIDTH))
}

fn indexed_viewport_image(indices: Vec<u8>, palette: &DibPalette) -> Image {
    IndexedSurface::from_pixels(VIEWPORT_WIDTH as i32, VIEWPORT_HEIGHT as i32, indices)
        .to_image(palette)
}

fn strategic_tile_at_position(
    state: &GameState,
    view_origin: TileId,
    normalized: Vec2,
) -> Option<TileId> {
    let x = ((normalized.x + 0.5) * VIEWPORT_WIDTH as f32).floor() as i32;
    let y = ((normalized.y + 0.5) * VIEWPORT_HEIGHT as f32).floor() as i32;
    if !(0..VIEWPORT_WIDTH as i32).contains(&x) || !(0..VIEWPORT_HEIGHT as i32).contains(&y) {
        return None;
    }
    let (origin_row, origin_column) = state.map().geometry().row_column(view_origin);
    let row = i32::from(origin_row) + y / TILE_SIZE;
    if !(0..i32::from(STRATEGIC_MAP_HEIGHT)).contains(&row) {
        return None;
    }
    let absolute_x = i32::from(origin_column) * TILE_SIZE + x;
    let column = if row & 1 != 0 {
        (absolute_x + TILE_SIZE / 2) / TILE_SIZE - 1
    } else {
        absolute_x / TILE_SIZE
    };
    let column = normalize_map_column(column);
    state.map().geometry().tile(row as u16, column as u16)
}

pub(crate) fn strategic_base_terrain_tile_at_cursor(
    state: &GameState,
    view_origin: TileId,
    cursor: &RelativeCursorPosition,
) -> Option<TileId> {
    cursor
        .normalized
        .filter(|_| cursor.cursor_over())
        .and_then(|position| strategic_tile_at_position(state, view_origin, position))
}

#[cfg(test)]
mod tests;
