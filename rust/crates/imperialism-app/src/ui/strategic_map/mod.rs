use super::RetailUiAssets;
use super::retail::RetailTree;
use super::retail_raster::{IndexedRasterExt, indexed_picture};
use super::session::GameSession;
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
mod map_projection;
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
    MapAction, MapEdges, StrategicMapSession, StrategicSelection, StrategicView,
};
pub(crate) use map_keys::register as register_map_keys;
pub(crate) use map_modals::register as register_map_modals;
use map_projection::DetailedMapProjection;
pub(crate) use minimap::{bind_minimap, sync_minimap};
pub(crate) use navy_toolbar::{bind_navy_toolbar, register as register_navy_toolbar};
pub(crate) use ocean_view::{bind_ocean_view, register as register_ocean_view};
use overlays::{
    IMPROVEMENT_PICTURE_IDS, compose_strategic_improvements, compose_strategic_railways,
    town_transport_linked,
};
use terrain::{compose_strategic_base_tile, uses_bounded_seam_frame};
pub(crate) use units::{animate_civilian_work, animate_strategic_selection, sync_strategic_units};

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
    pending_river_mouth_tile: Option<TileId>,
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
    survey_feedback: IndexedPicture,
    order_markers: IndexedPicture,
    composed: Option<StrategicMapComposeKey>,
}

#[derive(Clone, Copy)]
pub(super) struct StrategicMapSprites<'a> {
    pub(super) terrain: &'a [IndexedPicture],
    pub(super) river_masks: &'a [IndexedPicture],
    pub(super) improvements: &'a [IndexedPicture],
    pub(super) resource_icons: &'a IndexedPicture,
    pub(super) resource_overlays: &'a IndexedPicture,
    pub(super) survey_feedback: &'a IndexedPicture,
    pub(super) order_markers: &'a IndexedPicture,
}

pub(crate) fn bind_strategic_base_terrain(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    assets: &mut RetailUiAssets,
    session: &GameSession,
    origin: TileId,
) -> Entity {
    let state = &session.game;
    let view_origin = origin;
    let map = tree.find(root, MAP_TAG);
    let terrain_pictures = load_strategic_terrain_pictures(assets);
    let river_masks = load_strategic_river_masks(assets);
    let improvement_pictures = load_strategic_improvement_pictures(assets);
    let resource_icons = load_picture(assets, PictureId::new(750));
    let resource_overlays = load_picture(assets, PictureId::new(751));
    let survey_feedback = load_picture(assets, PictureId::new(801));
    let order_markers = load_picture(assets, PictureId::new(806));
    let selected_civilian = state
        .first_idle_civilian(state.turn().active_nation)
        .map(|(id, _)| id);
    let canvas = StrategicBaseTerrainCanvas {
        terrain_pictures,
        river_masks,
        improvement_pictures,
        resource_icons,
        resource_overlays,
        survey_feedback,
        order_markers,
        composed: Some(strategic_map_compose_key(
            state,
            view_origin,
            selected_civilian,
            None,
        )),
    };
    let image = compose_strategic_map(
        state,
        view_origin,
        selected_civilian,
        canvas.sprites(),
        assets.default_dib_palette(),
    );
    let image = assets.add_image(image);
    commands.entity(map).insert((
        ImageNode::new(image),
        RelativeCursorPosition::default(),
        canvas,
    ));
    units::bind_strategic_units(commands, map, assets, state, view_origin);
    bind_strategic_selection(commands, map, assets, state, view_origin, selected_civilian);
    map
}

fn bind_strategic_selection(
    commands: &mut Commands,
    map: Entity,
    assets: &mut RetailUiAssets,
    state: &GameState,
    view_origin: TileId,
    selected_civilian: Option<CivilianUnitId>,
) {
    let image = assets.add_image(compose_strategic_selection(
        state,
        view_origin,
        selected_civilian,
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
            composed: Some(strategic_map_compose_key(
                state,
                view_origin,
                selected_civilian,
                None,
            )),
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
            survey_feedback: &self.survey_feedback,
            order_markers: &self.order_markers,
        }
    }
}

pub(crate) fn sync_strategic_base_terrain(
    session: Res<GameSession>,
    map: Res<StrategicMapSession>,
    retail_assets: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut maps: Query<(&mut StrategicBaseTerrainCanvas, &ImageNode)>,
) {
    for (mut canvas, image_node) in &mut maps {
        let selected_civilian = map.selection.civilian();
        let origin = map.view.detailed_origin(&session.game);
        let key = strategic_map_compose_key(&session.game, origin, selected_civilian, None);
        if canvas.composed == Some(key) {
            continue;
        }
        let image = compose_strategic_map(
            &session.game,
            origin,
            selected_civilian,
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
    map: Res<StrategicMapSession>,
    retail_assets: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    maps: Query<&RelativeCursorPosition, With<StrategicBaseTerrainCanvas>>,
    mut overlays: Query<(&mut StrategicSelectionCanvas, &ImageNode)>,
) {
    for (mut overlay, image_node) in &mut overlays {
        let Ok(cursor) = maps.get(overlay.map) else {
            continue;
        };
        let origin = map.view.detailed_origin(&session.game);
        let hovered = strategic_base_terrain_tile_at_cursor(&session.game, origin, cursor);
        let key =
            strategic_map_compose_key(&session.game, origin, map.selection.civilian(), hovered);
        if overlay.composed == Some(key) {
            continue;
        }
        let image = compose_strategic_selection(
            &session.game,
            origin,
            map.selection.civilian(),
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
    match frame {
        0..=41 => PictureId::new(10_000).offset(frame as i16),
        42..=45 => PictureId::new(10_094).offset((frame - 42) as i16),
        46..=49 => PictureId::new(10_100).offset((frame - 46) as i16),
        50 => PictureId::new(10_110),
        _ => panic!("strategic terrain atlas frame {frame} is out of range"),
    }
}

fn load_strategic_improvement_pictures(assets: &RetailUiAssets) -> Vec<IndexedPicture> {
    IMPROVEMENT_PICTURE_IDS
        .iter()
        .map(|&id| load_tile_picture(assets, id))
        .collect()
}

fn load_picture(assets: &RetailUiAssets, picture_id: PictureId) -> IndexedPicture {
    assets.indexed_picture(picture_id).unwrap_or_else(|error| {
        panic!("retail strategic map picture {picture_id} must load: {error}")
    })
}

fn load_tile_picture(assets: &RetailUiAssets, picture_id: PictureId) -> IndexedPicture {
    let picture = load_picture(assets, picture_id);
    assert_eq!(
        (picture.width, picture.height),
        (TILE_SIZE as u32, TILE_SIZE as u32),
        "retail strategic map picture {picture_id} must be 64x64"
    );
    picture
}

fn river_mask_picture_id(mask: usize) -> PictureId {
    match mask {
        0..=15 => PictureId::new(10_048).offset(mask as i16),
        16..=23 => PictureId::new(10_086).offset((mask - 16) as i16),
        24..=29 => PictureId::new(10_042).offset((mask - 24) as i16),
        30..=35 => PictureId::new(10_080).offset((mask - 30) as i16),
        _ => panic!("strategic river mask {mask} is out of range"),
    }
}

fn compose_strategic_map(
    state: &GameState,
    view_origin: TileId,
    selected_civilian: Option<CivilianUnitId>,
    sprites: StrategicMapSprites<'_>,
    palette: &DibPalette,
) -> Image {
    compose_strategic_map_picture(state, view_origin, selected_civilian, sprites).to_image(palette)
}

fn compose_strategic_selection(
    state: &GameState,
    view_origin: TileId,
    selected_civilian: Option<CivilianUnitId>,
    hovered_tile: Option<TileId>,
    palette: &DibPalette,
) -> Image {
    let mut picture = indexed_picture(VIEWPORT_WIDTH as i32, VIEWPORT_HEIGHT as i32, 0);
    if let (Some(unit), Some(tile)) = (selected_civilian, hovered_tile) {
        draw_civilian_hover_highlight(state, view_origin, unit, tile, &mut picture);
    }
    picture.to_keyed_image(palette, 0)
}

fn strategic_map_compose_key(
    state: &GameState,
    view_origin: TileId,
    selected_civilian: Option<CivilianUnitId>,
    hovered_tile: Option<TileId>,
) -> StrategicMapComposeKey {
    use std::hash::Hasher;

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    let projection = DetailedMapProjection::new(state.map().geometry(), view_origin);
    for projected in projection.visible_tiles() {
        hash_visible_tile_facts(state, projected.tile, &mut hasher);
    }
    StrategicMapComposeKey {
        view_origin,
        topology: state.map().topology,
        active_nation: state.turn().active_nation,
        selected_civilian,
        hovered_tile,
        pending_river_mouth_tile: state.map().pending_river_mouth_tile,
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
    surface: &mut IndexedPicture,
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

    let projection = DetailedMapProjection::new(state.map().geometry(), view_origin);
    let Some(origin) = projection.tile_origin(hovered) else {
        return;
    };
    draw_frame(surface, origin.x, origin.y, MAP_SELECTION_PALETTE_INDEX);
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
    draw_city_site_neighbor_outline(&projection, neighbors, surface);
}

fn hash_visible_tile_facts(state: &GameState, tile: TileId, hasher: &mut impl std::hash::Hasher) {
    use std::hash::Hash;

    let tile_state = state.map()[tile];
    tile.get().hash(hasher);
    tile_state.terrain.hash(hasher);
    tile_state.gate.hash(hasher);
    tile_state.per_tile_visited.hash(hasher);
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
    tile_state.secondary_owner_nation.hash(hasher);
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

pub(super) fn compose_strategic_map_picture(
    state: &GameState,
    view_origin: TileId,
    selected_civilian: Option<CivilianUnitId>,
    sprites: StrategicMapSprites<'_>,
) -> IndexedPicture {
    compose_strategic_map_picture_with_city_overlay(
        state,
        view_origin,
        selected_civilian,
        true,
        sprites,
    )
}

fn compose_strategic_map_picture_with_city_overlay(
    state: &GameState,
    view_origin: TileId,
    selected_civilian: Option<CivilianUnitId>,
    city_overlay_visible: bool,
    sprites: StrategicMapSprites<'_>,
) -> IndexedPicture {
    let mut picture = indexed_picture(VIEWPORT_WIDTH as i32, VIEWPORT_HEIGHT as i32, 0);
    let projection = DetailedMapProjection::new(state.map().geometry(), view_origin);
    for projected in projection.visible_tiles() {
        let tile_picture = compose_strategic_tile_with_city_overlay(
            state,
            view_origin,
            projected.tile,
            selected_civilian,
            city_overlay_visible,
            sprites,
        );
        picture.copy_at(&tile_picture, projected.origin);
    }
    picture
}

pub(crate) fn compose_city_site_terrain(
    state: &GameState,
    view_origin: TileId,
    canvas: &StrategicBaseTerrainCanvas,
    nation: MajorNationId,
    highlighted_tile: Option<TileId>,
    palette: &DibPalette,
) -> Image {
    let mut picture = compose_strategic_map_picture_with_city_overlay(
        state,
        view_origin,
        None,
        false,
        canvas.sprites(),
    );
    if let Some(tile) = highlighted_tile {
        draw_city_site_selection(state, view_origin, nation, tile, &mut picture);
    }
    picture.to_image(palette)
}

pub(super) fn draw_city_site_selection(
    state: &GameState,
    view_origin: TileId,
    nation: MajorNationId,
    tile: TileId,
    surface: &mut IndexedPicture,
) {
    let projection = DetailedMapProjection::new(state.map().geometry(), view_origin);
    let Some(origin) = projection.tile_origin(tile) else {
        return;
    };
    draw_frame(surface, origin.x, origin.y, MAP_SELECTION_PALETTE_INDEX);

    let active_owner = TileOwnerTag::from_nation(nation.nation());
    let neighbors = state.map().geometry().neighbors(tile).map(|neighbor| {
        neighbor.filter(|&neighbor| {
            let neighbor = state.map()[neighbor];
            neighbor.terrain == TerrainKind::Water || neighbor.owner_nation == Some(active_owner)
        })
    });
    draw_city_site_neighbor_outline(&projection, neighbors, surface);
}

fn draw_frame(surface: &mut IndexedPicture, x: i32, y: i32, color: u8) {
    surface.frame_rect(IRect::new(x, y, x + TILE_SIZE, y + TILE_SIZE), color);
}

fn draw_city_site_neighbor_outline(
    projection: &DetailedMapProjection,
    neighbors: [Option<TileId>; 6],
    viewport: &mut IndexedPicture,
) {
    const OUTLINE_COLOR: u8 = MAP_SELECTION_PALETTE_INDEX;
    for (index, neighbor) in neighbors.iter().copied().enumerate() {
        let Some(neighbor) = neighbor else {
            continue;
        };
        let Some(origin) = projection.tile_origin(neighbor) else {
            continue;
        };
        let (x, y) = (origin.x, origin.y);
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

fn draw_line(surface: &mut IndexedPicture, start: (i32, i32), end: (i32, i32), color: u8) {
    surface.line_to_gdi(start.into(), end.into(), color, 1);
}

#[cfg(test)]
pub(super) fn compose_strategic_tile(
    state: &GameState,
    view_origin: TileId,
    tile: TileId,
    selected_civilian: Option<CivilianUnitId>,
    sprites: StrategicMapSprites<'_>,
) -> IndexedPicture {
    compose_strategic_tile_with_city_overlay(
        state,
        view_origin,
        tile,
        selected_civilian,
        true,
        sprites,
    )
}

fn compose_strategic_tile_with_city_overlay(
    state: &GameState,
    view_origin: TileId,
    tile: TileId,
    selected_civilian: Option<CivilianUnitId>,
    city_overlay_visible: bool,
    sprites: StrategicMapSprites<'_>,
) -> IndexedPicture {
    let tile_state = state.map()[tile];
    let wrapped_seam = uses_bounded_seam_frame(state, view_origin, tile);
    let mut picture = compose_strategic_base_tile(
        state,
        view_origin,
        tile,
        sprites.terrain,
        sprites.river_masks,
    );

    if !wrapped_seam {
        compose_strategic_borders(state, tile, &mut picture);
    }
    compose_strategic_railways(&tile_state, sprites.river_masks, &mut picture);
    compose_strategic_improvements(state, tile, city_overlay_visible, sprites, &mut picture);
    overlays::compose_strategic_survey_feedback(
        state,
        tile,
        selected_civilian,
        sprites.survey_feedback,
        &mut picture,
    );
    overlays::compose_strategic_activity_overlay(
        state,
        tile,
        sprites.resource_overlays,
        &mut picture,
    );
    overlays::compose_strategic_order_overlay(state, tile, sprites, &mut picture);
    picture
}

fn viewport_point(normalized: Vec2) -> IVec2 {
    IVec2::new(
        ((normalized.x + 0.5) * VIEWPORT_WIDTH as f32).floor() as i32,
        ((normalized.y + 0.5) * VIEWPORT_HEIGHT as f32).floor() as i32,
    )
}

fn strategic_tile_at_position(
    state: &GameState,
    view_origin: TileId,
    normalized: Vec2,
) -> Option<TileId> {
    DetailedMapProjection::new(state.map().geometry(), view_origin)
        .tile_at(viewport_point(normalized))
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
