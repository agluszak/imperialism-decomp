use super::GameSession;
use super::RetailUiAssets;
use super::retail::{RetailTag, find_descendant};
use crate::RetailAssetsResource;
use bevy::asset::RenderAssetUsages;
use bevy::image::ImageSampler;
use bevy::prelude::*;
use bevy::render::render_resource::{Extent3d, TextureDimension, TextureFormat};
use bevy::ui::RelativeCursorPosition;
use imperialism_core::*;
use imperialism_formats::*;

mod borders;
mod civilian_orders;
mod civilian_toolbar;
mod minimap;
mod overlays;
mod terrain;
mod units;

use borders::compose_strategic_borders;
use civilian_orders::StrategicSelection;
pub(crate) use civilian_orders::register as register_civilian_orders;
pub(crate) use civilian_toolbar::{bind_civilian_toolbar, register_civilian_toolbar};
pub(crate) use minimap::{bind_minimap, sync_minimap};
use overlays::{
    IMPROVEMENT_PICTURE_IDS, compose_strategic_improvements, compose_strategic_railways,
    town_transport_linked,
};
use terrain::{compose_strategic_base_tile, frame_for_offset};
pub(crate) use units::sync_strategic_units;

const MAP_TAG: FourCc = fourcc!("DLOG");
pub(super) const VIEWPORT_WIDTH: usize = 512;
pub(super) const VIEWPORT_HEIGHT: usize = 448;
pub(super) const TILE_SIZE: i32 = 64;
pub(super) const VIEWPORT_TILE_SPAN: i32 = 9;
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
    visible_tiles: u64,
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
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    assets: &mut RetailUiAssets,
    state: &GameState,
) -> Entity {
    let map = find_descendant(root, MAP_TAG, children, tags);
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
        composed: Some(strategic_map_compose_key(state, None)),
    };
    let image = compose_strategic_map(state, canvas.sprites(), assets.default_dib_palette(), None);
    let image = assets.add_image(image);
    commands.entity(map).insert((
        ImageNode::new(image),
        RelativeCursorPosition::default(),
        canvas,
        StrategicSelection::default(),
    ));
    units::bind_strategic_units(commands, map, assets, state);
    map
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
    mut maps: Query<(
        &mut StrategicBaseTerrainCanvas,
        &ImageNode,
        Ref<StrategicSelection>,
    )>,
) {
    for (mut canvas, image_node, selected) in &mut maps {
        if !session.is_changed() && !selected.is_changed() {
            continue;
        }
        let key = strategic_map_compose_key(&session.game, selected.0);
        if canvas.composed == Some(key) {
            continue;
        }
        let image = compose_strategic_map(
            &session.game,
            canvas.sprites(),
            retail_assets.assets().default_dib_palette(),
            selected.0,
        );
        let Some(mut existing) = images.get_mut(&image_node.image) else {
            continue;
        };
        *existing = image;
        canvas.composed = Some(key);
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
    sprites: StrategicMapSprites<'_>,
    palette: &DibPalette,
    selected_civilian: Option<CivilianUnitId>,
) -> Image {
    let mut indices = compose_strategic_map_indices(state, sprites);
    if let Some(unit) = selected_civilian.filter(|&unit| {
        state.civilian_units().iter().any(|candidate| {
            candidate.id() == unit && candidate.unit_type() == CivilianUnitKind::Engineer
        })
    }) {
        draw_rail_order_selection(state, unit, &mut indices);
    }
    indexed_viewport_image(&indices, palette)
}

fn strategic_map_compose_key(
    state: &GameState,
    selected_civilian: Option<CivilianUnitId>,
) -> StrategicMapComposeKey {
    use std::hash::Hasher;

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for_each_visible_strategic_tile(state, |tile, _screen_x, _screen_y| {
        hash_visible_tile_facts(state, tile, &mut hasher);
    });
    StrategicMapComposeKey {
        view_origin: state.map_view_origin(),
        topology: state.map().topology,
        active_nation: state.turn().active_nation,
        selected_civilian,
        visible_tiles: hasher.finish(),
    }
}

fn hash_visible_tile_facts(state: &GameState, tile: TileId, hasher: &mut impl std::hash::Hasher) {
    use std::hash::Hash;

    let tile_state = state.map()[tile];
    tile.get().hash(hasher);
    tile_state.terrain.hash(hasher);
    tile_state.gate.hash(hasher);
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
    mut visit: impl FnMut(TileId, i32, i32),
) {
    let (origin_row, origin_column) = state.map().geometry().row_column(state.map_view_origin());
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
    sprites: StrategicMapSprites<'_>,
) -> Vec<u8> {
    let mut indices = vec![0_u8; VIEWPORT_WIDTH * VIEWPORT_HEIGHT];
    for_each_visible_strategic_tile(state, |tile, screen_x, screen_y| {
        let tile_pixels = compose_strategic_tile(state, tile, sprites);
        copy_clipped_tile(&tile_pixels, screen_x, screen_y, &mut indices);
    });
    indices
}

pub(crate) fn compose_city_site_terrain(
    state: &GameState,
    canvas: &StrategicBaseTerrainCanvas,
    nation: MajorNationId,
    highlighted_tile: Option<TileId>,
    palette: &DibPalette,
) -> Image {
    let mut indices = compose_strategic_map_indices(state, canvas.sprites());
    if let Some(tile) = highlighted_tile {
        draw_city_site_selection(state, nation, tile, &mut indices);
    }
    indexed_viewport_image(&indices, palette)
}

pub(super) fn draw_city_site_selection(
    state: &GameState,
    nation: MajorNationId,
    tile: TileId,
    viewport: &mut [u8],
) {
    let (x, y) = strategic_tile_screen_origin(state, tile);
    draw_frame(viewport, x, y, 0);

    let active_owner = TileOwnerTag::from_nation(nation.nation());
    let neighbors = state.map().geometry().neighbors(tile).map(|neighbor| {
        neighbor.filter(|&neighbor| {
            let neighbor = state.map()[neighbor];
            neighbor.terrain == TerrainKind::Water || neighbor.owner_nation == Some(active_owner)
        })
    });
    draw_city_site_neighbor_outline(state, neighbors, viewport);
}

fn draw_rail_order_selection(state: &GameState, unit: CivilianUnitId, viewport: &mut [u8]) {
    let Some(origin) = state
        .civilian_units()
        .iter()
        .find(|candidate| candidate.id() == unit)
        .and_then(|candidate| candidate.location().tile())
    else {
        return;
    };
    let (x, y) = strategic_tile_screen_origin(state, origin);
    draw_frame(viewport, x, y, 0);
    draw_city_site_neighbor_outline(state, state.rail_construction_destinations(unit), viewport);
}

fn draw_frame(viewport: &mut [u8], x: i32, y: i32, color: u8) {
    for offset in 0..TILE_SIZE {
        put_viewport_pixel(viewport, x + offset, y, color);
        put_viewport_pixel(viewport, x + offset, y + TILE_SIZE - 1, color);
        put_viewport_pixel(viewport, x, y + offset, color);
        put_viewport_pixel(viewport, x + TILE_SIZE - 1, y + offset, color);
    }
}

fn draw_city_site_neighbor_outline(
    state: &GameState,
    neighbors: [Option<TileId>; 6],
    viewport: &mut [u8],
) {
    const OUTLINE_COLOR: u8 = 0x20;
    for (index, neighbor) in neighbors.iter().copied().enumerate() {
        let Some(neighbor) = neighbor else {
            continue;
        };
        let (x, y) = strategic_tile_screen_origin(state, neighbor);
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

pub(super) fn strategic_tile_screen_origin(state: &GameState, tile: TileId) -> (i32, i32) {
    let (origin_row, origin_column) = state.map().geometry().row_column(state.map_view_origin());
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

fn draw_line(viewport: &mut [u8], start: (i32, i32), end: (i32, i32), color: u8) {
    let (mut x, mut y) = start;
    let x_step = (end.0 - x).signum();
    let y_step = (end.1 - y).signum();
    while (x, y) != end {
        put_viewport_pixel(viewport, x, y, color);
        x += x_step;
        y += y_step;
    }
}

fn put_viewport_pixel(viewport: &mut [u8], x: i32, y: i32, color: u8) {
    if (0..VIEWPORT_WIDTH as i32).contains(&x) && (0..VIEWPORT_HEIGHT as i32).contains(&y) {
        viewport[y as usize * VIEWPORT_WIDTH + x as usize] = color;
    }
}

pub(super) fn compose_strategic_tile(
    state: &GameState,
    tile: TileId,
    sprites: StrategicMapSprites<'_>,
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
    let mut pixels = if wrapped_seam {
        sprites.terrain[frame_for_offset(0xc80)].pixels.clone()
    } else {
        compose_strategic_base_tile(state, tile, sprites.terrain, sprites.river_masks)
    };

    if !wrapped_seam {
        compose_strategic_borders(state, tile, &mut pixels);
    }
    compose_strategic_railways(&tile_state, sprites.river_masks, &mut pixels);
    compose_strategic_improvements(state, tile, sprites, &mut pixels);
    pixels
}

fn normalize_map_column(column: i32) -> i32 {
    // Draw and ConvertPoint modulo the column even when the viewport itself is bounded.
    column.rem_euclid(i32::from(STRATEGIC_MAP_WIDTH))
}

fn copy_clipped_tile(source: &[u8], screen_x: i32, screen_y: i32, destination: &mut [u8]) {
    for source_y in 0..TILE_SIZE {
        let destination_y = screen_y + source_y;
        if !(0..VIEWPORT_HEIGHT as i32).contains(&destination_y) {
            continue;
        }
        let source_left = (-screen_x).max(0);
        let source_right = (VIEWPORT_WIDTH as i32 - screen_x).min(TILE_SIZE);
        if source_left >= source_right {
            continue;
        }
        let source_start = (source_y * TILE_SIZE + source_left) as usize;
        let source_end = (source_y * TILE_SIZE + source_right) as usize;
        let destination_start =
            destination_y as usize * VIEWPORT_WIDTH + (screen_x + source_left) as usize;
        destination[destination_start..destination_start + source_end - source_start]
            .copy_from_slice(&source[source_start..source_end]);
    }
}
fn indexed_viewport_image(indices: &[u8], palette: &DibPalette) -> Image {
    let mut rgba = Vec::with_capacity(indices.len() * 4);
    for &palette_index in indices {
        palette[palette_index].write_rgba(0xff, &mut rgba);
    }
    let mut image = Image::new(
        Extent3d {
            width: VIEWPORT_WIDTH as u32,
            height: VIEWPORT_HEIGHT as u32,
            depth_or_array_layers: 1,
        },
        TextureDimension::D2,
        rgba,
        TextureFormat::Rgba8UnormSrgb,
        RenderAssetUsages::default(),
    );
    image.sampler = ImageSampler::nearest();
    image
}

fn strategic_tile_at_position(state: &GameState, normalized: Vec2) -> Option<TileId> {
    let x = ((normalized.x + 0.5) * VIEWPORT_WIDTH as f32).floor() as i32;
    let y = ((normalized.y + 0.5) * VIEWPORT_HEIGHT as f32).floor() as i32;
    if !(0..VIEWPORT_WIDTH as i32).contains(&x) || !(0..VIEWPORT_HEIGHT as i32).contains(&y) {
        return None;
    }
    let (origin_row, origin_column) = state.map().geometry().row_column(state.map_view_origin());
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
    cursor: &RelativeCursorPosition,
) -> Option<TileId> {
    cursor
        .normalized
        .filter(|_| cursor.cursor_over())
        .and_then(|position| strategic_tile_at_position(state, position))
}

#[cfg(test)]
mod tests;
