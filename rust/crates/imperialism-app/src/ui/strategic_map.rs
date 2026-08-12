use super::RetailUiAssets;
use super::random_setup::GameSession;
use super::retail::{RetailTag, find_descendant};
use crate::RetailAssetsResource;
use bevy::asset::RenderAssetUsages;
use bevy::image::ImageSampler;
use bevy::prelude::*;
use bevy::render::render_resource::{Extent3d, TextureDimension, TextureFormat};
use bevy::ui::RelativeCursorPosition;
use imperialism_core::*;
use imperialism_formats::*;

const MAP_TAG: FourCc = fourcc!("DLOG");
const VIEWPORT_WIDTH: usize = 512;
const VIEWPORT_HEIGHT: usize = 448;
const TILE_SIZE: i32 = 64;
const VIEWPORT_TILE_SPAN: i32 = 9;
const TERRAIN_ATLAS_FRAME_COUNT: usize = 51;
const RIVER_MASK_PICTURE_COUNT: usize = 36;
const RIVER_MASK_TRANSPARENT_INDEX: u8 = 0x10;
const CITY_BORDER_PALETTE: u8 = 0x13;
const MINOR_NATION_BORDER_PALETTE: u8 = 0x0a;
const MAJOR_NATION_BORDER_PALETTES: [u8; MajorNationId::COUNT as usize] =
    [0x16, 0x2a, 0x22, 0x1c, 0x2b, 0x1e, 0x2e];
const RESOURCE_ICON_WIDTH: i32 = 0x14;
const RESOURCE_ICON_HEIGHT: i32 = 0x18;
const RESOURCE_OVERLAY_WIDTH: i32 = 0x26;
const RESOURCE_OVERLAY_HEIGHT: i32 = 0x1a;
const RESOURCE_OVERLAY_SOURCE_X: [i16; 28] = [
    0, 798, 114, 228, 342, -114, 684, -114, -114, -114, -114, -114, -114, -114, -114, -114, -114,
    0, 0, -114, 798, 570, 456, 0, 0, 0, 0, 0,
];
const IMPROVEMENT_ATLAS_BASE_OFFSET: u16 = 0x6c0;
const IMPROVEMENT_PICTURE_IDS: [i16; 15] = [
    550, 551, 552, 553, 554, 555, 556, 557, 560, 561, 562, 10_104, 10_105, 578, 579,
];

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
const BASE_WATER_OFFSETS: [u16; 8] = [0x140, 0x980, 0x9c0, 0xa00, 0xa40, 0, 0, 0];
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

/// Facts that change the composed strategic-map bitmap. Session-wide Bevy change detection is broader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StrategicMapComposeKey {
    view_origin: TileId,
    topology: MapTopology,
    active_nation: NationId,
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
struct StrategicMapSprites<'a> {
    terrain: &'a [IndexedPicture],
    river_masks: &'a [IndexedPicture],
    improvements: &'a [IndexedPicture],
    resource_icons: &'a IndexedPicture,
    resource_overlays: &'a IndexedPicture,
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
        composed: Some(strategic_map_compose_key(state)),
    };
    let image = compose_strategic_map(state, canvas.sprites(), assets.default_dib_palette());
    let image = assets.add_image(image);
    commands.entity(map).insert((
        ImageNode::new(image),
        RelativeCursorPosition::default(),
        canvas,
    ));
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
    mut maps: Query<(&mut StrategicBaseTerrainCanvas, &ImageNode)>,
) {
    let key = strategic_map_compose_key(&session.0);
    for (mut canvas, image_node) in &mut maps {
        if canvas.composed == Some(key) {
            continue;
        }
        let image = compose_strategic_map(
            &session.0,
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
) -> Image {
    let indices = compose_strategic_map_indices(state, sprites);
    indexed_viewport_image(&indices, palette)
}

fn strategic_map_compose_key(state: &GameState) -> StrategicMapComposeKey {
    use std::hash::Hasher;

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for_each_visible_strategic_tile(state, |tile, _screen_x, _screen_y| {
        hash_visible_tile_facts(state, tile, &mut hasher);
    });
    StrategicMapComposeKey {
        view_origin: state.map.view_origin,
        topology: state.map.topology,
        active_nation: state.turn().active_nation,
        visible_tiles: hasher.finish(),
    }
}

fn hash_visible_tile_facts(state: &GameState, tile: TileId, hasher: &mut impl std::hash::Hasher) {
    use std::hash::Hash;

    let tile_state = &state.map[tile];
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
    for nation in 0..MajorNationId::COUNT {
        tile_state.development.resource_visible_to_majors[MajorNationId::new(nation)].hash(hasher);
    }
    tile_state.edge_resources.hash(hasher);
    town_transport_linked(state, tile).hash(hasher);
    if let Some(province) = tile_state.province {
        let province = &state.map.provinces[province];
        province.development_stage().hash(hasher);
        province.fort_level().hash(hasher);
    }
    for neighbor in state.map.geometry().neighbors(tile) {
        let Some(neighbor) = neighbor else {
            false.hash(hasher);
            continue;
        };
        true.hash(hasher);
        let neighbor = &state.map[neighbor];
        neighbor.owner_nation.hash(hasher);
        neighbor.terrain.hash(hasher);
    }
}

fn for_each_visible_strategic_tile(state: &GameState, mut visit: impl FnMut(TileId, i32, i32)) {
    let (origin_row, origin_column) = state.map.geometry().row_column(state.map.view_origin);
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
            let Some(tile) = state.map.geometry().tile(row as u16, column as u16) else {
                continue;
            };
            visit(tile, screen_x, screen_y);
        }
    }
}

fn compose_strategic_map_indices(state: &GameState, sprites: StrategicMapSprites<'_>) -> Vec<u8> {
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

fn draw_city_site_selection(
    state: &GameState,
    nation: MajorNationId,
    tile: TileId,
    viewport: &mut [u8],
) {
    let (x, y) = strategic_tile_screen_origin(state, tile);
    draw_frame(viewport, x, y, 0);

    let active_owner = TileOwnerTag::from_nation(nation.nation());
    let neighbors = state.map.geometry().neighbors(tile).map(|neighbor| {
        neighbor.filter(|&neighbor| {
            let neighbor = &state.map[neighbor];
            neighbor.terrain == TerrainKind::Water || neighbor.owner_nation == Some(active_owner)
        })
    });
    draw_city_site_neighbor_outline(state, neighbors, viewport);
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

fn strategic_tile_screen_origin(state: &GameState, tile: TileId) -> (i32, i32) {
    let (origin_row, origin_column) = state.map.geometry().row_column(state.map.view_origin);
    let (row, column) = state.map.geometry().row_column(tile);
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

fn compose_strategic_tile(
    state: &GameState,
    tile: TileId,
    sprites: StrategicMapSprites<'_>,
) -> Vec<u8> {
    let tile_state = &state.map[tile];
    let center_column = {
        let (_, origin_column) = state.map.geometry().row_column(state.map.view_origin);
        (i32::from(origin_column) + VIEWPORT_TILE_SPAN / 2)
            .rem_euclid(i32::from(STRATEGIC_MAP_WIDTH))
    };
    let (_, tile_column) = state.map.geometry().row_column(tile);
    // Retail's stored flag is inverted: this seam substitution belongs to Rust's bounded map.
    let wrapped_seam = state.map.topology == MapTopology::Bounded
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
    compose_strategic_railways(tile_state, sprites.river_masks, &mut pixels);
    compose_strategic_improvements(state, tile, sprites, &mut pixels);
    pixels
}

fn compose_strategic_base_tile(
    state: &GameState,
    tile: TileId,
    terrain_pictures: &[IndexedPicture],
    river_masks: &[IndexedPicture],
) -> Vec<u8> {
    let tile_state = &state.map[tile];
    let center_column = {
        let (_, origin_column) = state.map.geometry().row_column(state.map.view_origin);
        (i32::from(origin_column) + VIEWPORT_TILE_SPAN / 2)
            .rem_euclid(i32::from(STRATEGIC_MAP_WIDTH))
    };
    let (_, tile_column) = state.map.geometry().row_column(tile);
    // Retail's stored flag is inverted: this seam substitution belongs to Rust's bounded map.
    let wrapped_seam = state.map.topology == MapTopology::Bounded
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

fn coast_corner_variant(adjacency_mask: u8, corner: usize) -> u8 {
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

fn uses_river_mouth_coast_frame(corner: usize, river_sprite: Option<u8>) -> bool {
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

fn apply_tile_mask(source: &[u8], pixels: &mut [u8]) {
    for (&source_pixel, destination_pixel) in source.iter().zip(pixels) {
        if source_pixel != RIVER_MASK_TRANSPARENT_INDEX {
            *destination_pixel = source_pixel;
        }
    }
}

fn compose_strategic_railways(
    tile_state: &TileState,
    river_masks: &[IndexedPicture],
    pixels: &mut [u8],
) {
    if tile_state.transport_links.is_empty() && tile_state.pending_rail_links.is_empty() {
        return;
    }
    for direction in 0..6 {
        let direction_bit = 1 << direction;
        let mask = if tile_state.transport_links.bits() & direction_bit != 0 {
            0x18 + direction
        } else if tile_state.pending_rail_links.bits() & direction_bit != 0 {
            0x1e + direction
        } else {
            continue;
        };
        apply_tile_mask(&river_masks[mask].pixels, pixels);
    }
}

fn compose_strategic_improvements(
    state: &GameState,
    tile: TileId,
    sprites: StrategicMapSprites<'_>,
    pixels: &mut [u8],
) {
    let tile_state = &state.map[tile];
    let flags = tile_state.flags.bits();
    let city_or_town = flags & 3 != 0 && tile_state.gate != 0;

    if city_or_town && let Some(offset) = city_marker_offset(state, tile) {
        blit_improvement_sprite(sprites.improvements, offset, pixels);
    }

    if flags & 0x14 != 0
        && flags & 1 == 0
        && let Some(offset) = transport_marker_offset(flags, town_transport_linked(state, tile))
    {
        blit_improvement_sprite(sprites.improvements, offset, pixels);
    }

    if !city_or_town {
        compose_strategic_resource_indicators(state, tile, sprites, pixels);
    } else if let Some(offset) = fort_marker_offset(state, tile) {
        blit_improvement_sprite(sprites.improvements, offset, pixels);
    }
}

fn city_marker_offset(state: &GameState, tile: TileId) -> Option<u16> {
    let tile_state = &state.map[tile];
    let flags = tile_state.flags.bits();
    let minor_sprites = tile_state
        .former_owner_nation
        .is_some_and(|owner| owner.get() >= MajorNationId::COUNT);
    if !minor_sprites {
        if flags & 1 != 0 {
            return Some(0x6c0);
        }
        if flags & 2 != 0 {
            let stage = tile_state
                .province
                .map(|province| state.map.provinces[province].development_stage())
                .unwrap_or(0);
            return match stage {
                0 => Some(0x700),
                1 => Some(0x740),
                2 => Some(0x780),
                _ => None,
            };
        }
        return None;
    }
    if flags & 1 != 0 {
        Some(0x9c0)
    } else if flags & 2 != 0 {
        Some(0x980)
    } else {
        None
    }
}

fn transport_marker_offset(flags: u16, linked: bool) -> Option<u16> {
    if flags & 4 != 0 {
        if flags & 0x10 != 0 {
            Some(if linked { 0x840 } else { 0xa40 })
        } else {
            Some(if linked { 0x880 } else { 0xa00 })
        }
    } else if flags & 0x10 != 0 {
        Some(if linked { 0x7c0 } else { 0x800 })
    } else {
        None
    }
}

fn fort_marker_offset(state: &GameState, tile: TileId) -> Option<u16> {
    let fort_level = state.map[tile]
        .province
        .map(|province| state.map.provinces[province].fort_level())
        .unwrap_or(0);
    if fort_level == 0 {
        return None;
    }
    Some(((fort_level - 1 + 0x23) as u16) << 6)
}

fn town_transport_linked(state: &GameState, tile: TileId) -> bool {
    let Some(owner) = state.map[tile].owner_nation.and_then(TileOwnerTag::nation) else {
        return true;
    };
    let Some(major) = MajorNationId::from_nation(owner) else {
        return true;
    };
    state
        .nations()
        .major(major)
        .towns
        .iter()
        .find(|town| town.tile == tile)
        .map(|town| town.transport_linked)
        .unwrap_or(true)
}

fn blit_improvement_sprite(pictures: &[IndexedPicture], offset: u16, pixels: &mut [u8]) {
    let index = usize::from((offset - IMPROVEMENT_ATLAS_BASE_OFFSET) / TILE_SIZE as u16);
    blit_indexed(&pictures[index], 0, 0, TILE_SIZE, TILE_SIZE, pixels, 0, 0);
}

fn compose_strategic_resource_indicators(
    state: &GameState,
    tile: TileId,
    sprites: StrategicMapSprites<'_>,
    pixels: &mut [u8],
) {
    let tile_state = &state.map[tile];
    let surface = tile_state.development.surface.get();
    let extractive = tile_state.development.extractive.get();
    let first = tile_state.edge_resources[0];
    let second = tile_state.edge_resources[1];

    if let Some(resource) = first.filter(resource_is_prospectable) {
        if extractive != 0 {
            blit_resource_overlay(
                sprites.resource_overlays,
                resource,
                extractive,
                2,
                2,
                pixels,
            );
        } else if resource_visible_to_active_nation(state, tile) {
            blit_resource_icon(sprites.resource_icons, resource, 0, 0, pixels);
        }
    } else if surface != 0
        && let Some(resource) = first
    {
        blit_resource_overlay(
            sprites.resource_overlays,
            resource,
            surface,
            0x1b,
            2,
            pixels,
        );
    }

    if let Some(resource) = second.filter(resource_is_prospectable) {
        if extractive != 0 {
            blit_resource_overlay(
                sprites.resource_overlays,
                resource,
                extractive,
                2,
                0x1c,
                pixels,
            );
        } else if resource_visible_to_active_nation(state, tile) {
            blit_resource_icon(sprites.resource_icons, resource, 0, 0x1c, pixels);
        }
    }

    if second == Some(ResourceKind::Livestock)
        && matches!(first, Some(ResourceKind::Coal | ResourceKind::Iron))
        && surface != 0
    {
        blit_resource_overlay(
            sprites.resource_overlays,
            ResourceKind::Livestock,
            surface,
            0x1b,
            0x1c,
            pixels,
        );
    }
}

fn resource_is_prospectable(resource: &ResourceKind) -> bool {
    matches!(
        resource,
        ResourceKind::Coal
            | ResourceKind::Iron
            | ResourceKind::Oil
            | ResourceKind::Gems
            | ResourceKind::Gold
    )
}

fn resource_visible_to_active_nation(state: &GameState, tile: TileId) -> bool {
    MajorNationId::from_nation(state.turn().active_nation)
        .is_some_and(|nation| state.map[tile].development.resource_visible_to_majors[nation])
}

fn blit_resource_icon(
    atlas: &IndexedPicture,
    resource: ResourceKind,
    dest_x: i32,
    dest_y: i32,
    pixels: &mut [u8],
) {
    blit_indexed(
        atlas,
        i32::from(resource as u8) * RESOURCE_ICON_WIDTH,
        0,
        RESOURCE_ICON_WIDTH,
        RESOURCE_ICON_HEIGHT,
        pixels,
        dest_x,
        dest_y,
    );
}

fn blit_resource_overlay(
    atlas: &IndexedPicture,
    resource: ResourceKind,
    level: u8,
    dest_x: i32,
    dest_y: i32,
    pixels: &mut [u8],
) {
    if level == 0 {
        return;
    }
    let source_base = RESOURCE_OVERLAY_SOURCE_X[resource as usize];
    if source_base < 0 {
        return;
    }
    let source_x =
        i32::from(source_base) - RESOURCE_OVERLAY_WIDTH + i32::from(level) * RESOURCE_OVERLAY_WIDTH;
    blit_indexed(
        atlas,
        source_x,
        0,
        RESOURCE_OVERLAY_WIDTH,
        RESOURCE_OVERLAY_HEIGHT,
        pixels,
        dest_x,
        dest_y,
    );
}

#[allow(clippy::too_many_arguments)]
fn blit_indexed(
    source: &IndexedPicture,
    src_x: i32,
    src_y: i32,
    width: i32,
    height: i32,
    destination: &mut [u8],
    dest_x: i32,
    dest_y: i32,
) {
    let source_width = source.width as i32;
    let source_height = source.height as i32;
    for row in 0..height {
        let destination_y = dest_y + row;
        let source_row = src_y + row;
        if !(0..TILE_SIZE).contains(&destination_y) || !(0..source_height).contains(&source_row) {
            continue;
        }
        for column in 0..width {
            let destination_x = dest_x + column;
            let source_column = src_x + column;
            if !(0..TILE_SIZE).contains(&destination_x)
                || !(0..source_width).contains(&source_column)
            {
                continue;
            }
            let pixel =
                source.pixels[source_row as usize * source.width as usize + source_column as usize];
            if pixel != RIVER_MASK_TRANSPARENT_INDEX {
                destination[destination_y as usize * TILE_SIZE as usize + destination_x as usize] =
                    pixel;
            }
        }
    }
}

fn compose_strategic_borders(state: &GameState, tile: TileId, pixels: &mut [u8]) {
    let tile_state = &state.map[tile];
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
    let mask = state.map[tile].owner_border_mask;
    let owner = border_palette(state.map[tile].owner_nation);
    let neighbors = state.map.geometry().neighbors(tile);
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

    if state.map[tile].terrain == TerrainKind::Water {
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
    let mask = state.map[tile].city_border_mask;
    let neighbors = state.map.geometry().neighbors(tile);
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

    if state.map[tile].terrain == TerrainKind::Water {
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
    let neighbors = state.map.geometry().neighbors(tile);
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
    let first = &state.map[first];
    let second = &state.map[second];
    first.terrain != TerrainKind::Water
        && second.terrain != TerrainKind::Water
        && first.owner_nation != second.owner_nation
}

fn neighbor_is_water(state: &GameState, neighbor: Option<TileId>) -> bool {
    neighbor.is_some_and(|neighbor| state.map[neighbor].terrain == TerrainKind::Water)
}

fn neighbor_palette(state: &GameState, neighbor: Option<TileId>) -> u8 {
    border_palette(neighbor.and_then(|neighbor| state.map[neighbor].owner_nation))
}

fn border_palette(owner: Option<TileOwnerTag>) -> u8 {
    owner
        .and_then(TileOwnerTag::nation)
        .and_then(MajorNationId::from_nation)
        .map(|nation| MAJOR_NATION_BORDER_PALETTES[usize::from(nation.get())])
        .unwrap_or(MINOR_NATION_BORDER_PALETTE)
}

fn draw_border(pixels: &mut [u8], relation: u8, nation_a: u8, nation_b: u8) {
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

fn frame_for_offset(offset: u16) -> usize {
    assert_eq!(offset % TILE_SIZE as u16, 0);
    usize::from(offset / TILE_SIZE as u16)
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
    let (origin_row, origin_column) = state.map.geometry().row_column(state.map.view_origin);
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
    state.map.geometry().tile(row as u16, column as u16)
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
mod tests {
    use super::*;
    use imperialism_core::{
        MapTopology, STRATEGIC_TILE_COUNT, TerrainKind, TileOwnerTag, TileRendering, TileState,
    };
    use imperialism_formats::{LegacyGameStateContext, LegacySaveV62};

    const BEGINNING_OF_GAME: &[u8] =
        include_bytes!("../../../../../fixtures/retail/beginning_of_game.imp");

    fn solid_frame(index: u8) -> IndexedPicture {
        IndexedPicture {
            width: TILE_SIZE as u32,
            height: TILE_SIZE as u32,
            pixels: vec![index; (TILE_SIZE * TILE_SIZE) as usize],
        }
    }

    fn synthetic_terrain_pictures() -> Vec<IndexedPicture> {
        (0..51).map(|index| solid_frame(index as u8)).collect()
    }

    fn synthetic_river_masks() -> Vec<IndexedPicture> {
        (0..RIVER_MASK_PICTURE_COUNT)
            .map(|index| IndexedPicture {
                width: TILE_SIZE as u32,
                height: TILE_SIZE as u32,
                // Non-transparent river ink uses a distinct high index.
                pixels: vec![0x80 | index as u8; (TILE_SIZE * TILE_SIZE) as usize],
            })
            .collect()
    }

    fn synthetic_improvement_pictures() -> Vec<IndexedPicture> {
        (0..IMPROVEMENT_PICTURE_IDS.len())
            .map(|index| solid_frame(0x90 + index as u8))
            .collect()
    }

    fn synthetic_resource_icons() -> IndexedPicture {
        let width = (ResourceKind::LENGTH as i32 * RESOURCE_ICON_WIDTH) as u32;
        IndexedPicture {
            width,
            height: RESOURCE_ICON_HEIGHT as u32,
            pixels: (0..width as usize * RESOURCE_ICON_HEIGHT as usize)
                .map(|index| 0xa0 + (index as u8 % ResourceKind::LENGTH as u8))
                .collect(),
        }
    }

    fn synthetic_resource_overlays() -> IndexedPicture {
        let width = 24 * RESOURCE_OVERLAY_WIDTH as u32;
        IndexedPicture {
            width,
            height: RESOURCE_OVERLAY_HEIGHT as u32,
            pixels: vec![0xb0; width as usize * RESOURCE_OVERLAY_HEIGHT as usize],
        }
    }

    fn synthetic_sprites() -> (
        Vec<IndexedPicture>,
        Vec<IndexedPicture>,
        Vec<IndexedPicture>,
        IndexedPicture,
        IndexedPicture,
    ) {
        (
            synthetic_terrain_pictures(),
            synthetic_river_masks(),
            synthetic_improvement_pictures(),
            synthetic_resource_icons(),
            synthetic_resource_overlays(),
        )
    }

    fn sprites_from<'a>(
        terrain: &'a [IndexedPicture],
        rivers: &'a [IndexedPicture],
        improvements: &'a [IndexedPicture],
        icons: &'a IndexedPicture,
        overlays: &'a IndexedPicture,
    ) -> StrategicMapSprites<'a> {
        StrategicMapSprites {
            terrain,
            river_masks: rivers,
            improvements,
            resource_icons: icons,
            resource_overlays: overlays,
        }
    }

    fn fixture_state() -> GameState {
        let save = LegacySaveV62::parse(BEGINNING_OF_GAME);
        save.game_state(LegacyGameStateContext {
            crt_rand_state: 1,
            map_generation_lcg: 0,
            zone_status_lcg: 3_916_827_792,
            selected_nation: imperialism_core::NationId::new(6),
        })
    }

    #[test]
    fn coast_corner_variant_matches_the_adjacent_bit_rule() {
        assert_eq!(coast_corner_variant(0x05, 1), 0);
        // Corner 0 needs bits 5 and 0 both set for the joined-corner variant.
        assert_eq!(coast_corner_variant(0b0010_0001, 0), 1);
        assert_eq!(coast_corner_variant(0b0000_0001, 0), 2);
        assert_eq!(coast_corner_variant(0b0010_0000, 0), 3);
    }

    #[test]
    fn river_mouth_coast_frames_follow_corner_and_sprite_pairs() {
        assert!(uses_river_mouth_coast_frame(1, Some(0x33)));
        assert!(uses_river_mouth_coast_frame(4, Some(0x39)));
        assert!(!uses_river_mouth_coast_frame(1, Some(0x35)));
        assert!(!uses_river_mouth_coast_frame(0, Some(0x33)));
    }

    #[test]
    fn water_coast_corners_pull_distinct_frame_inks() {
        let terrain = synthetic_terrain_pictures();
        let rivers = synthetic_river_masks();
        let mut state = fixture_state();
        let origin = state.map.view_origin;
        state.map[origin].terrain = TerrainKind::Water;
        state.map[origin].rendering = TileRendering::from_retail(0, 0, 0, 0b0000_0011).unwrap();

        let pixels = compose_strategic_base_tile(&state, origin, &terrain, &rivers);
        let base_ink = frame_for_offset(BASE_WATER_OFFSETS[0]) as u8;
        assert!(pixels.contains(&base_ink));
        assert!(pixels.iter().any(|&pixel| pixel >= 22));
    }

    #[test]
    fn river_masks_replace_opaque_destination_indexes() {
        let terrain = synthetic_terrain_pictures();
        let rivers = synthetic_river_masks();
        let mut state = fixture_state();
        let origin = state.map.view_origin;
        state.map[origin].terrain = TerrainKind::Plains;
        state.map[origin].gate = 0;
        state.map[origin].rendering = TileRendering::from_retail(0, 0x0b, 0, 0).unwrap();

        let pixels = compose_strategic_base_tile(&state, origin, &terrain, &rivers);
        assert!(pixels.iter().all(|&pixel| pixel == 0x80));
    }

    #[test]
    fn bounded_seam_tiles_use_the_dedicated_seam_frame() {
        let terrain = synthetic_terrain_pictures();
        let rivers = synthetic_river_masks();
        let mut state = fixture_state();
        // Force bounded topology and a center column past 54 so column 0 is a seam.
        let tiles = vec![TileState::default(); STRATEGIC_TILE_COUNT];
        let mut world = MapMgr::new(MapTopology::Bounded, tiles);
        let origin = world.geometry().tile(10, 51).unwrap();
        world.view_origin = origin;
        let seam = world.geometry().tile(10, 0).unwrap();
        state.map = world;

        let pixels = compose_strategic_base_tile(&state, seam, &terrain, &rivers);
        assert!(
            pixels
                .iter()
                .all(|&pixel| pixel == frame_for_offset(0xc80) as u8)
        );
    }

    #[test]
    fn city_site_selection_draws_black_frame_and_neighbor_outline() {
        let mut state = fixture_state();
        let nation = MajorNationId::new(6);
        let owner = TileOwnerTag::from_nation(nation.nation());
        let origin = state.map.view_origin;
        state.map[origin].owner_nation = Some(owner);
        state.map[origin].terrain = TerrainKind::Plains;
        let neighbors = state.map.geometry().neighbors(origin);
        for neighbor in neighbors.into_iter().flatten() {
            state.map[neighbor].owner_nation = Some(owner);
            state.map[neighbor].terrain = TerrainKind::Plains;
        }

        let (terrain, rivers, improvements, icons, overlays) = synthetic_sprites();
        let mut indices = compose_strategic_map_indices(
            &state,
            sprites_from(&terrain, &rivers, &improvements, &icons, &overlays),
        );
        let before = indices.clone();
        draw_city_site_selection(&state, nation, origin, &mut indices);
        assert_ne!(indices, before);
        let (x, y) = strategic_tile_screen_origin(&state, origin);
        let top_left = (y * VIEWPORT_WIDTH as i32 + x) as usize;
        assert_eq!(indices[top_left], 0);
    }

    #[test]
    fn city_marker_offsets_follow_former_owner_and_development_stage() {
        let mut state = fixture_state();
        let origin = state.map.view_origin;
        state.map[origin].flags = TileFlags::from_bits_retain(1);
        state.map[origin].former_owner_nation = Some(TileOwnerTag::from_nation(NationId::new(6)));
        assert_eq!(city_marker_offset(&state, origin), Some(0x6c0));

        state.map[origin].flags = TileFlags::from_bits_retain(2);
        state.map[origin].province = Some(ProvinceId::new(0));
        assert_eq!(city_marker_offset(&state, origin), Some(0x700));

        state.map[origin].former_owner_nation = Some(TileOwnerTag::new(8));
        state.map[origin].flags = TileFlags::from_bits_retain(1);
        assert_eq!(city_marker_offset(&state, origin), Some(0x9c0));
        state.map[origin].flags = TileFlags::from_bits_retain(2);
        assert_eq!(city_marker_offset(&state, origin), Some(0x980));
    }

    #[test]
    fn transport_marker_offsets_encode_port_depot_and_link_state() {
        assert_eq!(transport_marker_offset(0x10, true), Some(0x7c0));
        assert_eq!(transport_marker_offset(0x10, false), Some(0x800));
        assert_eq!(transport_marker_offset(0x14, true), Some(0x840));
        assert_eq!(transport_marker_offset(0x14, false), Some(0xa40));
        assert_eq!(transport_marker_offset(4, true), Some(0x880));
        assert_eq!(transport_marker_offset(4, false), Some(0xa00));
        assert_eq!(transport_marker_offset(0, true), None);
    }

    #[test]
    fn completed_rails_use_the_later_mask_family_than_pending_rails() {
        let (terrain, rivers, improvements, icons, overlays) = synthetic_sprites();
        let mut state = fixture_state();
        let origin = state.map.view_origin;
        state.map[origin].terrain = TerrainKind::Plains;
        state.map[origin].gate = 0;
        state.map[origin].rendering = TileRendering::default();
        state.map[origin].transport_links = TileTransportLinks::EAST;
        state.map[origin].pending_rail_links = TileTransportLinks::empty();
        state.map[origin].flags = TileFlags::empty();
        state.map[origin].edge_resources = [None, None];

        let completed = compose_strategic_tile(
            &state,
            origin,
            sprites_from(&terrain, &rivers, &improvements, &icons, &overlays),
        );
        assert!(completed.contains(&(0x80 | 0x19)));

        state.map[origin].transport_links = TileTransportLinks::empty();
        state.map[origin].pending_rail_links = TileTransportLinks::EAST;
        let pending = compose_strategic_tile(
            &state,
            origin,
            sprites_from(&terrain, &rivers, &improvements, &icons, &overlays),
        );
        assert!(pending.contains(&(0x80 | 0x1f)));
    }

    #[test]
    fn prospectable_resources_use_extractive_overlay_or_undeveloped_icon() {
        let (terrain, rivers, improvements, icons, overlays) = synthetic_sprites();
        let mut state = fixture_state();
        let origin = state.map.view_origin;
        let nation = MajorNationId::from_nation(state.turn().active_nation).unwrap();
        state.map[origin].terrain = TerrainKind::Hills;
        state.map[origin].gate = 2;
        state.map[origin].flags = TileFlags::empty();
        state.map[origin].edge_resources = [Some(ResourceKind::Coal), None];
        state.map[origin].development.extractive = DevelopmentLevel::ZERO;
        state.map[origin].development.surface = DevelopmentLevel::ZERO;
        state.map[origin].development.resource_visible_to_majors[nation] = true;

        let undeveloped = compose_strategic_tile(
            &state,
            origin,
            sprites_from(&terrain, &rivers, &improvements, &icons, &overlays),
        );
        assert!(
            undeveloped
                .iter()
                .any(|&pixel| (0xa0..0xb0).contains(&pixel))
        );

        state.map[origin].development.extractive = DevelopmentLevel::new(1);
        let developed = compose_strategic_tile(
            &state,
            origin,
            sprites_from(&terrain, &rivers, &improvements, &icons, &overlays),
        );
        assert!(developed.contains(&0xb0));
    }

    #[test]
    fn city_tiles_blit_the_capital_improvement_ink() {
        let (terrain, rivers, improvements, icons, overlays) = synthetic_sprites();
        let mut state = fixture_state();
        let origin = state.map.view_origin;
        state.map[origin].terrain = TerrainKind::Plains;
        state.map[origin].gate = 1;
        state.map[origin].flags = TileFlags::from_bits_retain(1);
        state.map[origin].former_owner_nation = Some(TileOwnerTag::from_nation(NationId::new(6)));
        state.map[origin].edge_resources = [None, None];

        let pixels = compose_strategic_tile(
            &state,
            origin,
            sprites_from(&terrain, &rivers, &improvements, &icons, &overlays),
        );
        assert!(pixels.contains(&0x90));
    }

    #[test]
    fn nation_borders_use_the_owner_palette() {
        let mut pixels = vec![1_u8; (TILE_SIZE * TILE_SIZE) as usize];
        draw_border(
            &mut pixels,
            0,
            MAJOR_NATION_BORDER_PALETTES[6],
            MINOR_NATION_BORDER_PALETTE,
        );
        assert!(pixels.contains(&MAJOR_NATION_BORDER_PALETTES[6]));
        assert!(pixels.contains(&MINOR_NATION_BORDER_PALETTE));
    }
}
