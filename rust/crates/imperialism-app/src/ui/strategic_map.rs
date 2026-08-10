use super::catalog::{SpawnedView, UiAssetResources};
use super::random_setup::GameSession;
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
const RIVER_MASK_PICTURE_COUNT: usize = 32;
const RIVER_MASK_TRANSPARENT_INDEX: u8 = 0x10;

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

/// The bounded strategic terrain layer: retail bases, transitions, coast corners, and rivers.
/// Borders, improvements, towns, and units intentionally remain absent.
#[derive(Component)]
pub(crate) struct StrategicBaseTerrainCanvas {
    terrain_pictures: Vec<IndexedPicture>,
    river_masks: Vec<IndexedPicture>,
}

pub(crate) fn bind_strategic_base_terrain(
    commands: &mut Commands,
    spawned: &SpawnedView,
    assets: &mut UiAssetResources,
    state: &GameState,
) {
    let map = spawned
        .require_unique(MAP_TAG)
        .expect("validated strategic-map canvas binding");
    let terrain_pictures = load_strategic_terrain_pictures(assets);
    let river_masks = load_strategic_river_masks(assets);
    let image = compose_strategic_base_terrain(
        state,
        &terrain_pictures,
        &river_masks,
        assets.default_dib_palette(),
    );
    let image = assets.add_image(image);
    commands.entity(map).insert((
        ImageNode::new(image),
        RelativeCursorPosition::default(),
        StrategicBaseTerrainCanvas {
            terrain_pictures,
            river_masks,
        },
    ));
}

pub(crate) fn sync_strategic_base_terrain(
    session: Option<Res<GameSession>>,
    retail_assets: Res<RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    maps: Query<(&StrategicBaseTerrainCanvas, &ImageNode)>,
) {
    let Some(session) = session else {
        return;
    };
    if !session.is_changed() {
        return;
    }
    for (canvas, image_node) in &maps {
        let image = compose_strategic_base_terrain(
            &session.0,
            &canvas.terrain_pictures,
            &canvas.river_masks,
            retail_assets.assets().default_dib_palette(),
        );
        let Some(mut existing) = images.get_mut(&image_node.image) else {
            continue;
        };
        *existing = image;
    }
}

fn load_strategic_terrain_pictures(assets: &UiAssetResources) -> Vec<IndexedPicture> {
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

fn load_strategic_river_masks(assets: &UiAssetResources) -> Vec<IndexedPicture> {
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

fn river_mask_picture_id(mask: usize) -> PictureId {
    let id = match mask {
        0..=15 => 10_048 + mask as i16,
        16..=23 => 10_086 + (mask - 16) as i16,
        24..=29 => 10_042 + (mask - 24) as i16,
        30..=31 => 10_080 + (mask - 30) as i16,
        _ => panic!("strategic river mask {mask} is out of range"),
    };
    PictureId::new(id)
}

fn compose_strategic_base_terrain(
    state: &GameState,
    terrain_pictures: &[IndexedPicture],
    river_masks: &[IndexedPicture],
    palette: &DibPalette,
) -> Image {
    let mut indices = vec![0_u8; VIEWPORT_WIDTH * VIEWPORT_HEIGHT];
    let (origin_row, origin_column) = state.world.geometry().row_column(state.world.view_origin());
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
            let Some(tile) = state.world.geometry().tile(row as u16, column as u16) else {
                continue;
            };
            let tile_pixels =
                compose_strategic_base_tile(state, tile, terrain_pictures, river_masks);
            copy_clipped_tile(&tile_pixels, screen_x, screen_y, &mut indices);
        }
    }

    indexed_viewport_image(&indices, palette)
}

fn compose_strategic_base_tile(
    state: &GameState,
    tile: TileId,
    terrain_pictures: &[IndexedPicture],
    river_masks: &[IndexedPicture],
) -> Vec<u8> {
    let tile_state = &state.world[tile];
    let center_column = {
        let (_, origin_column) = state.world.geometry().row_column(state.world.view_origin());
        (i32::from(origin_column) + VIEWPORT_TILE_SPAN / 2)
            .rem_euclid(i32::from(STRATEGIC_MAP_WIDTH))
    };
    let (_, tile_column) = state.world.geometry().row_column(tile);
    // Retail's stored flag is inverted: this seam substitution belongs to Rust's bounded map.
    let wrapped_seam = state.world.topology() == MapTopology::Bounded
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
        let subtype = usize::try_from(tile_state.region_tile_subtype.retail())
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
        let subtype = usize::try_from(tile_state.region_tile_subtype.retail())
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
    let source = &river_masks[mask].pixels;
    for (&source_pixel, destination_pixel) in source.iter().zip(pixels) {
        if source_pixel != RIVER_MASK_TRANSPARENT_INDEX {
            *destination_pixel = source_pixel;
        }
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
    let (origin_row, origin_column) = state.world.geometry().row_column(state.world.view_origin());
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
    state.world.geometry().tile(row as u16, column as u16)
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
