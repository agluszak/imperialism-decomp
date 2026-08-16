//! `TOceanDialog` (`DOOG`) alternate strategic view.

use super::map_interaction::OceanView;
use super::{VIEWPORT_HEIGHT, VIEWPORT_WIDTH};
use crate::AppState;
use crate::ui::GameSession;
use crate::ui::RetailUiAssets;
use crate::ui::retail::RetailTree;
use bevy::asset::RenderAssetUsages;
use bevy::image::ImageSampler;
use bevy::prelude::*;
use bevy::render::render_resource::{Extent3d, TextureDimension, TextureFormat};
use bevy::ui::RelativeCursorPosition;
use imperialism_core::*;
use imperialism_formats::*;

const LAND_POS: Vec2 = Vec2::new(5.0, 0x1b as f32);
const PARKED_POS: Vec2 = Vec2::new(1001.0, 27.0);
const OCEAN_TILE: i32 = 16;

#[derive(Component)]
pub(crate) struct LandMapFrame;

#[derive(Component)]
pub(crate) struct OceanMapCanvas;

pub(crate) fn register(app: &mut App) {
    app.add_systems(
        Update,
        (sync_ocean_view_frames, sync_ocean_canvas)
            .chain()
            .run_if(in_state(AppState::StrategicMap)),
    );
}

pub(crate) fn bind_ocean_view(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let land = tree.find(root, fourcc!("DLOG"));
    commands.entity(land).insert(LandMapFrame);
    let ocean = tree.find(root, fourcc!("DOOG"));
    let palette = *assets.default_dib_palette();
    let image = assets.add_image(empty_ocean_image(&palette));
    commands.entity(ocean).insert((
        OceanMapCanvas,
        ImageNode::new(image),
        RelativeCursorPosition::default(),
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(PARKED_POS.x),
            top: Val::Px(PARKED_POS.y),
            width: Val::Px(VIEWPORT_WIDTH as f32),
            height: Val::Px(VIEWPORT_HEIGHT as f32),
            ..default()
        },
    ));
}

fn sync_ocean_view_frames(
    mode: Res<super::map_interaction::MapInteractionMode>,
    mut ocean: ResMut<OceanView>,
    mut land: Query<&mut Node, (With<LandMapFrame>, Without<OceanMapCanvas>)>,
    mut sea: Query<&mut Node, (With<OceanMapCanvas>, Without<LandMapFrame>)>,
) {
    if *mode == super::map_interaction::MapInteractionMode::Civilian && ocean.active {
        ocean.active = false;
    }
    let (land_pos, sea_pos) = if ocean.active {
        (PARKED_POS, LAND_POS)
    } else {
        (LAND_POS, PARKED_POS)
    };
    if let Ok(mut node) = land.single_mut() {
        node.left = Val::Px(land_pos.x);
        node.top = Val::Px(land_pos.y);
    }
    if let Ok(mut node) = sea.single_mut() {
        node.left = Val::Px(sea_pos.x);
        node.top = Val::Px(sea_pos.y);
    }
}

fn sync_ocean_canvas(
    session: Res<GameSession>,
    ocean: Res<OceanView>,
    retail: Res<crate::RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    canvases: Query<&ImageNode, With<OceanMapCanvas>>,
) {
    if !ocean.active && !session.is_changed() && !ocean.is_changed() {
        return;
    }
    if !ocean.active {
        return;
    }
    let palette = retail.assets().default_dib_palette();
    let image = compose_ocean_map(&session.game, &ocean, palette);
    for node in &canvases {
        if let Some(mut existing) = images.get_mut(&node.image) {
            *existing = image.clone();
        }
    }
}

pub(crate) fn ocean_tile_at_cursor(
    state: &GameState,
    cursor: &RelativeCursorPosition,
    ocean: &OceanView,
) -> Option<TileId> {
    cursor
        .normalized
        .filter(|_| cursor.cursor_over())
        .and_then(|position| {
            ocean_tile_at_position(state, position, ocean.origin_column, ocean.origin_row)
        })
}

fn ocean_tile_at_position(
    state: &GameState,
    normalized: Vec2,
    origin_column: i32,
    origin_row: i32,
) -> Option<TileId> {
    let x = ((normalized.x + 0.5) * VIEWPORT_WIDTH as f32).floor() as i32;
    let y = ((normalized.y + 0.5) * VIEWPORT_HEIGHT as f32).floor() as i32;
    if !(0..VIEWPORT_WIDTH as i32).contains(&x) || !(0..VIEWPORT_HEIGHT as i32).contains(&y) {
        return None;
    }
    let row = origin_row + y / OCEAN_TILE;
    if !(0..i32::from(STRATEGIC_MAP_HEIGHT)).contains(&row) {
        return None;
    }
    let mut adjusted = x;
    if row & 1 == 0 {
        adjusted += 8;
    }
    let column = (origin_column + adjusted / OCEAN_TILE).rem_euclid(i32::from(STRATEGIC_MAP_WIDTH));
    state.map().geometry().tile(row as u16, column as u16)
}

fn compose_ocean_map(state: &GameState, ocean: &OceanView, palette: &DibPalette) -> Image {
    let mut indices = vec![0_u8; VIEWPORT_WIDTH * VIEWPORT_HEIGHT];
    for row_delta in 0..28 {
        let row = ocean.origin_row + row_delta;
        if !(0..i32::from(STRATEGIC_MAP_HEIGHT)).contains(&row) {
            continue;
        }
        let odd = if row & 1 != 0 { OCEAN_TILE / 2 } else { 0 };
        for column_delta in -1..33 {
            let column =
                (ocean.origin_column + column_delta).rem_euclid(i32::from(STRATEGIC_MAP_WIDTH));
            let screen_x = column_delta * OCEAN_TILE + odd;
            let screen_y = row_delta * OCEAN_TILE;
            let Some(tile) = state.map().geometry().tile(row as u16, column as u16) else {
                continue;
            };
            let color = ocean_tile_index(state.map()[tile].terrain);
            fill_ocean_cell(&mut indices, screen_x, screen_y, color);
        }
    }
    indexed_image(&indices, palette)
}

fn ocean_tile_index(terrain: TerrainKind) -> u8 {
    match terrain {
        TerrainKind::Water => 0x54,
        TerrainKind::Forest => 0x40,
        TerrainKind::Mountain => 0x1c,
        TerrainKind::Hills => 0x2a,
        TerrainKind::Swamp => 0x48,
        TerrainKind::Desert => 0x36,
        TerrainKind::Farmland => 0x3c,
        TerrainKind::Plains => 0x38,
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

fn empty_ocean_image(palette: &DibPalette) -> Image {
    indexed_image(&vec![0; VIEWPORT_WIDTH * VIEWPORT_HEIGHT], palette)
}

fn indexed_image(indices: &[u8], palette: &DibPalette) -> Image {
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
