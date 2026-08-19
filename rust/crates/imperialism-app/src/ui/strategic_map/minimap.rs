//! In-game toolbar mini-map: `TMiniMapView::Draw` / `TrackMouse` plus the
//! `TMacViewMgr` owner-color atlas.

use super::super::GameSession;
use super::super::RetailUiAssets;
use super::super::retail::RetailTree;
use super::map_interaction::{
    MapProjection, MapTransition, StrategicInteraction, StrategicViewport, apply_map_transition,
};
use crate::RetailAssetsResource;
use bevy::asset::RenderAssetUsages;
use bevy::image::ImageSampler;
use bevy::picking::events::{Click, Drag, DragEnd, Pointer, Press};
use bevy::prelude::*;
use bevy::render::render_resource::{Extent3d, TextureDimension, TextureFormat};
use bevy::ui::RelativeCursorPosition;
use imperialism_core::*;
use imperialism_formats::*;

const TOOL_TAG: FourCc = fourcc!("tool");
const FRAME_X: i32 = 4;
const FRAME_Y: i32 = 0x31;
pub(super) const FRAME_WIDTH: i32 = 0x71;
pub(super) const FRAME_HEIGHT: i32 = 0x41;
const ATLAS_WIDTH: usize = 0xd8;
const ATLAS_HEIGHT: usize = 0x78;
const ATLAS_SEAM: i32 = 0xd7;
const MAP_COLUMNS: i32 = 108;
const MAP_ROWS: i32 = 60;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ViewportMarker {
    half_width: i32,
    half_height: i32,
}

const DETAILED_MARKER: ViewportMarker = ViewportMarker {
    half_width: 9,
    half_height: 8,
};
const OCEAN_MARKER: ViewportMarker = ViewportMarker {
    half_width: 0x20,
    half_height: 0x1c,
};
#[cfg(test)]
const MARKER_WIDTH: i32 = DETAILED_MARKER.half_width;
#[cfg(test)]
const MARKER_HEIGHT: i32 = DETAILED_MARKER.half_height;
const WHITE_RGBA: [u8; 4] = [0xff, 0xff, 0xff, 0xff];

#[derive(Component)]
pub(crate) struct MiniMap {
    drag_pixel: Option<(i32, i32)>,
    scroll_column: i32,
    scroll_row: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MiniMapWindow {
    pub(super) source_column: i32,
    pub(super) source_row: i32,
    pub(super) vertical_clip_offset: i32,
}

pub(crate) fn bind_minimap(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    assets: &mut RetailUiAssets,
    session: &GameSession,
) {
    let toolbar = tree.find(root, TOOL_TAG);
    let (image, window) = compose_minimap(
        &session.game,
        session.map_view_origin,
        assets.default_dib_palette(),
        None,
        DETAILED_MARKER,
    );
    let image = assets.add_image(image);
    commands.entity(toolbar).with_children(|parent| {
        parent
            .spawn((
                MiniMap {
                    drag_pixel: None,
                    scroll_column: window.source_column,
                    scroll_row: window.source_row,
                },
                Node {
                    position_type: PositionType::Absolute,
                    left: px(FRAME_X),
                    top: px(FRAME_Y),
                    width: px(FRAME_WIDTH),
                    height: px(FRAME_HEIGHT),
                    overflow: Overflow::clip(),
                    ..default()
                },
                ImageNode::new(image),
                RelativeCursorPosition::default(),
                Pickable::default(),
            ))
            .observe(on_minimap_press)
            .observe(on_minimap_drag)
            .observe(on_minimap_click)
            .observe(on_minimap_drag_end);
    });
}

pub(crate) fn sync_minimap(
    session: Res<GameSession>,
    viewports: Query<Ref<StrategicViewport>>,
    mut images: ResMut<Assets<Image>>,
    retail_assets: Res<RetailAssetsResource>,
    mut minimaps: Query<(&mut MiniMap, &ImageNode)>,
) {
    let Ok(viewport) = viewports.single() else {
        return;
    };
    let (view_origin, marker) = active_minimap_view(&session, &viewport);
    let palette = retail_assets.assets().default_dib_palette();
    for (mut minimap, image_node) in &mut minimaps {
        if !session.is_changed() && !viewport.is_changed() && !minimap.is_added() {
            continue;
        }
        let drag_pixel = minimap.drag_pixel;
        write_minimap(
            &mut minimap,
            image_node,
            &mut images,
            &session.game,
            view_origin,
            palette,
            drag_pixel,
            marker,
        );
    }
}

fn on_minimap_press(
    press: On<Pointer<Press>>,
    session: Res<GameSession>,
    viewports: Query<&StrategicViewport>,
    mut images: ResMut<Assets<Image>>,
    retail_assets: Res<RetailAssetsResource>,
    mut minimaps: Query<(&RelativeCursorPosition, &mut MiniMap, &ImageNode)>,
) {
    if press.event.button != PointerButton::Primary {
        return;
    }
    let Ok((cursor, mut minimap, image_node)) = minimaps.get_mut(press.entity) else {
        return;
    };
    let Some(pixel) = cursor_pixel(cursor) else {
        return;
    };
    let Ok(viewport) = viewports.single() else {
        return;
    };
    let (view_origin, marker) = active_minimap_view(&session, viewport);
    minimap.drag_pixel = Some(pixel);
    write_minimap(
        &mut minimap,
        image_node,
        &mut images,
        &session.game,
        view_origin,
        retail_assets.assets().default_dib_palette(),
        Some(pixel),
        marker,
    );
}

fn on_minimap_drag(
    drag: On<Pointer<Drag>>,
    session: Res<GameSession>,
    viewports: Query<&StrategicViewport>,
    mut images: ResMut<Assets<Image>>,
    retail_assets: Res<RetailAssetsResource>,
    mut minimaps: Query<(&RelativeCursorPosition, &mut MiniMap, &ImageNode)>,
) {
    if drag.event.button != PointerButton::Primary {
        return;
    }
    let Ok((cursor, mut minimap, image_node)) = minimaps.get_mut(drag.entity) else {
        return;
    };
    let Some(pixel) = cursor_pixel(cursor) else {
        return;
    };
    let Ok(viewport) = viewports.single() else {
        return;
    };
    let (view_origin, marker) = active_minimap_view(&session, viewport);
    minimap.drag_pixel = Some(pixel);
    write_minimap(
        &mut minimap,
        image_node,
        &mut images,
        &session.game,
        view_origin,
        retail_assets.assets().default_dib_palette(),
        Some(pixel),
        marker,
    );
}

fn on_minimap_click(
    click: On<Pointer<Click>>,
    mut session: ResMut<GameSession>,
    mut maps: Query<(&mut StrategicInteraction, &mut StrategicViewport)>,
    mut images: ResMut<Assets<Image>>,
    retail_assets: Res<RetailAssetsResource>,
    mut minimaps: Query<(&RelativeCursorPosition, &mut MiniMap, &ImageNode)>,
) {
    if click.event.button != PointerButton::Primary {
        return;
    }
    let Ok((cursor, mut minimap, image_node)) = minimaps.get_mut(click.entity) else {
        return;
    };
    let Ok((mut interaction, mut viewport)) = maps.single_mut() else {
        return;
    };
    commit_minimap_track(
        cursor,
        &mut minimap,
        image_node,
        &mut session,
        &mut interaction,
        &mut viewport,
        &mut images,
        retail_assets.assets().default_dib_palette(),
    );
}

fn on_minimap_drag_end(
    drag_end: On<Pointer<DragEnd>>,
    mut session: ResMut<GameSession>,
    mut maps: Query<(&mut StrategicInteraction, &mut StrategicViewport)>,
    mut images: ResMut<Assets<Image>>,
    retail_assets: Res<RetailAssetsResource>,
    mut minimaps: Query<(&RelativeCursorPosition, &mut MiniMap, &ImageNode)>,
) {
    if drag_end.event.button != PointerButton::Primary {
        return;
    }
    let Ok((cursor, mut minimap, image_node)) = minimaps.get_mut(drag_end.entity) else {
        return;
    };
    let Ok((mut interaction, mut viewport)) = maps.single_mut() else {
        return;
    };
    commit_minimap_track(
        cursor,
        &mut minimap,
        image_node,
        &mut session,
        &mut interaction,
        &mut viewport,
        &mut images,
        retail_assets.assets().default_dib_palette(),
    );
}

fn commit_minimap_track(
    cursor: &RelativeCursorPosition,
    minimap: &mut MiniMap,
    image_node: &ImageNode,
    session: &mut GameSession,
    interaction: &mut StrategicInteraction,
    viewport: &mut StrategicViewport,
    images: &mut Assets<Image>,
    palette: &DibPalette,
) {
    let Some(drag_pixel) = minimap.drag_pixel else {
        return;
    };
    let pixel = cursor_pixel_unclamped(cursor).unwrap_or(drag_pixel);
    let marker = marker_size(viewport);
    let (column, row) =
        minimap_release_cell(pixel, minimap.scroll_column, minimap.scroll_row, marker);
    apply_map_transition(
        session,
        interaction,
        viewport,
        MapTransition::SetUpperLeft(IVec2::new(column, row)),
    );
    minimap.drag_pixel = None;
    let (view_origin, marker) = active_minimap_view(session, viewport);
    write_minimap(
        minimap,
        image_node,
        images,
        &session.game,
        view_origin,
        palette,
        None,
        marker,
    );
}

fn write_minimap(
    minimap: &mut MiniMap,
    image_node: &ImageNode,
    images: &mut Assets<Image>,
    state: &GameState,
    view_origin: TileId,
    palette: &DibPalette,
    drag_pixel: Option<(i32, i32)>,
    marker: ViewportMarker,
) {
    let (image, window) = compose_minimap(state, view_origin, palette, drag_pixel, marker);
    minimap.scroll_column = window.source_column;
    minimap.scroll_row = window.source_row;
    let Some(mut existing) = images.get_mut(&image_node.image) else {
        return;
    };
    *existing = image;
}

fn marker_size(viewport: &StrategicViewport) -> ViewportMarker {
    if viewport.projection == MapProjection::Overview {
        OCEAN_MARKER
    } else {
        DETAILED_MARKER
    }
}

fn active_minimap_view(
    session: &GameSession,
    viewport: &StrategicViewport,
) -> (TileId, ViewportMarker) {
    let marker = marker_size(viewport);
    if viewport.projection == MapProjection::Detailed {
        return (session.map_view_origin, marker);
    }
    let origin = session
        .game
        .map()
        .geometry()
        .tile(MapPosition::new(
            viewport.ocean.origin.y,
            viewport.ocean.origin.x,
        ))
        .expect("retail ocean origin is inside the map");
    (origin, marker)
}

fn cursor_pixel(cursor: &RelativeCursorPosition) -> Option<(i32, i32)> {
    let (x, y) = cursor_pixel_unclamped(cursor).filter(|_| cursor.cursor_over())?;
    if (0..FRAME_WIDTH).contains(&x) && (0..FRAME_HEIGHT).contains(&y) {
        Some((x, y))
    } else {
        None
    }
}

fn cursor_pixel_unclamped(cursor: &RelativeCursorPosition) -> Option<(i32, i32)> {
    let position = cursor.normalized?;
    Some((
        ((position.x + 0.5) * FRAME_WIDTH as f32).floor() as i32,
        ((position.y + 0.5) * FRAME_HEIGHT as f32).floor() as i32,
    ))
}

pub(super) fn compose_minimap(
    state: &GameState,
    view_origin: TileId,
    palette: &DibPalette,
    drag_pixel: Option<(i32, i32)>,
    marker: ViewportMarker,
) -> (Image, MiniMapWindow) {
    let atlas = compose_minimap_atlas(state);
    let window = minimap_window(view_origin, marker);
    let mut indices = vec![0_u8; (FRAME_WIDTH * FRAME_HEIGHT) as usize];
    blit_minimap_window(&atlas, window, state.map().topology, &mut indices);
    let mut rgba = Vec::with_capacity(indices.len() * 4);
    for &palette_index in &indices {
        palette[palette_index].write_rgba(0xff, &mut rgba);
    }
    let marker_origin = viewport_marker(window, drag_pixel, marker);
    draw_white_rect(
        &mut rgba,
        marker_origin.0,
        marker_origin.1,
        marker_origin.0 + marker.half_width * 2,
        marker_origin.1 + marker.half_height * 2,
    );
    (rgba_image(&rgba), window)
}

pub(super) fn compose_minimap_atlas(state: &GameState) -> Vec<u8> {
    let fill = view_mgr_color(0x32);
    let mut atlas = vec![fill; ATLAS_WIDTH * ATLAS_HEIGHT];
    for index in 0..STRATEGIC_TILE_COUNT {
        let tile = TileId::new(index);
        let Some(palette_index) = atlas_owner_palette(state.map()[tile].owner_nation) else {
            continue;
        };
        let column = (index % MAP_COLUMNS as usize) * 2;
        let row = (index / MAP_COLUMNS as usize) * 2;
        atlas[row * ATLAS_WIDTH + column] = palette_index;
        atlas[row * ATLAS_WIDTH + column + 1] = palette_index;
        atlas[(row + 1) * ATLAS_WIDTH + column] = palette_index;
        atlas[(row + 1) * ATLAS_WIDTH + column + 1] = palette_index;
    }
    smooth_minimap_atlas(&mut atlas);
    atlas
}

fn smooth_minimap_atlas(atlas: &mut [u8]) {
    let mut scratch = atlas.to_vec();
    let stride = ATLAS_WIDTH as i32;
    let mut compare = stride * 2 + 1;
    let mut scratch_pos = 0x1b1;
    for _ in 0..0x70 {
        for _ in 0..0xd6 {
            let center = atlas[compare as usize];
            let left = atlas[(compare - 1) as usize];
            let right = atlas[(compare + 1) as usize];
            if atlas[(compare - stride) as usize] != center && (left != center || right != center) {
                scratch[scratch_pos] = if left != center { left } else { right };
            }
            if atlas[(compare + stride) as usize] != center && (left != center || right != center) {
                scratch[scratch_pos] = if left != center { left } else { right };
            }
            compare += 1;
            scratch_pos += 1;
        }
        compare += stride - 0xd6;
        scratch_pos += 2;
    }
    atlas.copy_from_slice(&scratch);
}

fn atlas_owner_palette(owner: Option<TileContext>) -> Option<u8> {
    let owner_code = match owner {
        None => -1,
        Some(tag) => i16::from(tag.to_retail_tag()),
    };
    if owner_code >= 0x17 {
        return None;
    }
    let color_code = if owner_code == 0 { 0x3e } else { owner_code };
    Some(view_mgr_color(color_code))
}

pub(super) fn minimap_window(origin: TileId, marker: ViewportMarker) -> MiniMapWindow {
    let index = origin.get() as i32;
    let mut source_column = index % MAP_COLUMNS;
    let mut source_row = index / MAP_COLUMNS;
    source_column -= (FRAME_WIDTH / 2 - marker.half_width) / 2 + 1;
    source_row -= (FRAME_HEIGHT / 2 - marker.half_height) / 2 + 1;
    let mut vertical_clip_offset = 0;
    if source_column < 0 {
        source_column += MAP_COLUMNS;
    }
    if source_row < 0 {
        vertical_clip_offset = source_row * 2;
        source_row = 0;
    } else {
        let visible_rows = (FRAME_HEIGHT + 1) / 2;
        if source_row + visible_rows > MAP_ROWS {
            vertical_clip_offset = (source_row + visible_rows) * 2 - 120;
            source_row = MAP_ROWS - visible_rows;
        }
    }
    MiniMapWindow {
        source_column,
        source_row,
        vertical_clip_offset,
    }
}

fn blit_minimap_window(
    atlas: &[u8],
    window: MiniMapWindow,
    topology: MapTopology,
    dest: &mut [u8],
) {
    let src_left = window.source_column * 2;
    let src_top = window.source_row * 2;
    let src_right = src_left + FRAME_WIDTH;
    let src_bottom = src_top + FRAME_HEIGHT;
    let overflow = src_right - ATLAS_SEAM;
    if overflow <= 0 {
        copy_atlas_rect(
            atlas,
            (src_left, src_top, src_right, src_bottom),
            dest,
            (0, 0),
        );
        return;
    }

    let first_dest_right = ATLAS_SEAM - src_left;
    if !topology.wraps_horizontally() && first_dest_right <= FRAME_WIDTH / 2 {
        fill_rect(dest, 0, 0, first_dest_right, FRAME_HEIGHT, 0);
    } else {
        copy_atlas_rect(
            atlas,
            (src_left, src_top, ATLAS_SEAM, src_bottom),
            dest,
            (0, 0),
        );
    }
    let second_dest_left = FRAME_WIDTH - overflow;
    if !topology.wraps_horizontally() && overflow <= FRAME_WIDTH / 2 {
        fill_rect(dest, second_dest_left, 0, FRAME_WIDTH, FRAME_HEIGHT, 0);
    } else {
        copy_atlas_rect(
            atlas,
            (0, src_top, overflow, src_bottom),
            dest,
            (second_dest_left, 0),
        );
    }
}

fn copy_atlas_rect(
    atlas: &[u8],
    src: (i32, i32, i32, i32),
    dest: &mut [u8],
    dest_origin: (i32, i32),
) {
    let (src_left, src_top, src_right, src_bottom) = src;
    let (dest_left, dest_top) = dest_origin;
    let width = src_right - src_left;
    let height = src_bottom - src_top;
    for y in 0..height {
        let src_y = src_top + y;
        let dest_y = dest_top + y;
        if !(0..ATLAS_HEIGHT as i32).contains(&src_y) || !(0..FRAME_HEIGHT).contains(&dest_y) {
            continue;
        }
        for x in 0..width {
            let src_x = src_left + x;
            let dest_x = dest_left + x;
            if !(0..ATLAS_WIDTH as i32).contains(&src_x) || !(0..FRAME_WIDTH).contains(&dest_x) {
                continue;
            }
            dest[(dest_y * FRAME_WIDTH + dest_x) as usize] =
                atlas[(src_y as usize) * ATLAS_WIDTH + src_x as usize];
        }
    }
}

fn fill_rect(dest: &mut [u8], left: i32, top: i32, right: i32, bottom: i32, color: u8) {
    for y in top.max(0)..bottom.min(FRAME_HEIGHT) {
        for x in left.max(0)..right.min(FRAME_WIDTH) {
            dest[(y * FRAME_WIDTH + x) as usize] = color;
        }
    }
}

pub(super) fn viewport_marker(
    window: MiniMapWindow,
    drag_pixel: Option<(i32, i32)>,
    marker: ViewportMarker,
) -> (i32, i32) {
    if let Some((x, y)) = drag_pixel {
        return (x - marker.half_width, y - marker.half_height);
    }
    (
        FRAME_WIDTH / 2 - marker.half_width,
        FRAME_HEIGHT / 2 - marker.half_height + window.vertical_clip_offset,
    )
}

pub(super) fn minimap_release_cell(
    pixel: (i32, i32),
    scroll_column: i32,
    scroll_row: i32,
    marker: ViewportMarker,
) -> (i32, i32) {
    let mut column = pixel.0 / 2 + scroll_column - marker.half_width / 2;
    let row = pixel.1 / 2 + scroll_row - marker.half_height / 2;
    if column < 0 {
        column += MAP_COLUMNS;
    } else if column >= MAP_COLUMNS {
        column -= MAP_COLUMNS;
    }
    (column, row.clamp(0, MAP_ROWS))
}

fn draw_white_rect(rgba: &mut [u8], left: i32, top: i32, right: i32, bottom: i32) {
    for x in left..=right {
        put_rgba(rgba, x, top);
        put_rgba(rgba, x, bottom);
    }
    for y in top..=bottom {
        put_rgba(rgba, left, y);
        put_rgba(rgba, right, y);
    }
}

fn put_rgba(rgba: &mut [u8], x: i32, y: i32) {
    if !(0..FRAME_WIDTH).contains(&x) || !(0..FRAME_HEIGHT).contains(&y) {
        return;
    }
    let start = ((y * FRAME_WIDTH + x) as usize) * 4;
    rgba[start..start + 4].copy_from_slice(&WHITE_RGBA);
}

fn rgba_image(rgba: &[u8]) -> Image {
    let mut image = Image::new(
        Extent3d {
            width: FRAME_WIDTH as u32,
            height: FRAME_HEIGHT as u32,
            depth_or_array_layers: 1,
        },
        TextureDimension::D2,
        rgba.to_vec(),
        TextureFormat::Rgba8UnormSrgb,
        RenderAssetUsages::default(),
    );
    image.sampler = ImageSampler::nearest();
    image
}

/// Retail `TViewMgr::GetColor`.
pub(super) fn view_mgr_color(event_code: i16) -> u8 {
    if event_code > 200 {
        if event_code < 0x2b68 {
            if event_code == 0x2b67 {
                return 0;
            }
            return match event_code {
                0xc9 => 0x2d,
                0xca => 0x30,
                0xcb => 0x2e,
                0xcc => 0x27,
                0xcd => 0x24,
                0xce => 0x26,
                0xcf => 0x18,
                0xd0 => 0x14,
                _ => 0xff,
            };
        }
        return match event_code {
            0x2b68 => 0x13,
            0x2b69 => 0xcb,
            0x2b6a => 0x5c,
            0x2b6b => 0xd2,
            0x2b6c => 0x28,
            0x2b6d => 1,
            _ => 0xff,
        };
    }
    if event_code == 200 {
        return 0x20;
    }
    match event_code {
        0 => 0x16,
        1 => 0x2a,
        2 | 0x40 => 0x22,
        3 | 0x3c | 0x4e => 0x1c,
        4 => 0x2b,
        5 => 0x1e,
        6 => 0x2e,
        7 | 0x35 => 10,
        8 | 0x3d => 0xb,
        9 => 0xd,
        10 | 0x43 => 0x29,
        0xb => 0xde,
        0xc | 0x47 => 0xdf,
        0xd | 0x49 => 0xfa,
        0xe | 0x38 => 0x2c,
        0xf | 0x4a => 0x31,
        0x10 => 0x33,
        0x11 => 0x41,
        0x12 => 0x48,
        0x13 => 0xd0,
        0x14 => 0xcd,
        0x15 => 0xce,
        0x16 => 0xcf,
        0x25 | 0x3f => 0x20,
        0x32 => 0x1a,
        0x33 => 0x2d,
        0x34 => 0x18,
        0x37 => 0xbd,
        0x3a => 0xc6,
        0x3b => 0x27,
        0x3e => 0x15,
        0x41 => 0x1b,
        0x42 => 0x21,
        0x44 => 0x17,
        0x45 => 0x5f,
        0x46 => 0xbe,
        0x48 => 100,
        0x4b => 0x66,
        0x4c => 0x89,
        0x4d => 0xad,
        0x4f => 0xe7,
        0x50 => 0xe6,
        0x51 => 0xf6,
        0x52 => 0xc,
        0x53 => 0xef,
        0x54 => 0xf9,
        _ => 0xff,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::test_support::{
        beginning_of_game_parts_with, beginning_of_game_with, strategic_map_beginning_context,
    };

    fn fixture_state() -> GameState {
        beginning_of_game_with(strategic_map_beginning_context())
    }

    #[test]
    fn land_map_window_follows_retail_source_offset_and_north_clip() {
        let origin = TileId::new(0);
        let window = minimap_window(origin, DETAILED_MARKER);
        assert_eq!(
            window,
            MiniMapWindow {
                source_column: 84,
                source_row: 0,
                vertical_clip_offset: -26,
            }
        );
        assert_eq!(viewport_marker(window, None, DETAILED_MARKER), (47, -2));
    }

    #[test]
    fn interior_origin_keeps_the_marker_centered() {
        let origin = TileId::new(20 * 108 + 40);
        let window = minimap_window(origin, DETAILED_MARKER);
        assert_eq!(
            window,
            MiniMapWindow {
                source_column: 16,
                source_row: 7,
                vertical_clip_offset: 0,
            }
        );
        assert_eq!(viewport_marker(window, None, DETAILED_MARKER), (47, 24));
        assert_eq!(
            viewport_marker(window, Some((60, 40)), DETAILED_MARKER),
            (51, 32)
        );
    }

    #[test]
    fn ocean_marker_uses_retail_dimensions_and_release_offset() {
        let origin = TileId::new(20 * 108 + 40);
        let window = minimap_window(origin, OCEAN_MARKER);
        assert_eq!(
            window,
            MiniMapWindow {
                source_column: 27,
                source_row: 17,
                vertical_clip_offset: 0,
            }
        );
        assert_eq!(viewport_marker(window, None, OCEAN_MARKER), (24, 4));
        assert_eq!(
            minimap_release_cell((60, 40), 27, 17, OCEAN_MARKER),
            (41, 23)
        );
    }

    #[test]
    fn interior_compose_draws_the_white_viewport_rect() {
        let state = fixture_state();
        let mut view_origin = TileId::new(20 * 108 + 40);
        let palette = nation_preview_palette();
        let (image, window) = compose_minimap(&state, view_origin, &palette, None, DETAILED_MARKER);
        assert_eq!(viewport_marker(window, None, DETAILED_MARKER), (47, 24));
        let pixels = image
            .data
            .as_ref()
            .expect("composed minimap keeps CPU pixels");
        let sample = |x: i32, y: i32| {
            let start = ((y * FRAME_WIDTH + x) as usize) * 4;
            [
                pixels[start],
                pixels[start + 1],
                pixels[start + 2],
                pixels[start + 3],
            ]
        };
        assert_eq!(sample(47, 24), WHITE_RGBA);
        assert_eq!(sample(47 + MARKER_WIDTH * 2, 24), WHITE_RGBA);
        assert_eq!(sample(47, 24 + MARKER_HEIGHT * 2), WHITE_RGBA);
        assert_eq!(
            sample(47 + MARKER_WIDTH * 2, 24 + MARKER_HEIGHT * 2),
            WHITE_RGBA
        );
        assert_ne!(sample(48, 25), WHITE_RGBA);

        let (column, row) = minimap_release_cell(
            (60, 40),
            window.source_column,
            window.source_row,
            DETAILED_MARKER,
        );
        view_origin = state.map().viewport_origin_from_upper_left(column, row);
        let window = minimap_window(view_origin, DETAILED_MARKER);
        assert_eq!(
            viewport_marker(window, None, DETAILED_MARKER).0,
            FRAME_WIDTH / 2 - MARKER_WIDTH
        );
    }

    #[test]
    fn click_converts_through_scroll_and_marker_half_size() {
        assert_eq!(
            minimap_release_cell((60, 40), 16, 7, DETAILED_MARKER),
            (42, 23)
        );
        assert_eq!(
            minimap_release_cell((0, 0), 0, 0, DETAILED_MARKER),
            (104, 0)
        );
        assert_eq!(
            minimap_release_cell((112, 64), 100, 50, DETAILED_MARKER),
            (44, 60)
        );
    }

    #[test]
    fn owner_zero_uses_the_retail_0x3e_palette_and_sea_zones_keep_fill() {
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        for row in 9..=11 {
            for column in 9..=11 {
                let tile = parts
                    .map
                    .geometry()
                    .tile(MapPosition::new(row, column))
                    .unwrap();
                parts.map[tile].owner_nation = Some(TileContext::from(MajorNationId::new(0)));
            }
        }
        let sea = parts.map.geometry().tile(MapPosition::new(10, 40)).unwrap();
        parts.map[sea].owner_nation = Some(TileContext::Ocean(OceanZoneId::new(0)));
        let state = GameState::from_parts(parts);
        let atlas = compose_minimap_atlas(&state);
        assert_eq!(atlas[20 * ATLAS_WIDTH + 20], view_mgr_color(0x3e));
        assert_eq!(atlas[20 * ATLAS_WIDTH + 80], view_mgr_color(0x32));
        assert_eq!(
            atlas_owner_palette(Some(TileContext::from(MajorNationId::new(0)))),
            Some(0x15)
        );
        assert_eq!(
            atlas_owner_palette(Some(TileContext::Ocean(OceanZoneId::new(0)))),
            None
        );
        assert_eq!(atlas_owner_palette(None), Some(0xff));
        assert_eq!(view_mgr_color(0x3e), 0x15);
        assert_eq!(view_mgr_color(0x32), 0x1a);
        assert_eq!(view_mgr_color(0), 0x16);
        assert_eq!(view_mgr_color(-1), 0xff);
        assert_eq!(view_mgr_color(6), 0x2e);
    }

    #[test]
    fn beginning_of_game_atlas_paints_nations_and_ocean_fill() {
        let state = fixture_state();
        let atlas = compose_minimap_atlas(&state);
        assert!(atlas.contains(&view_mgr_color(0x32)));
        assert!(atlas.iter().any(|&pixel| {
            [
                view_mgr_color(0x3e),
                view_mgr_color(1),
                view_mgr_color(2),
                view_mgr_color(3),
                view_mgr_color(4),
                view_mgr_color(5),
                view_mgr_color(6),
            ]
            .contains(&pixel)
        }));
        let view_origin = TileId::new(1);
        let window = minimap_window(view_origin, DETAILED_MARKER);
        let mut indices = vec![0_u8; (FRAME_WIDTH * FRAME_HEIGHT) as usize];
        blit_minimap_window(&atlas, window, state.map().topology, &mut indices);
        let (mx, my) = viewport_marker(window, None, DETAILED_MARKER);
        assert!((0..FRAME_WIDTH).contains(&(mx + MARKER_WIDTH * 2)));
        assert!((0..FRAME_HEIGHT).contains(&(my + MARKER_HEIGHT * 2)) || my < 0);
        let (image, window) = compose_minimap(
            &state,
            view_origin,
            &nation_preview_palette(),
            None,
            DETAILED_MARKER,
        );
        let (mx, my) = viewport_marker(window, None, DETAILED_MARKER);
        let pixels = image
            .data
            .as_ref()
            .expect("composed minimap keeps CPU pixels");
        let sample = |x: i32, y: i32| {
            let start = ((y * FRAME_WIDTH + x) as usize) * 4;
            [
                pixels[start],
                pixels[start + 1],
                pixels[start + 2],
                pixels[start + 3],
            ]
        };
        let marker_x = mx.clamp(0, FRAME_WIDTH - 1);
        let marker_y = my.clamp(0, FRAME_HEIGHT - 1);
        assert_eq!(sample(marker_x, marker_y), WHITE_RGBA);
        assert_eq!(
            sample(
                (mx + MARKER_WIDTH * 2).clamp(0, FRAME_WIDTH - 1),
                (my + MARKER_HEIGHT * 2).clamp(0, FRAME_HEIGHT - 1)
            ),
            WHITE_RGBA
        );
    }

    fn nation_preview_palette() -> DibPalette {
        let mut palette = DibPalette::default();
        for index in 0..=255_u8 {
            palette[index] = Rgb::new(index, index / 2, 255 - index);
        }
        palette[view_mgr_color(0x32)] = Rgb::new(0x1a, 0x2c, 0x4a);
        palette[view_mgr_color(0x3e)] = Rgb::new(0x57, 0x8b, 0xa6);
        palette[view_mgr_color(1)] = Rgb::new(0xc4, 0x3a, 0x2a);
        palette[view_mgr_color(2)] = Rgb::new(0x2a, 0x6e, 0xc4);
        palette[view_mgr_color(3)] = Rgb::new(0xc4, 0x8a, 0x2a);
        palette[view_mgr_color(4)] = Rgb::new(0xc4, 0xc4, 0x2a);
        palette[view_mgr_color(5)] = Rgb::new(0x8b, 0x3a, 0x8b);
        palette[view_mgr_color(6)] = Rgb::new(0x2a, 0xc4, 0xa6);
        palette
    }
}
