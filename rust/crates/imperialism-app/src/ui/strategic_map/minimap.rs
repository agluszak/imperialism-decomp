//! In-game toolbar mini-map: `TMiniMapView::Draw` / `TrackMouse` plus the
//! `TMacViewMgr` owner-color atlas.

use super::super::RetailUiAssets;
use super::super::retail::RetailTree;
use super::super::retail_raster::{IndexedRasterExt, indexed_picture};
use super::super::{GameSession, MapViewOrigin};
use super::map_interaction::{
    MapProjection, MapTransition, StrategicInteraction, StrategicViewport, apply_map_transition,
};
use crate::RetailAssetsResource;
use crate::ui::retail_palette::view_mgr_color;
use bevy::picking::events::{Click, Drag, DragEnd, Pointer, Press};
use bevy::prelude::*;
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
const MARKER_PALETTE: u8 = 0x13;
#[cfg(test)]
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
    origin: TileId,
) {
    let toolbar = tree.find(root, TOOL_TAG);
    let (image, window) = compose_minimap(
        &session.game,
        origin,
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
    origin: Res<MapViewOrigin>,
    viewports: Query<Ref<StrategicViewport>>,
    mut images: ResMut<Assets<Image>>,
    retail_assets: Res<RetailAssetsResource>,
    mut minimaps: Query<(&mut MiniMap, &ImageNode)>,
) {
    let Ok(viewport) = viewports.single() else {
        return;
    };
    let (view_origin, marker) = active_minimap_view(&session, origin.0, &viewport);
    let palette = retail_assets.assets().default_dib_palette();
    for (mut minimap, image_node) in &mut minimaps {
        if !session.is_changed()
            && !origin.is_changed()
            && !viewport.is_changed()
            && !minimap.is_added()
        {
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
    origin: Res<MapViewOrigin>,
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
    let (view_origin, marker) = active_minimap_view(&session, origin.0, viewport);
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
    origin: Res<MapViewOrigin>,
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
    let (view_origin, marker) = active_minimap_view(&session, origin.0, viewport);
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
    mut origin: ResMut<MapViewOrigin>,
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
        &mut origin,
        &mut interaction,
        &mut viewport,
        &mut images,
        retail_assets.assets().default_dib_palette(),
    );
}

fn on_minimap_drag_end(
    drag_end: On<Pointer<DragEnd>>,
    mut session: ResMut<GameSession>,
    mut origin: ResMut<MapViewOrigin>,
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
        &mut origin,
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
    origin: &mut MapViewOrigin,
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
        origin,
        interaction,
        viewport,
        MapTransition::SetUpperLeft(IVec2::new(column, row)),
    );
    minimap.drag_pixel = None;
    let (view_origin, marker) = active_minimap_view(session, origin.0, viewport);
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
    origin: TileId,
    viewport: &StrategicViewport,
) -> (TileId, ViewportMarker) {
    let marker = marker_size(viewport);
    if viewport.projection == MapProjection::Detailed {
        return (origin, marker);
    }
    let origin = session
        .game
        .map()
        .geometry()
        .tile(
            viewport.ocean.origin.y as u16,
            viewport.ocean.origin.x as u16,
        )
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
    let mut picture = indexed_picture(FRAME_WIDTH, FRAME_HEIGHT, 0);
    blit_minimap_window(&atlas, window, state.map().topology, &mut picture);
    let (x, y) = viewport_marker(window, drag_pixel, marker);
    picture.frame_rect(
        IRect::new(
            x,
            y,
            x + marker.half_width * 2 + 1,
            y + marker.half_height * 2 + 1,
        ),
        MARKER_PALETTE,
    );
    (picture.to_image(palette), window)
}

pub(super) fn compose_minimap_atlas(state: &GameState) -> IndexedPicture {
    let fill = view_mgr_color(0x32);
    let mut atlas = indexed_picture(ATLAS_WIDTH as i32, ATLAS_HEIGHT as i32, fill);
    for index in 0..STRATEGIC_TILE_COUNT {
        let tile = TileId::new(index as u16);
        let Some(palette_index) = atlas_owner_palette(state.map()[tile].owner_nation) else {
            continue;
        };
        let column = (index % MAP_COLUMNS as usize) * 2;
        let row = (index / MAP_COLUMNS as usize) * 2;
        atlas.fill_rect(
            IRect::new(column as i32, row as i32, column as i32 + 2, row as i32 + 2),
            palette_index,
        );
    }
    smooth_minimap_atlas(&mut atlas.pixels);
    atlas
}

fn smooth_minimap_atlas(atlas: &mut [u8]) {
    let mut scratch = atlas.to_vec();
    for y in 2..114 {
        for x in 1..215 {
            let index = y * ATLAS_WIDTH + x;
            let center = atlas[index];
            let left = atlas[index - 1];
            let right = atlas[index + 1];
            if (atlas[index - ATLAS_WIDTH] != center || atlas[index + ATLAS_WIDTH] != center)
                && (left != center || right != center)
            {
                scratch[index] = if left != center { left } else { right };
            }
        }
    }
    atlas.copy_from_slice(&scratch);
}

fn atlas_owner_palette(owner: Option<TileOwnerTag>) -> Option<u8> {
    let owner_code = match owner {
        None => -1,
        Some(tag) => i16::from(tag.get()),
    };
    if owner_code >= 0x17 {
        return None;
    }
    let color_code = if owner_code == 0 { 0x3e } else { owner_code };
    Some(view_mgr_color(color_code))
}

pub(super) fn minimap_window(origin: TileId, marker: ViewportMarker) -> MiniMapWindow {
    let index = i32::from(origin.get());
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
    atlas: &IndexedPicture,
    window: MiniMapWindow,
    topology: MapTopology,
    destination: &mut IndexedPicture,
) {
    let src_left = window.source_column * 2;
    let src_top = window.source_row * 2;
    let src_right = src_left + FRAME_WIDTH;
    let src_bottom = src_top + FRAME_HEIGHT;
    let overflow = src_right - ATLAS_SEAM;
    if overflow <= 0 {
        destination.copy_rect(
            atlas,
            IRect::new(src_left, src_top, src_right, src_bottom),
            IVec2::ZERO,
        );
        return;
    }

    let first_dest_right = ATLAS_SEAM - src_left;
    if !topology.wraps_horizontally() && first_dest_right <= FRAME_WIDTH / 2 {
        destination.fill_rect(IRect::new(0, 0, first_dest_right, FRAME_HEIGHT), 0);
    } else {
        destination.copy_rect(
            atlas,
            IRect::new(src_left, src_top, ATLAS_SEAM, src_bottom),
            IVec2::ZERO,
        );
    }
    let second_dest_left = FRAME_WIDTH - overflow;
    if !topology.wraps_horizontally() && overflow <= FRAME_WIDTH / 2 {
        destination.fill_rect(
            IRect::new(second_dest_left, 0, FRAME_WIDTH, FRAME_HEIGHT),
            0,
        );
    } else {
        destination.copy_rect(
            atlas,
            IRect::new(0, src_top, overflow, src_bottom),
            IVec2::new(second_dest_left, 0),
        );
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
                let tile = parts.map.geometry().tile(row, column).unwrap();
                parts.map[tile].owner_nation = Some(TileOwnerTag::new(0));
            }
        }
        let sea = parts.map.geometry().tile(10, 40).unwrap();
        parts.map[sea].owner_nation = Some(TileOwnerTag::new(0x17));
        let state = GameState::from_parts(parts);
        let atlas = compose_minimap_atlas(&state);
        assert_eq!(atlas.pixels[20 * ATLAS_WIDTH + 20], view_mgr_color(0x3e));
        assert_eq!(atlas.pixels[20 * ATLAS_WIDTH + 80], view_mgr_color(0x32));
        assert_eq!(atlas_owner_palette(Some(TileOwnerTag::new(0))), Some(0x15));
        assert_eq!(atlas_owner_palette(Some(TileOwnerTag::new(0x17))), None);
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
        assert!(atlas.pixels.contains(&view_mgr_color(0x32)));
        assert!(atlas.pixels.iter().any(|&pixel| {
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
        let mut surface = indexed_picture(FRAME_WIDTH, FRAME_HEIGHT, 0);
        blit_minimap_window(&atlas, window, state.map().topology, &mut surface);
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
        palette[MARKER_PALETTE] = Rgb::new(0xff, 0xff, 0xff);
        palette
    }
}
