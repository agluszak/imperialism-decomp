//! Bevy projection for the retail `DOOG` alternate strategic view.

use super::map_interaction::{
    MapProjection, OceanViewport, StrategicInteraction, StrategicViewport,
};
use super::ocean_raster::{OceanRaster, OceanRenderAssets};
use super::{VIEWPORT_HEIGHT, VIEWPORT_WIDTH};
use crate::AppState;
use crate::ui::GameSession;
use crate::ui::RetailUiAssets;
use crate::ui::retail::RetailTree;
use bevy::asset::RenderAssetUsages;
use bevy::image::ImageSampler;
use bevy::prelude::*;
use bevy::render::render_resource::{Extent3d, TextureDimension, TextureFormat};
use bevy::text::LineHeight;
use bevy::ui::RelativeCursorPosition;
use imperialism_core::*;
use imperialism_formats::*;

const LAND_POS: Vec2 = Vec2::new(5.0, 0x1b as f32);
const OCEAN_CELL_PIXELS: i32 = 0x10;
const RETAIL_MAP_COLUMNS: i32 = 108;

#[derive(Component)]
pub(crate) struct LandMapFrame;

#[derive(Component)]
pub(crate) struct OceanMapCanvas {
    composed: Option<OceanComposeKey>,
}

#[derive(Resource)]
struct CachedOceanRenderAssets(OceanRenderAssets);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OceanComposeKey {
    origin: IVec2,
    hovered: Option<TileId>,
    mode: super::map_interaction::MapInteractionMode,
    civilian: Option<CivilianUnitId>,
}

#[derive(Component)]
pub(crate) struct OceanZoneLabel;

#[derive(Component)]
pub(crate) struct OceanNationLabel;

#[derive(Component)]
struct OceanLabelAnchor {
    tile: TileId,
    offset: Vec2,
}

pub(crate) fn register(app: &mut App) {
    app.add_systems(
        Update,
        (sync_ocean_view_frames, sync_ocean_canvas, sync_ocean_labels)
            .chain()
            .run_if(in_state(AppState::StrategicMap)),
    );
}

pub(crate) fn bind_ocean_view(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
    session: &GameSession,
) -> Entity {
    let land = tree.find(root, fourcc!("DLOG"));
    commands.entity(land).insert(LandMapFrame);
    commands.insert_resource(CachedOceanRenderAssets(OceanRenderAssets::load(|id| {
        assets
            .indexed_picture(PictureId::new(id))
            .unwrap_or_else(|error| panic!("retail ocean picture {id} must load: {error}"))
    })));

    let ocean = tree.find(root, fourcc!("DOOG"));
    let palette = *assets.default_dib_palette();
    let image = assets.add_image(indexed_image(
        &vec![0; VIEWPORT_WIDTH * VIEWPORT_HEIGHT],
        &palette,
    ));
    commands.entity(ocean).insert((
        OceanMapCanvas { composed: None },
        ImageNode::new(image),
        Visibility::Hidden,
        RelativeCursorPosition::default(),
        Node {
            position_type: PositionType::Absolute,
            left: Val::Px(LAND_POS.x),
            top: Val::Px(LAND_POS.y),
            width: Val::Px(VIEWPORT_WIDTH as f32),
            height: Val::Px(VIEWPORT_HEIGHT as f32),
            ..default()
        },
    ));
    spawn_ocean_labels(commands, assets, ocean, session);
    ocean
}

fn sync_ocean_view_frames(
    viewports: Query<&StrategicViewport>,
    mut land: Query<&mut Visibility, (With<LandMapFrame>, Without<OceanMapCanvas>)>,
    mut sea: Query<&mut Visibility, (With<OceanMapCanvas>, Without<LandMapFrame>)>,
) {
    let Ok(viewport) = viewports.single() else {
        return;
    };
    let (land_visibility, sea_visibility) = match viewport.projection {
        MapProjection::Detailed => (Visibility::Visible, Visibility::Hidden),
        MapProjection::Overview => (Visibility::Hidden, Visibility::Visible),
    };
    if let Ok(mut visibility) = land.single_mut() {
        *visibility = land_visibility;
    }
    if let Ok(mut visibility) = sea.single_mut() {
        *visibility = sea_visibility;
    }
}

fn sync_ocean_canvas(
    session: Res<GameSession>,
    maps: Query<(Ref<StrategicInteraction>, Ref<StrategicViewport>)>,
    render_assets: Res<CachedOceanRenderAssets>,
    retail: Res<crate::RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut canvases: Query<(&mut OceanMapCanvas, &ImageNode, &RelativeCursorPosition)>,
) {
    let Ok((interaction, viewport)) = maps.single() else {
        return;
    };
    if viewport.projection != MapProjection::Overview {
        return;
    }
    for (mut canvas, node, cursor) in &mut canvases {
        let hovered = ocean_tile_at_cursor(&session.game, cursor, &viewport.ocean);
        let key = OceanComposeKey {
            origin: viewport.ocean.origin,
            hovered,
            mode: interaction.mode,
            civilian: interaction.civilian,
        };
        if canvas.composed == Some(key)
            && !session.is_changed()
            && !interaction.is_changed()
            && !viewport.is_changed()
        {
            continue;
        }
        let raster = OceanRaster::compose(
            &session.game,
            &viewport.ocean,
            &interaction,
            hovered,
            &render_assets.0,
        );
        if let Some(mut existing) = images.get_mut(&node.image) {
            *existing = indexed_image(raster.pixels(), retail.assets().default_dib_palette());
            canvas.composed = Some(key);
        }
    }
}

fn spawn_ocean_labels(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    canvas: Entity,
    session: &GameSession,
) {
    let (zone_font, zone_layout, zone_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 3,
            face_flags: 2,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail ocean-zone text style");
    let (nation_font, nation_layout, nation_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 1,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail ocean-nation text style");
    let palette = *assets.default_dib_palette();

    commands.entity(canvas).with_children(|parent| {
        for zone in session.game.ocean().zones.iter().rev() {
            let Some(tile) = zone.zone().target_tile else {
                continue;
            };
            let color = if matches!(zone, ZoneKind::PortZone(_)) {
                palette_color(&palette, 0)
            } else {
                palette_color(&palette, 0x13)
            };
            spawn_ocean_label(
                parent,
                OceanZoneLabel,
                &zone.zone().display_name,
                tile,
                Vec2::new(0.0, 2.0),
                color,
                &zone_font,
                &zone_layout,
                zone_line_height,
            );
        }

        for slot in 0..NationId::COUNT {
            let nation = NationId::new(slot);
            let Some(name) = session.game.nations().display_name(nation) else {
                continue;
            };
            // Retail stops the nation loop on the first missing computed anchor.
            let Some(tile) = session.game.ocean_overlay_anchor_for_nation(nation) else {
                break;
            };
            spawn_ocean_label(
                parent,
                OceanNationLabel,
                name,
                tile,
                Vec2::new(1.0, -13.0),
                palette_color(&palette, 0x13),
                &nation_font,
                &nation_layout,
                nation_line_height,
            );
            spawn_ocean_label(
                parent,
                OceanNationLabel,
                name,
                tile,
                Vec2::new(0.0, -14.0),
                palette_color(&palette, 0),
                &nation_font,
                &nation_layout,
                nation_line_height,
            );
        }
    });
}

#[allow(clippy::too_many_arguments)]
fn spawn_ocean_label<M: Component>(
    parent: &mut ChildSpawnerCommands,
    marker: M,
    text: &str,
    tile: TileId,
    offset: Vec2,
    color: Color,
    font: &TextFont,
    layout: &TextLayout,
    line_height: LineHeight,
) {
    parent.spawn((
        marker,
        OceanLabelAnchor { tile, offset },
        Pickable::IGNORE,
        Visibility::Hidden,
        Text::new(text),
        font.clone(),
        *layout,
        line_height,
        TextColor(color),
        Node {
            position_type: PositionType::Absolute,
            width: Val::Px(300.0),
            ..default()
        },
    ));
}

fn sync_ocean_labels(
    session: Res<GameSession>,
    viewports: Query<Ref<StrategicViewport>>,
    mut labels: Query<(&OceanLabelAnchor, &mut Node, &mut Visibility)>,
) {
    let Ok(viewport) = viewports.single() else {
        return;
    };
    if !viewport.is_changed() {
        return;
    }
    for (anchor, mut node, mut visibility) in &mut labels {
        let position = (viewport.projection == MapProjection::Overview)
            .then(|| {
                ocean_label_position(session.game.map().geometry(), anchor.tile, &viewport.ocean)
            })
            .flatten();
        let Some(position) = position else {
            *visibility = Visibility::Hidden;
            continue;
        };
        *visibility = Visibility::Visible;
        node.left = Val::Px(position.x + anchor.offset.x - 150.0);
        node.top = Val::Px(position.y + anchor.offset.y);
    }
}

fn ocean_label_position(
    geometry: MapGeometry,
    tile: TileId,
    ocean: &OceanViewport,
) -> Option<Vec2> {
    let (row, column) = geometry.row_column(tile);
    let y = (i32::from(row) - ocean.origin.y) * OCEAN_CELL_PIXELS + 8;
    let x = (i32::from(column) - ocean.origin.x).rem_euclid(RETAIL_MAP_COLUMNS) * OCEAN_CELL_PIXELS
        + i32::from(row & 1) * 8;
    ((0..=VIEWPORT_WIDTH as i32).contains(&x) && (0..=VIEWPORT_HEIGHT as i32).contains(&y))
        .then_some(Vec2::new(x as f32, y as f32))
}

fn palette_color(palette: &DibPalette, index: u8) -> Color {
    let [red, green, blue] = palette[index].to_array();
    Color::srgb_u8(red, green, blue)
}

pub(crate) fn ocean_tile_at_cursor(
    state: &GameState,
    cursor: &RelativeCursorPosition,
    ocean: &OceanViewport,
) -> Option<TileId> {
    cursor
        .normalized
        .filter(|_| cursor.cursor_over())
        .and_then(|position| ocean_tile_at_position(state, position, ocean.origin))
}

fn ocean_tile_at_position(state: &GameState, normalized: Vec2, origin: IVec2) -> Option<TileId> {
    let x = ((normalized.x + 0.5) * VIEWPORT_WIDTH as f32).floor() as i32;
    let y = ((normalized.y + 0.5) * VIEWPORT_HEIGHT as f32).floor() as i32;
    if !(0..VIEWPORT_WIDTH as i32).contains(&x) || !(0..VIEWPORT_HEIGHT as i32).contains(&y) {
        return None;
    }
    let row = origin.y + y / OCEAN_CELL_PIXELS;
    if !(0..i32::from(STRATEGIC_MAP_HEIGHT)).contains(&row) {
        return None;
    }
    let adjusted = x + if row & 1 == 0 { 8 } else { 0 };
    let column = origin.x + adjusted / OCEAN_CELL_PIXELS;
    let column = if state.map().geometry().wraps_horizontally() {
        column.rem_euclid(i32::from(STRATEGIC_MAP_WIDTH))
    } else if (0..i32::from(STRATEGIC_MAP_WIDTH)).contains(&column) {
        column
    } else {
        return None;
    };
    state.map().geometry().tile(row as u16, column as u16)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::test_support::{
        beginning_of_game_parts_with, beginning_of_game_with, strategic_map_beginning_context,
    };

    #[test]
    fn alternate_map_visibility_follows_projection() {
        let mut app = App::new();
        app.add_systems(Update, sync_ocean_view_frames);
        let land = app
            .world_mut()
            .spawn((
                LandMapFrame,
                Visibility::Visible,
                StrategicViewport::default(),
            ))
            .id();
        let sea = app
            .world_mut()
            .spawn((OceanMapCanvas { composed: None }, Visibility::Hidden))
            .id();

        app.update();
        assert_eq!(
            app.world().get::<Visibility>(land),
            Some(&Visibility::Visible)
        );
        assert_eq!(
            app.world().get::<Visibility>(sea),
            Some(&Visibility::Hidden)
        );

        app.world_mut()
            .get_mut::<StrategicViewport>(land)
            .unwrap()
            .projection = MapProjection::Overview;
        app.update();
        assert_eq!(
            app.world().get::<Visibility>(land),
            Some(&Visibility::Hidden)
        );
        assert_eq!(
            app.world().get::<Visibility>(sea),
            Some(&Visibility::Visible)
        );
    }

    #[test]
    fn bounded_overview_rejects_the_wrapped_right_cell() {
        let mut parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        let tiles = TileId::all()
            .map(|tile| parts.map[tile])
            .collect::<Vec<_>>();
        parts.map = MapMgr::from_parts(MapTopology::Bounded, tiles, parts.map.provinces.clone());
        let state = GameState::from_parts(parts);

        assert_eq!(
            ocean_tile_at_position(&state, Vec2::new(0.499, -0.49), IVec2::new(76, 0)),
            None
        );
    }

    #[test]
    fn ocean_labels_persist_when_the_viewport_moves() {
        let session = GameSession::new(beginning_of_game_with(strategic_map_beginning_context()));
        let tile = session.game.map().geometry().tile(10, 10).unwrap();
        let mut app = App::new();
        app.insert_resource(session);
        app.add_systems(Update, sync_ocean_labels);
        let viewport = app
            .world_mut()
            .spawn(StrategicViewport {
                projection: MapProjection::Overview,
                ..default()
            })
            .id();
        let label = app
            .world_mut()
            .spawn((
                OceanZoneLabel,
                OceanLabelAnchor {
                    tile,
                    offset: Vec2::ZERO,
                },
                Node::default(),
                Visibility::Hidden,
            ))
            .id();

        app.update();
        let first_left = app.world().get::<Node>(label).unwrap().left;
        app.world_mut()
            .get_mut::<StrategicViewport>(viewport)
            .unwrap()
            .ocean
            .origin
            .x = 4;
        app.update();

        assert!(app.world().get_entity(label).is_ok());
        assert_ne!(app.world().get::<Node>(label).unwrap().left, first_left);
        assert_eq!(
            app.world().get::<Visibility>(label),
            Some(&Visibility::Visible)
        );
    }
}
