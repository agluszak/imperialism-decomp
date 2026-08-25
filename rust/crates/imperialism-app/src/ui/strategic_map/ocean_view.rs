//! Bevy projection for the retail `DOOG` alternate strategic view.

use super::map_interaction::{OceanViewport, StrategicMapSession, StrategicSelection};
use super::map_projection::OceanProjection;
use super::ocean_raster::{OceanRenderAssets, compose_ocean_raster};
use super::{VIEWPORT_HEIGHT, VIEWPORT_WIDTH, viewport_point};
use crate::AppState;
use crate::ui::GameSession;
use crate::ui::RetailUiAssets;
use crate::ui::retail::RetailTree;
use crate::ui::retail_raster::{IndexedRasterExt, indexed_picture};
use bevy::prelude::*;
use bevy::text::LineHeight;
use bevy::ui::RelativeCursorPosition;
use imperialism_core::*;
use imperialism_formats::*;

const LAND_POS: Vec2 = Vec2::new(5.0, 0x1b as f32);
#[derive(Component)]
pub(crate) struct LandMapFrame;

#[derive(Component)]
pub(crate) struct OceanMapCanvas {
    assets: OceanRenderAssets,
    composed: Option<OceanComposeKey>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OceanComposeKey {
    origin: IVec2,
    hovered: Option<TileId>,
    selection: StrategicSelection,
}

#[derive(Component)]
pub(crate) struct OceanZoneLabel {
    tile: TileId,
}

#[derive(Component)]
pub(crate) struct OceanNationLabel {
    nation: NationId,
}

#[derive(Component)]
struct OceanLabelAnchor {
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
    let ocean_assets = OceanRenderAssets::load(|id| {
        assets
            .indexed_picture(PictureId::new(id))
            .unwrap_or_else(|error| panic!("retail ocean picture {id} must load: {error}"))
    });

    let ocean = tree.find(root, fourcc!("DOOG"));
    let palette = *assets.default_dib_palette();
    let image = assets.add_image(
        indexed_picture(VIEWPORT_WIDTH as i32, VIEWPORT_HEIGHT as i32, 0).to_image(&palette),
    );
    commands.entity(ocean).insert((
        OceanMapCanvas {
            assets: ocean_assets,
            composed: None,
        },
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
    map: Res<StrategicMapSession>,
    mut land: Query<&mut Visibility, (With<LandMapFrame>, Without<OceanMapCanvas>)>,
    mut sea: Query<&mut Visibility, (With<OceanMapCanvas>, Without<LandMapFrame>)>,
) {
    let (land_visibility, sea_visibility) = if map.view.is_overview() {
        (Visibility::Hidden, Visibility::Visible)
    } else {
        (Visibility::Visible, Visibility::Hidden)
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
    map: Res<StrategicMapSession>,
    retail: Res<crate::RetailAssetsResource>,
    mut images: ResMut<Assets<Image>>,
    mut canvases: Query<(&mut OceanMapCanvas, &ImageNode, &RelativeCursorPosition)>,
) {
    if !map.view.is_overview() {
        return;
    }
    let ocean = map.view.ocean();
    for (mut canvas, node, cursor) in &mut canvases {
        let hovered = ocean_tile_at_cursor(&session.game, cursor, &ocean);
        let key = OceanComposeKey {
            origin: ocean.origin,
            hovered,
            selection: map.selection,
        };
        if canvas.composed == Some(key) && !session.is_changed() && !map.is_changed() {
            continue;
        }
        let picture = compose_ocean_raster(
            &session.game,
            &ocean,
            map.selection,
            hovered,
            &canvas.assets,
        );
        if let Some(mut existing) = images.get_mut(&node.image) {
            *existing = picture.to_image(retail.assets().default_dib_palette());
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
                OceanZoneLabel { tile },
                &zone.zone().display_name,
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
            spawn_ocean_label(
                parent,
                OceanNationLabel { nation },
                name,
                Vec2::new(1.0, -13.0),
                palette_color(&palette, 0x13),
                &nation_font,
                &nation_layout,
                nation_line_height,
            );
            spawn_ocean_label(
                parent,
                OceanNationLabel { nation },
                name,
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
    offset: Vec2,
    color: Color,
    font: &TextFont,
    layout: &TextLayout,
    line_height: LineHeight,
) {
    parent.spawn((
        marker,
        OceanLabelAnchor { offset },
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
    map: Res<StrategicMapSession>,
    mut zones: Query<
        (
            &OceanZoneLabel,
            &OceanLabelAnchor,
            &mut Node,
            &mut Visibility,
        ),
        Without<OceanNationLabel>,
    >,
    mut nations: Query<
        (
            &OceanNationLabel,
            &OceanLabelAnchor,
            &mut Node,
            &mut Visibility,
        ),
        Without<OceanZoneLabel>,
    >,
) {
    if !map.is_changed() && !session.is_changed() {
        return;
    }
    let ocean = map.view.ocean();
    let projection = OceanProjection::new(session.game.map().geometry(), &ocean);
    for (zone, anchor, mut node, mut visibility) in &mut zones {
        project_ocean_label(
            &projection,
            Some(zone.tile),
            anchor.offset,
            map.view.is_overview(),
            &mut node,
            &mut visibility,
        );
    }
    let nation_tiles = ocean_nation_overlay_tiles(&session.game);
    for (label, anchor, mut node, mut visibility) in &mut nations {
        project_ocean_label(
            &projection,
            nation_tiles[usize::from(label.nation.get())],
            anchor.offset,
            map.view.is_overview(),
            &mut node,
            &mut visibility,
        );
    }
}

fn ocean_nation_overlay_tiles(game: &GameState) -> [Option<TileId>; NationId::COUNT as usize] {
    let mut tiles = [None; NationId::COUNT as usize];
    for slot in 0..NationId::COUNT {
        let nation = NationId::new(slot);
        if game.nations().display_name(nation).is_none() {
            continue;
        }
        // Retail stops the nation loop on the first missing computed anchor.
        let Some(tile) = game.ocean_overlay_anchor_for_nation(nation) else {
            break;
        };
        tiles[usize::from(slot)] = Some(tile);
    }
    tiles
}

fn project_ocean_label(
    projection: &OceanProjection,
    tile: Option<TileId>,
    offset: Vec2,
    overview: bool,
    node: &mut Node,
    visibility: &mut Visibility,
) {
    let position = overview
        .then(|| tile.and_then(|tile| projection.tile_center(tile)))
        .flatten();
    let Some(position) = position else {
        *visibility = Visibility::Hidden;
        return;
    };
    *visibility = Visibility::Visible;
    node.left = Val::Px(position.x + offset.x - 150.0);
    node.top = Val::Px(position.y + offset.y);
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
        .and_then(|position| {
            OceanProjection::new(state.map().geometry(), ocean).tile_at(viewport_point(position))
        })
}

#[cfg(test)]
mod tests {
    use super::super::map_interaction::StrategicView;
    use super::*;
    use crate::ui::test_support::{
        beginning_of_game_parts_with, beginning_of_game_with, strategic_map_beginning_context,
    };

    #[test]
    fn alternate_map_visibility_follows_projection() {
        let mut app = App::new();
        app.insert_resource(StrategicMapSession::default());
        app.add_systems(Update, sync_ocean_view_frames);
        let land = app
            .world_mut()
            .spawn((LandMapFrame, Visibility::Visible))
            .id();
        let sea = app
            .world_mut()
            .spawn((test_ocean_canvas(), Visibility::Hidden))
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

        app.world_mut().resource_mut::<StrategicMapSession>().view = StrategicView::Overview {
            origin: IVec2::ZERO,
        };
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
            OceanProjection::new(
                state.map().geometry(),
                &OceanViewport {
                    origin: IVec2::new(76, 0),
                },
            )
            .tile_at(viewport_point(Vec2::new(0.499, -0.49))),
            None
        );
    }

    #[test]
    fn ocean_labels_persist_when_the_viewport_moves() {
        let session = GameSession::new(beginning_of_game_with(strategic_map_beginning_context()));
        let tile = session.game.map().geometry().tile(10, 10).unwrap();
        let mut app = App::new();
        app.insert_resource(session);
        app.insert_resource(StrategicMapSession {
            selection: StrategicSelection::default(),
            view: StrategicView::Overview {
                origin: IVec2::ZERO,
            },
        });
        app.add_systems(Update, sync_ocean_labels);
        let label = app
            .world_mut()
            .spawn((
                OceanZoneLabel { tile },
                OceanLabelAnchor { offset: Vec2::ZERO },
                Node::default(),
                Visibility::Hidden,
            ))
            .id();

        app.update();
        let first_left = app.world().get::<Node>(label).unwrap().left;
        app.world_mut().resource_mut::<StrategicMapSession>().view = StrategicView::Overview {
            origin: IVec2::new(4, 0),
        };
        app.update();

        assert!(app.world().get_entity(label).is_ok());
        assert_ne!(app.world().get::<Node>(label).unwrap().left, first_left);
        assert_eq!(
            app.world().get::<Visibility>(label),
            Some(&Visibility::Visible)
        );
    }

    #[test]
    fn nation_ocean_label_follows_the_current_overlay_anchor() {
        let nation = NationId::new(0);
        let mut first_parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        let owner = TileOwnerTag::from_nation(nation);
        let owned = TileId::all()
            .filter(|&tile| first_parts.map[tile].owner_nation == Some(owner))
            .collect::<Vec<_>>();
        let first_tile = owned[owned.len() / 2];
        let mut ocean = OceanViewport::default();
        ocean.center_on(first_tile, &first_parts.map.geometry());
        let second_tile = owned
            .iter()
            .copied()
            .find(|&tile| {
                tile != first_tile
                    && OceanProjection::new(first_parts.map.geometry(), &ocean)
                        .tile_center(tile)
                        .is_some()
            })
            .expect("nation 0 owns another tile in the same ocean view");

        keep_only_owned_tile(&mut first_parts.map, owner, first_tile);
        let first = GameSession::new(GameState::from_parts(first_parts));
        assert_eq!(
            first.game.ocean_overlay_anchor_for_nation(nation),
            Some(first_tile)
        );

        let mut second_parts = beginning_of_game_parts_with(strategic_map_beginning_context());
        keep_only_owned_tile(&mut second_parts.map, owner, second_tile);
        let second = GameSession::new(GameState::from_parts(second_parts));
        assert_eq!(
            second.game.ocean_overlay_anchor_for_nation(nation),
            Some(second_tile)
        );

        let mut app = App::new();
        app.insert_resource(first);
        app.insert_resource(StrategicMapSession {
            selection: StrategicSelection::default(),
            view: StrategicView::Overview {
                origin: ocean.origin,
            },
        });
        app.add_systems(Update, sync_ocean_labels);
        let label = app
            .world_mut()
            .spawn((
                OceanNationLabel { nation },
                OceanLabelAnchor { offset: Vec2::ZERO },
                Node::default(),
                Visibility::Hidden,
            ))
            .id();

        app.update();
        let first_left = app.world().get::<Node>(label).unwrap().left;
        assert_eq!(
            app.world().get::<Visibility>(label),
            Some(&Visibility::Visible)
        );

        app.insert_resource(second);
        app.update();
        assert_ne!(app.world().get::<Node>(label).unwrap().left, first_left);
        assert_eq!(
            app.world().get::<Visibility>(label),
            Some(&Visibility::Visible)
        );
    }

    fn test_ocean_canvas() -> OceanMapCanvas {
        OceanMapCanvas {
            assets: OceanRenderAssets::load(|_| IndexedPicture {
                width: 1,
                height: 1,
                pixels: vec![0],
            }),
            composed: None,
        }
    }

    fn keep_only_owned_tile(map: &mut MapMgr, owner: TileOwnerTag, keep: TileId) {
        for tile in TileId::all() {
            if map[tile].owner_nation == Some(owner) && tile != keep {
                map[tile].owner_nation = None;
            }
        }
    }
}
