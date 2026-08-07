use crate::GameSession;
use crate::session::GameLoopSet;
use crate::strategic_map::{
    DisplayCamera, HoveredTile, LogicalCanvas, PresentedLayout, SelectionMarker, TileRef,
};
use bevy::prelude::*;
use bevy::window::PrimaryWindow;

type SelectionMarkerFilter = (With<SelectionMarker>, Without<LogicalCanvas>);
type SelectionMarkerQuery<'w, 's> = Single<
    'w,
    's,
    (
        &'static mut Transform,
        &'static mut Visibility,
        &'static mut TileRef,
    ),
    SelectionMarkerFilter,
>;

pub struct GameInputPlugin;

impl Plugin for GameInputPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            Update,
            update_hovered_tile.in_set(GameLoopSet::CollectInput),
        );
    }
}

fn update_hovered_tile(
    session: Res<GameSession>,
    layout: Res<PresentedLayout>,
    mut hovered: ResMut<HoveredTile>,
    mut window: Single<&mut Window, With<PrimaryWindow>>,
    display_camera: Single<(&Camera, &GlobalTransform), With<DisplayCamera>>,
    canvas: Single<&Transform, (With<LogicalCanvas>, Without<SelectionMarker>)>,
    selection: SelectionMarkerQuery,
) {
    let next = window.cursor_position().and_then(|cursor| {
        display_camera
            .0
            .viewport_to_world_2d(display_camera.1, cursor)
            .ok()
            .and_then(|world| layout.0.hit_test(world / canvas.scale.x))
    });
    if hovered.0 == next {
        return;
    }
    hovered.0 = next;
    let (mut transform, mut visibility, mut tile_ref) = selection.into_inner();
    if let Some(tile) = next {
        let center = layout
            .0
            .tile_center(tile)
            .expect("hit-tested tile is valid");
        transform.translation.x = center.x;
        transform.translation.y = center.y;
        *visibility = Visibility::Visible;
        tile_ref.0 = tile;
        let state = &session.simulation().state().world.tiles[usize::from(tile.get())];
        window.title = format!(
            "Imperialism snapshot — tile {} terrain {} owner {} region {}",
            tile.get(),
            state.terrain_kind,
            state.owner_nation,
            state.city_or_province_index
        );
    } else {
        *visibility = Visibility::Hidden;
        window.title = "Imperialism strategic-map snapshot".to_owned();
    }
}
