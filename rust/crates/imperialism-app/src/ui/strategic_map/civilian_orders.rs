use crate::AppState;
use crate::ui::GameSession;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::RelativeCursorPosition;
use imperialism_core::{CivilianUnitId, RailOrderRejection};

use super::{StrategicBaseTerrainCanvas, strategic_base_terrain_tile_at_cursor};

#[derive(Clone, Copy, Default, Resource)]
pub(crate) struct SelectedEngineer(pub(crate) Option<CivilianUnitId>);

pub(crate) fn register(app: &mut App) {
    app.init_resource::<SelectedEngineer>()
        .add_systems(OnExit(AppState::StrategicMap), clear_selected_engineer);
}

fn clear_selected_engineer(mut selected: ResMut<SelectedEngineer>) {
    selected.0 = None;
}

pub(crate) fn on_strategic_map_click(
    click: On<Pointer<Click>>,
    maps: Query<&RelativeCursorPosition, With<StrategicBaseTerrainCanvas>>,
    mut session: ResMut<GameSession>,
    mut selected: ResMut<SelectedEngineer>,
) {
    let Ok(cursor) = maps.get(click.entity) else {
        return;
    };
    let Some(tile) = strategic_base_terrain_tile_at_cursor(&session.0, cursor) else {
        return;
    };
    let nation = session.0.turn().active_nation;
    if let Some(unit) = session.0.selectable_engineer_on_tile(tile, nation) {
        selected.0 = Some(unit);
        return;
    }
    let Some(unit) = selected.0 else {
        return;
    };
    match session.0.order_rail_construction(unit, tile) {
        Ok(()) => selected.0 = None,
        Err(RailOrderRejection::InsufficientFunds | RailOrderRejection::InvalidTarget) => {}
        Err(RailOrderRejection::IneligibleUnit) => selected.0 = None,
    }
}
