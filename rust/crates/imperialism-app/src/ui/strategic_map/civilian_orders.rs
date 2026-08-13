use crate::AppState;
use crate::ui::GameSession;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::RelativeCursorPosition;
use imperialism_core::{CivilianUnitId, CivilianUnitKind, RailOrderRejection};

use super::{StrategicBaseTerrainCanvas, strategic_base_terrain_tile_at_cursor};

#[derive(Clone, Copy, Default, Resource)]
pub(crate) struct SelectedCivilian(pub(crate) Option<CivilianUnitId>);

pub(crate) fn register(app: &mut App) {
    app.init_resource::<SelectedCivilian>()
        .add_observer(on_strategic_map_click.run_if(in_state(AppState::StrategicMap)))
        .add_systems(OnExit(AppState::StrategicMap), clear_selected_civilian);
}

fn clear_selected_civilian(mut selected: ResMut<SelectedCivilian>) {
    selected.0 = None;
}

fn on_strategic_map_click(
    click: On<Pointer<Click>>,
    maps: Query<&RelativeCursorPosition, With<StrategicBaseTerrainCanvas>>,
    mut session: ResMut<GameSession>,
    mut selected: ResMut<SelectedCivilian>,
) {
    let Ok(cursor) = maps.get(click.entity) else {
        return;
    };
    let Some(tile) = strategic_base_terrain_tile_at_cursor(&session.0, cursor) else {
        return;
    };
    let nation = session.0.turn().active_nation;
    if let Some(unit) = session.0.selectable_civilian_on_tile(tile, nation) {
        selected.0 = Some(unit);
        return;
    }
    let Some(unit) = selected.0 else {
        return;
    };
    let Some(kind) = session
        .0
        .civilian_units()
        .iter()
        .find(|candidate| candidate.id() == unit)
        .map(|candidate| candidate.unit_type())
    else {
        selected.0 = None;
        return;
    };
    if kind != CivilianUnitKind::Engineer {
        return;
    }
    match session.0.order_rail_construction(unit, tile) {
        Ok(()) => selected.0 = None,
        Err(RailOrderRejection::InsufficientFunds | RailOrderRejection::InvalidTarget) => {}
        Err(RailOrderRejection::IneligibleUnit) => selected.0 = None,
    }
}
