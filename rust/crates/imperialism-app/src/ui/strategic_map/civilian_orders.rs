use crate::AppState;
use crate::ui::GameSession;
use bevy::picking::events::{Click, Pointer};
use bevy::prelude::*;
use bevy::ui::RelativeCursorPosition;
use imperialism_core::{CivilianUnitId, RailOrderRejection};

use super::{StrategicBaseTerrainCanvas, strategic_base_terrain_tile_at_cursor};

#[derive(Component, Default)]
pub(crate) struct StrategicSelection(pub(crate) Option<CivilianUnitId>);

pub(crate) fn register(app: &mut App) {
    app.add_observer(on_strategic_map_click.run_if(in_state(AppState::StrategicMap)));
}

fn on_strategic_map_click(
    click: On<Pointer<Click>>,
    mut maps: Query<
        (&RelativeCursorPosition, &mut StrategicSelection),
        With<StrategicBaseTerrainCanvas>,
    >,
    mut session: ResMut<GameSession>,
) {
    let Ok((cursor, mut selected)) = maps.get_mut(click.entity) else {
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
