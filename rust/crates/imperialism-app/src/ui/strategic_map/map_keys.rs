//! Confirmed `TWorldView::DoKeyEvent` bindings: N/W/C/Z/X/A.

use super::civilian_orders::StrategicSelection;
use super::map_interaction::{
    ArmySelection, MapInteractionMode, NavySelection, OceanView, cycle_map_interaction_selection,
    has_active_map_interaction_selection, navy_zone_center_tile,
};
use crate::AppState;
use crate::ui::GameSession;
use bevy::prelude::*;
use imperialism_core::*;

pub(crate) fn register(app: &mut App) {
    app.add_systems(Update, map_hotkeys.run_if(in_state(AppState::StrategicMap)));
}

fn map_hotkeys(
    keys: Res<ButtonInput<KeyCode>>,
    mut session: ResMut<GameSession>,
    mut mode: ResMut<MapInteractionMode>,
    mut civilian: Query<&mut StrategicSelection>,
    mut army: ResMut<ArmySelection>,
    mut navy: ResMut<NavySelection>,
    mut ocean: ResMut<OceanView>,
) {
    let Ok(mut civilian) = civilian.single_mut() else {
        return;
    };
    let nation = session.game.turn().active_nation;
    if keys.just_pressed(KeyCode::KeyN) {
        session.game.clear_nation_army_action_modes(nation);
        if !has_active_map_interaction_selection(*mode, civilian.0, army.0, navy.force) {
            cycle_map_interaction_selection(
                &mut session,
                &mut mode,
                &mut civilian,
                &mut army,
                &mut navy,
            );
        }
    }
    if keys.just_pressed(KeyCode::KeyW) {
        session.game.clear_nation_civilian_action_modes(nation);
        if !has_active_map_interaction_selection(*mode, civilian.0, army.0, navy.force) {
            cycle_map_interaction_selection(
                &mut session,
                &mut mode,
                &mut civilian,
                &mut army,
                &mut navy,
            );
        }
    }
    if keys.just_pressed(KeyCode::KeyC) {
        center_current_selection(
            &mut session,
            *mode,
            civilian.0,
            army.0,
            navy.zone,
            &mut ocean,
        );
    }
    if keys.just_pressed(KeyCode::KeyX)
        && let Some(tile) = session.game.representative_tile_for_nation(nation)
    {
        center_on(&mut session, &mut ocean, tile);
    }
    if keys.just_pressed(KeyCode::KeyA) {
        session.game.free_ships_of(nation);
        navy.force = None;
    }
    if keys.just_pressed(KeyCode::KeyZ) {
        toggle_ocean_view(&mut session, &mut ocean);
    }
}

fn toggle_ocean_view(session: &mut GameSession, ocean: &mut OceanView) {
    if ocean.active {
        let geometry = session.game.map().geometry();
        let column = ocean.origin_column + 0x10;
        let row = ocean.origin_row + 0x0e;
        if let Some(tile) = geometry.tile(
            row.max(0) as u16,
            column.rem_euclid(i32::from(STRATEGIC_MAP_WIDTH)) as u16,
        ) {
            session.game.center_map_on(tile);
        }
        ocean.active = false;
    } else {
        let origin = session.game.map_view_origin();
        ocean.center_on(origin, &session.game.map().geometry());
        ocean.active = true;
    }
}

fn center_current_selection(
    session: &mut GameSession,
    mode: MapInteractionMode,
    civilian: Option<CivilianUnitId>,
    army: Option<ProvinceId>,
    navy_zone: Option<OceanZoneId>,
    ocean: &mut OceanView,
) {
    let tile = match mode {
        MapInteractionMode::Civilian => civilian.and_then(|id| {
            session
                .game
                .civilian_units()
                .iter()
                .find(|unit| unit.id() == id)
                .and_then(|unit| unit.location().tile())
        }),
        MapInteractionMode::Army => {
            army.and_then(|province| session.game.map().provinces[province].city_tile())
        }
        MapInteractionMode::Navy => {
            navy_zone.and_then(|zone| navy_zone_center_tile(&session.game, zone))
        }
        MapInteractionMode::None => session
            .game
            .representative_tile_for_nation(session.game.turn().active_nation),
    };
    if let Some(tile) = tile {
        center_on(session, ocean, tile);
    }
}

fn center_on(session: &mut GameSession, ocean: &mut OceanView, tile: TileId) {
    if ocean.active {
        ocean.center_on(tile, &session.game.map().geometry());
    } else {
        session.game.center_map_on(tile);
    }
}
