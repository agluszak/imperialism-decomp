//! Confirmed `TWorldView::DoKeyEvent` bindings: N/W/C/Z/X/A.

use super::map_interaction::{
    MapAction, StrategicMapSession, StrategicSelection, navy_zone_center_tile,
};
use crate::AppState;
use crate::ui::GameSession;
use crate::ui::window::no_modal;
use bevy::prelude::*;

pub(crate) fn register(app: &mut App) {
    app.add_systems(
        Update,
        map_hotkeys.run_if(in_state(AppState::StrategicMap).and_then(no_modal)),
    );
}

fn map_hotkeys(
    keys: Res<ButtonInput<KeyCode>>,
    mut session: ResMut<GameSession>,
    mut map: ResMut<StrategicMapSession>,
) {
    let nation = session.game.turn().active_nation;
    if keys.just_pressed(KeyCode::KeyN) {
        session.game.clear_nation_army_action_modes(nation);
        if !map.selection.has_target() {
            map.cycle_selection(&mut session.game);
        }
    }
    if keys.just_pressed(KeyCode::KeyW) {
        session.game.clear_nation_civilian_action_modes(nation);
        if !map.selection.has_target() {
            map.cycle_selection(&mut session.game);
        }
    }
    if keys.just_pressed(KeyCode::KeyC) {
        center_current_selection(&mut session, &mut map);
    }
    if keys.just_pressed(KeyCode::KeyX)
        && let Some(tile) = session.game.representative_tile_for_nation(nation)
    {
        map.apply(&mut session.game, MapAction::Center(tile));
    }
    if keys.just_pressed(KeyCode::KeyA) {
        session.game.free_ships_of(nation);
        if let StrategicSelection::Navy { zone, .. } = map.selection {
            map.selection = StrategicSelection::Navy { zone, force: None };
        }
    }
    if keys.just_pressed(KeyCode::KeyZ) {
        map.apply(&mut session.game, MapAction::ToggleZoom);
    }
}

fn center_current_selection(session: &mut GameSession, map: &mut StrategicMapSession) {
    let tile = match map.selection {
        StrategicSelection::Civilian(civilian) => civilian
            .and_then(|id| session.game.civilian_unit(id))
            .and_then(|unit| unit.location().tile()),
        StrategicSelection::Army(army) => {
            army.and_then(|province| session.game.map().provinces[province].city_tile())
        }
        StrategicSelection::Navy { zone, .. } => {
            zone.and_then(|zone| navy_zone_center_tile(&session.game, zone))
        }
        StrategicSelection::None => session
            .game
            .representative_tile_for_nation(session.game.turn().active_nation),
    };
    if let Some(tile) = tile {
        map.apply(&mut session.game, MapAction::Center(tile));
    }
}
