//! Confirmed `TWorldView::DoKeyEvent` bindings: N/W/C/Z/X/A.

use super::map_interaction::{
    MapInteractionMode, StrategicInteraction, center_active_map, cycle_map_interaction_selection,
    has_active_map_interaction_selection, navy_zone_center_tile, toggle_zoom,
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
    mut interactions: Query<&mut StrategicInteraction>,
) {
    let Ok(mut interaction) = interactions.single_mut() else {
        return;
    };
    let nation = session.game.turn().active_nation;
    if keys.just_pressed(KeyCode::KeyN) {
        session.game.clear_nation_army_action_modes(nation);
        if !has_active_map_interaction_selection(&interaction) {
            cycle_map_interaction_selection(&mut session, &mut interaction);
        }
    }
    if keys.just_pressed(KeyCode::KeyW) {
        session.game.clear_nation_civilian_action_modes(nation);
        if !has_active_map_interaction_selection(&interaction) {
            cycle_map_interaction_selection(&mut session, &mut interaction);
        }
    }
    if keys.just_pressed(KeyCode::KeyC) {
        center_current_selection(
            &mut session,
            interaction.mode,
            interaction.civilian,
            interaction.army,
            interaction.navy.zone,
            &mut interaction,
        );
    }
    if keys.just_pressed(KeyCode::KeyX)
        && let Some(tile) = session.game.representative_tile_for_nation(nation)
    {
        center_active_map(&mut session, &mut interaction, tile);
    }
    if keys.just_pressed(KeyCode::KeyA) {
        session.game.free_ships_of(nation);
        interaction.navy.force = None;
    }
    if keys.just_pressed(KeyCode::KeyZ) {
        toggle_zoom(&mut session, &mut interaction);
    }
}

fn center_current_selection(
    session: &mut GameSession,
    mode: MapInteractionMode,
    civilian: Option<CivilianUnitId>,
    army: Option<ProvinceId>,
    navy_zone: Option<OceanZoneId>,
    interaction: &mut StrategicInteraction,
) {
    let tile = match mode {
        MapInteractionMode::Civilian => civilian
            .and_then(|id| session.game.civilian_unit(id))
            .and_then(|unit| unit.location().tile()),
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
        center_active_map(session, interaction, tile);
    }
}
