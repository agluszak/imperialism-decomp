//! Confirmed `TWorldView::DoKeyEvent` bindings: N/W/C/Z/X/A.

use super::map_interaction::{
    MapInteractionMode, MapTransition, StrategicInteraction, StrategicViewport,
    apply_map_transition, cycle_map_interaction_selection, has_active_map_interaction_selection,
    navy_zone_center_tile,
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
    mut maps: Query<(&mut StrategicInteraction, &mut StrategicViewport)>,
) {
    let Ok((mut interaction, mut viewport)) = maps.single_mut() else {
        return;
    };
    let nation = session.game.turn().active_nation;
    if keys.just_pressed(KeyCode::KeyN) {
        session.game.clear_nation_army_action_modes(nation);
        if !has_active_map_interaction_selection(&interaction) {
            cycle_map_interaction_selection(&mut session, &mut interaction, &mut viewport);
        }
    }
    if keys.just_pressed(KeyCode::KeyW) {
        session.game.clear_nation_civilian_action_modes(nation);
        if !has_active_map_interaction_selection(&interaction) {
            cycle_map_interaction_selection(&mut session, &mut interaction, &mut viewport);
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
            &mut viewport,
        );
    }
    if keys.just_pressed(KeyCode::KeyX)
        && let Some(tile) = session.game.representative_tile_for_nation(nation)
    {
        apply_map_transition(
            &mut session,
            &mut interaction,
            &mut viewport,
            MapTransition::Center(tile),
        );
    }
    if keys.just_pressed(KeyCode::KeyA) {
        session.game.free_ships_of(nation);
        interaction.navy.force = None;
    }
    if keys.just_pressed(KeyCode::KeyZ) {
        apply_map_transition(
            &mut session,
            &mut interaction,
            &mut viewport,
            MapTransition::ToggleZoom,
        );
    }
}

fn center_current_selection(
    session: &mut GameSession,
    mode: MapInteractionMode,
    civilian: Option<CivilianUnitId>,
    army: Option<ProvinceId>,
    navy_zone: Option<OceanZoneId>,
    interaction: &mut StrategicInteraction,
    viewport: &mut StrategicViewport,
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
        apply_map_transition(session, interaction, viewport, MapTransition::Center(tile));
    }
}
