//! `TWorldView::HandleMapClickByInteractionMode` (0x005964b0).

use super::map_interaction::{
    MapInteractionMode, StrategicInteraction, cycle_map_interaction_selection,
    has_active_map_interaction_selection, navy_zone_center_tile, set_map_interaction_mode,
};
use super::map_modals::{spawn_army_report, spawn_fleet_report, spawn_garrison, spawn_navy_roster};
use super::ocean_view::{OceanMapCanvas, ocean_tile_at_cursor};
use super::{StrategicBaseTerrainCanvas, strategic_base_terrain_tile_at_cursor};
use crate::AppState;
use crate::ui::GameSession;
use crate::ui::cursor::{RequestedCursor, request_arrow_cursor, request_turn_event_cursor};
use bevy::picking::events::{Click, Pointer};
use bevy::picking::pointer::PointerButton;
use bevy::prelude::*;
use bevy::ui::RelativeCursorPosition;
use imperialism_core::*;

pub(crate) fn register(app: &mut App) {
    app.add_systems(
        Update,
        sync_strategic_map_cursor.run_if(in_state(AppState::StrategicMap)),
    );
}

#[allow(clippy::type_complexity)]
pub(crate) fn on_strategic_map_click(
    click: On<Pointer<Click>>,
    mut commands: Commands,
    mut land: Query<
        (&RelativeCursorPosition, &mut StrategicInteraction),
        (With<StrategicBaseTerrainCanvas>, Without<OceanMapCanvas>),
    >,
    ocean_maps: Query<&RelativeCursorPosition, With<OceanMapCanvas>>,
    mut session: ResMut<GameSession>,
) {
    if click.event.button != PointerButton::Primary {
        return;
    }
    let tile = if let Ok((cursor, _)) = land.get(click.entity) {
        strategic_base_terrain_tile_at_cursor(&session.game, cursor)
    } else if let Ok(cursor) = ocean_maps.get(click.entity) {
        let Ok((_, interaction)) = land.single() else {
            return;
        };
        ocean_tile_at_cursor(&session.game, cursor, &interaction.ocean)
    } else {
        return;
    };
    let Some(tile) = tile else {
        return;
    };
    let Ok((_, mut interaction)) = land.single_mut() else {
        return;
    };
    handle_map_click_by_interaction_mode(&mut commands, &mut session, &mut interaction, tile, 0);
}

fn handle_map_click_by_interaction_mode(
    commands: &mut Commands,
    session: &mut GameSession,
    interaction: &mut StrategicInteraction,
    tile: TileId,
    input_flags: i32,
) {
    let nation = session.game.turn().active_nation;
    let has_selection = has_active_map_interaction_selection(interaction);
    match interaction.mode {
        MapInteractionMode::Civilian => {
            if apply_army_unselected(
                session,
                &mut interaction.army,
                nation,
                tile,
                input_flags,
                has_selection,
            ) || apply_navy_selection(commands, session, interaction, tile, nation)
            {
                return;
            }
            if apply_civilian_tile_order(session, &mut interaction.civilian, tile, nation) {
                cycle_map_interaction_selection(session, interaction);
            }
        }
        MapInteractionMode::Army => {
            if apply_army_unselected(
                session,
                &mut interaction.army,
                nation,
                tile,
                input_flags,
                has_selection,
            ) || apply_civilian_selection_or_report(
                commands,
                session,
                interaction,
                tile,
                nation,
                input_flags,
            ) || apply_navy_selection(commands, session, interaction, tile, nation)
            {
                return;
            }
            if let Some(pending) = interaction.army
                && apply_army_selected(
                    commands,
                    session,
                    &mut interaction.army,
                    nation,
                    pending,
                    tile,
                )
            {
                cycle_map_interaction_selection(session, interaction);
            }
        }
        MapInteractionMode::Navy => {
            if apply_army_unselected(
                session,
                &mut interaction.army,
                nation,
                tile,
                input_flags,
                has_selection,
            ) || apply_civilian_selection_or_report(
                commands,
                session,
                interaction,
                tile,
                nation,
                input_flags,
            ) {
                return;
            }
            if apply_navy_tile_click(commands, session, interaction, tile, nation) {
                cycle_map_interaction_selection(session, interaction);
            }
        }
        MapInteractionMode::None => {
            if apply_army_unselected(
                session,
                &mut interaction.army,
                nation,
                tile,
                input_flags,
                has_selection,
            ) || apply_civilian_selection_or_report(
                commands,
                session,
                interaction,
                tile,
                nation,
                input_flags,
            ) {
                return;
            }
            apply_navy_selection(commands, session, interaction, tile, nation);
        }
    }
}

fn apply_army_unselected(
    session: &mut GameSession,
    army: &mut Option<ProvinceId>,
    nation: NationId,
    tile: TileId,
    input_flags: i32,
    has_selection: bool,
) -> bool {
    match session
        .game
        .handle_army_unselected_map_click(nation, tile, input_flags, has_selection)
    {
        ArmyMapClickOutcome::Ignored => false,
        ArmyMapClickOutcome::SelectedProvince(province) => {
            *army = Some(province);
            true
        }
        ArmyMapClickOutcome::Marched | ArmyMapClickOutcome::IssuedOrders => true,
        ArmyMapClickOutcome::SpyReport(_)
        | ArmyMapClickOutcome::Garrison(_)
        | ArmyMapClickOutcome::OrderRejected(_) => true,
    }
}

fn apply_army_selected(
    commands: &mut Commands,
    session: &mut GameSession,
    army: &mut Option<ProvinceId>,
    nation: NationId,
    pending: ProvinceId,
    tile: TileId,
) -> bool {
    match session
        .game
        .handle_army_selected_map_click(nation, pending, tile)
    {
        ArmyMapClickOutcome::Ignored | ArmyMapClickOutcome::OrderRejected(_) => false,
        ArmyMapClickOutcome::SelectedProvince(province) => {
            *army = Some(province);
            true
        }
        ArmyMapClickOutcome::IssuedOrders | ArmyMapClickOutcome::Marched => true,
        ArmyMapClickOutcome::Garrison(province) => {
            spawn_garrison(commands, province);
            true
        }
        ArmyMapClickOutcome::SpyReport(province) => {
            spawn_army_report(commands, province);
            true
        }
    }
}

fn apply_civilian_selection_or_report(
    commands: &mut Commands,
    session: &mut GameSession,
    interaction: &mut StrategicInteraction,
    tile: TileId,
    nation: NationId,
    input_flags: i32,
) -> bool {
    let Some((id, unit)) = session.game.civilian_on_tile_for_nation(tile, nation) else {
        return false;
    };
    let idle = matches!(
        unit.order(),
        CivilianWorkOrder::Idle | CivilianWorkOrder::Sleep
    );
    let city = session.game.map()[tile]
        .flags
        .contains(TileFlags::CITY_MARKER);
    if idle {
        if input_flags == 2 || !city {
            set_map_interaction_mode(interaction, MapInteractionMode::Civilian);
            interaction.civilian = Some(id);
            return true;
        }
        return false;
    }
    let Some(province) = session.game.map()[tile].province else {
        return true;
    };
    spawn_army_report(commands, province);
    true
}

fn apply_civilian_tile_order(
    session: &mut GameSession,
    civilian: &mut Option<CivilianUnitId>,
    tile: TileId,
    nation: NationId,
) -> bool {
    if let Some(unit) = session.game.selectable_civilian_on_tile(tile, nation) {
        *civilian = Some(unit);
        return false;
    }
    let Some(unit) = *civilian else {
        return false;
    };
    let Some(kind) = session
        .game
        .civilian_units()
        .find(|(candidate, _)| *candidate == unit)
        .map(|(_, candidate)| candidate.unit_type())
    else {
        *civilian = None;
        return false;
    };
    if kind != CivilianUnitKind::Engineer {
        return false;
    }
    match session.game.order_rail_construction(unit, tile) {
        Ok(()) => {
            *civilian = None;
            true
        }
        Err(RailOrderRejection::InsufficientFunds | RailOrderRejection::InvalidTarget) => false,
        Err(RailOrderRejection::IneligibleUnit) => {
            *civilian = None;
            false
        }
    }
}

fn apply_navy_selection(
    commands: &mut Commands,
    session: &mut GameSession,
    interaction: &mut StrategicInteraction,
    tile: TileId,
    nation: NationId,
) -> bool {
    match session
        .game
        .navy_selection_click(tile, interaction.navy.zone, nation)
    {
        NavySelectionClick::Ignored => false,
        NavySelectionClick::SelectZone { zone, force } => {
            set_map_interaction_mode(interaction, MapInteractionMode::Navy);
            interaction.navy.zone = Some(zone);
            interaction.navy.force = force;
            if let Some(center) = navy_zone_center_tile(&session.game, zone) {
                session.game.center_map_on(center);
            }
            true
        }
        NavySelectionClick::Intelligence { .. } => {
            spawn_fleet_report(commands, false);
            true
        }
        NavySelectionClick::InspectForce(_) => {
            spawn_fleet_report(commands, true);
            true
        }
        NavySelectionClick::Roster => {
            spawn_navy_roster(commands);
            true
        }
    }
}

fn apply_navy_tile_click(
    commands: &mut Commands,
    session: &mut GameSession,
    interaction: &mut StrategicInteraction,
    tile: TileId,
    nation: NationId,
) -> bool {
    match session.game.navy_do_tile_click(
        tile,
        interaction.navy.force,
        interaction.navy.zone,
        nation,
    ) {
        NavyTileClick::Ignored => false,
        NavyTileClick::Selection(selection) => {
            match selection {
                NavySelectionClick::SelectZone { zone, force } => {
                    set_map_interaction_mode(interaction, MapInteractionMode::Navy);
                    interaction.navy.zone = Some(zone);
                    interaction.navy.force = force;
                }
                NavySelectionClick::Intelligence { .. } => spawn_fleet_report(commands, false),
                NavySelectionClick::InspectForce(_) => spawn_fleet_report(commands, true),
                NavySelectionClick::Roster => spawn_navy_roster(commands),
                NavySelectionClick::Ignored => {}
            }
            false
        }
        NavyTileClick::Submitted => true,
        NavyTileClick::Roster => {
            spawn_navy_roster(commands);
            true
        }
    }
}

fn sync_strategic_map_cursor(
    session: Res<GameSession>,
    interactions: Query<Ref<StrategicInteraction>>,
    land: Query<&RelativeCursorPosition, With<StrategicBaseTerrainCanvas>>,
    ocean: Query<&RelativeCursorPosition, With<OceanMapCanvas>>,
    mut requested: ResMut<RequestedCursor>,
) {
    let Ok(interaction) = interactions.single() else {
        return;
    };
    let tile = if interaction.ocean.active {
        ocean
            .iter()
            .find_map(|cursor| ocean_tile_at_cursor(&session.game, cursor, &interaction.ocean))
    } else {
        land.iter()
            .find_map(|cursor| strategic_base_terrain_tile_at_cursor(&session.game, cursor))
    };
    let Some(tile) = tile else {
        request_arrow_cursor(&mut requested);
        return;
    };
    let has_selection = has_active_map_interaction_selection(&interaction);
    let nation = session.game.turn().active_nation;
    let token = match interaction.mode {
        MapInteractionMode::Civilian => {
            let army_token = session
                .game
                .army_map_cursor_state(nation, None, tile, 0, has_selection)
                .unselected_cursor_token();
            if army_token != 0 {
                army_token
            } else {
                let navy_token = session
                    .game
                    .navy_action_cursor_token(tile, interaction.navy.zone);
                if navy_token != 0 { navy_token } else { 0 }
            }
        }
        MapInteractionMode::Army => {
            let army_token = session
                .game
                .army_map_cursor_state(nation, None, tile, 0, has_selection)
                .unselected_cursor_token();
            if army_token != 0 {
                army_token
            } else if let Some(pending) = interaction.army {
                session
                    .game
                    .army_map_cursor_state(nation, Some(pending), tile, 0, has_selection)
                    .selected_cursor_token()
            } else {
                session
                    .game
                    .navy_action_cursor_token(tile, interaction.navy.zone)
            }
        }
        MapInteractionMode::Navy => {
            let army_token = session
                .game
                .army_map_cursor_state(nation, None, tile, 0, has_selection)
                .unselected_cursor_token();
            if army_token != 0 {
                army_token
            } else {
                session.game.navy_selection_cursor_token(
                    tile,
                    interaction.navy.force,
                    interaction.navy.zone,
                )
            }
        }
        MapInteractionMode::None => session
            .game
            .army_map_cursor_state(nation, None, tile, 0, has_selection)
            .unselected_cursor_token(),
    };
    if token == 0 || token == 0x3e7 {
        request_arrow_cursor(&mut requested);
    } else {
        request_turn_event_cursor(&mut requested, token);
    }
}
