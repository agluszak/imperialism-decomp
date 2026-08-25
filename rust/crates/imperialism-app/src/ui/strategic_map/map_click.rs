//! `TWorldView::HandleMapClickByInteractionMode` (0x005964b0).

use super::map_interaction::{
    MapInteractionMode, MapProjection, MapTransition, StrategicInteraction, StrategicViewport,
    activate_navy_selection, apply_map_transition, cycle_map_interaction_selection,
    has_active_map_interaction_selection,
};
use super::map_modals::{
    spawn_army_report, spawn_civilian_report, spawn_developer_purchase,
    spawn_engineer_construction, spawn_fleet_report, spawn_garrison, spawn_navy_roster,
};
use super::ocean_view::{OceanMapCanvas, ocean_tile_at_cursor};
use super::{StrategicBaseTerrainCanvas, strategic_base_terrain_tile_at_cursor};
use crate::AppState;
use crate::media::RetailAudioAssets;
use crate::ui::GameSession;
use crate::ui::cursor::{RequestedCursor, request_arrow_cursor, request_turn_event_cursor};
use bevy::picking::events::{Click, Pointer};
use bevy::picking::pointer::PointerButton;
use bevy::prelude::*;
use bevy::ui::RelativeCursorPosition;
use imperialism_core::*;
use imperialism_formats::SoundId;

const CIVILIAN_SELECTED_SOUND: SoundId = SoundId::new(0x2338);

const fn civilian_cursor_token(action: CivilianTileAction) -> u16 {
    match action {
        CivilianTileAction::None | CivilianTileAction::SelectUnit => 0,
        CivilianTileAction::Blocked => 1008,
        CivilianTileAction::MoveUnit => 1004,
        CivilianTileAction::EngineerSameTile => 1003,
        CivilianTileAction::EngineerDirection14 => 1002,
        CivilianTileAction::EngineerDirection03 => 1018,
        CivilianTileAction::EngineerDirection25 => 1019,
        CivilianTileAction::Prospect => 1001,
        CivilianTileAction::DevelopResource => 1003,
        CivilianTileAction::ShowOrderReport => 1011,
        CivilianTileAction::PurchaseLand => 1025,
    }
}

const fn army_unselected_cursor_token(state: ArmyMapCursorState) -> u16 {
    match state {
        ArmyMapCursorState::SelectProvince => 1000,
        ArmyMapCursorState::MarchOverlay | ArmyMapCursorState::SameProvinceCity => 1011,
        ArmyMapCursorState::SpyReport => 1010,
        _ => 0,
    }
}

const fn army_selected_cursor_token(state: ArmyMapCursorState) -> u16 {
    match state {
        ArmyMapCursorState::None => 0,
        ArmyMapCursorState::EmptyOrBlocked => 1008,
        ArmyMapCursorState::SelectProvince => 1000,
        ArmyMapCursorState::FriendlyAdjacent => 1005,
        ArmyMapCursorState::FriendlyNonAdjacent => 1006,
        ArmyMapCursorState::Hostile => 1007,
        ArmyMapCursorState::MarchOverlay | ArmyMapCursorState::SameProvinceCity => 1011,
        ArmyMapCursorState::SpyReport => 1010,
    }
}

fn navy_cursor_token(action_code: i32) -> u16 {
    const TOKENS: [u16; 17] = [
        0, 0x3f0, 0x3f2, 0x3f2, 0x3f2, 0x3f2, 0x3f2, 0x3f2, 0x3f2, 0x3f1, 0x3f3, 0x3f3, 0x3f6,
        0x3f8, 0x3f4, 0x3f5, 0x3f7,
    ];
    TOKENS
        .get(usize::try_from(action_code).unwrap_or(0))
        .copied()
        .unwrap_or(0)
}

fn navy_action_cursor_token(
    state: &GameState,
    tile: TileId,
    selected_zone: Option<OceanZoneId>,
) -> u16 {
    navy_cursor_token(state.navy_map_action_code(tile, selected_zone))
}

fn navy_selection_cursor_token(
    state: &GameState,
    tile: TileId,
    force: Option<TaskForceId>,
    selected_zone: Option<OceanZoneId>,
) -> u16 {
    let action = state.navy_map_action_code(tile, selected_zone);
    if action != 0 {
        return navy_cursor_token(action);
    }
    let Some(force) = force else {
        return navy_cursor_token(0);
    };
    navy_cursor_token(state.navy_command_for_tile(force, tile))
}

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
        (
            &RelativeCursorPosition,
            &mut StrategicInteraction,
            &mut StrategicViewport,
        ),
        (With<StrategicBaseTerrainCanvas>, Without<OceanMapCanvas>),
    >,
    ocean_maps: Query<&RelativeCursorPosition, With<OceanMapCanvas>>,
    mut session: ResMut<GameSession>,
    mut audio: RetailAudioAssets,
) {
    if click.event.button != PointerButton::Primary {
        return;
    }
    let tile = if let Ok((cursor, _, _)) = land.get(click.entity) {
        strategic_base_terrain_tile_at_cursor(&session.game, session.map_view_origin, cursor)
    } else if let Ok(cursor) = ocean_maps.get(click.entity) {
        let Ok((_, _, viewport)) = land.single() else {
            return;
        };
        ocean_tile_at_cursor(&session.game, cursor, &viewport.ocean)
    } else {
        return;
    };
    let Some(tile) = tile else {
        return;
    };
    let Ok((_, mut interaction, mut viewport)) = land.single_mut() else {
        return;
    };
    handle_map_click_by_interaction_mode(
        &mut commands,
        &mut session,
        &mut interaction,
        &mut viewport,
        &mut audio,
        tile,
        0,
    );
}

fn handle_map_click_by_interaction_mode(
    commands: &mut Commands,
    session: &mut GameSession,
    interaction: &mut StrategicInteraction,
    viewport: &mut StrategicViewport,
    audio: &mut RetailAudioAssets,
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
            ) || apply_navy_selection(commands, session, interaction, viewport, tile, nation)
            {
                return;
            }
            if apply_civilian_tile_order(
                commands,
                session,
                &mut interaction.civilian,
                audio,
                tile,
                nation,
            ) {
                cycle_map_interaction_selection(session, interaction, viewport);
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
                viewport,
                audio,
                tile,
                nation,
                input_flags,
            ) || apply_navy_selection(commands, session, interaction, viewport, tile, nation)
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
                cycle_map_interaction_selection(session, interaction, viewport);
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
                viewport,
                audio,
                tile,
                nation,
                input_flags,
            ) {
                return;
            }
            if apply_navy_tile_click(commands, session, interaction, viewport, tile, nation) {
                cycle_map_interaction_selection(session, interaction, viewport);
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
                viewport,
                audio,
                tile,
                nation,
                input_flags,
            ) {
                return;
            }
            apply_navy_selection(commands, session, interaction, viewport, tile, nation);
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
    viewport: &mut StrategicViewport,
    audio: &mut RetailAudioAssets,
    tile: TileId,
    nation: NationId,
    input_flags: i32,
) -> bool {
    let Some((id, unit)) = session.game.civilian_on_tile_for_nation(tile, nation) else {
        return false;
    };
    let idle = matches!(
        unit.order(),
        CivilianWorkOrder::Idle | CivilianWorkOrder::Sleep | CivilianWorkOrder::Later
    );
    let city = session.game.map()[tile]
        .flags
        .contains(TileFlags::CITY_MARKER);
    if idle {
        if input_flags == 2 || !city {
            apply_map_transition(
                session,
                interaction,
                viewport,
                MapTransition::SetMode(MapInteractionMode::Civilian),
            );
            interaction.civilian = Some(id);
            session.game.activate_civilian_selection(id);
            audio.play(commands, CIVILIAN_SELECTED_SOUND);
            return true;
        }
        return false;
    }
    spawn_civilian_report(commands, id);
    true
}

fn apply_civilian_tile_order(
    commands: &mut Commands,
    session: &mut GameSession,
    civilian: &mut Option<CivilianUnitId>,
    audio: &mut RetailAudioAssets,
    tile: TileId,
    nation: NationId,
) -> bool {
    if let Some(unit) = session.game.selectable_civilian_on_tile(tile, nation)
        && Some(unit) != *civilian
    {
        *civilian = Some(unit);
        session.game.activate_civilian_selection(unit);
        audio.play(commands, CIVILIAN_SELECTED_SOUND);
        return false;
    }
    let Some(unit) = *civilian else {
        return false;
    };
    if session.game.civilian_unit(unit).is_none() {
        *civilian = None;
        return false;
    }
    let action = session.game.civilian_tile_action(unit, tile);
    match action {
        CivilianTileAction::ShowOrderReport => {
            let Some((clicked, _)) = session.game.civilian_on_tile_for_nation(tile, nation) else {
                return false;
            };
            spawn_civilian_report(commands, clicked);
            return false;
        }
        CivilianTileAction::EngineerSameTile => {
            spawn_engineer_construction(commands, unit);
            return false;
        }
        CivilianTileAction::PurchaseLand => {
            spawn_developer_purchase(commands, unit, tile);
            return false;
        }
        _ => {}
    }
    let kind = session
        .game
        .civilian_unit(unit)
        .map(|unit| unit.unit_type());
    match session.game.issue_civilian_tile_order(unit, tile) {
        Ok(_) => {
            if let Some(sound) = civilian_order_sound(action, kind) {
                audio.play(commands, sound);
            }
            *civilian = None;
            true
        }
        Err(
            CivilianOrderRejection::Blocked
            | CivilianOrderRejection::InsufficientFunds
            | CivilianOrderRejection::ConstructionRequiresChoice
            | CivilianOrderRejection::PurchaseLandRequiresConfirmation,
        ) => false,
    }
}

const fn civilian_order_sound(
    action: CivilianTileAction,
    kind: Option<CivilianUnitKind>,
) -> Option<SoundId> {
    match action {
        CivilianTileAction::MoveUnit => Some(SoundId::new(0x2328)),
        CivilianTileAction::EngineerDirection14
        | CivilianTileAction::EngineerDirection03
        | CivilianTileAction::EngineerDirection25 => Some(SoundId::new(0x2329)),
        CivilianTileAction::Prospect => Some(SoundId::new(0x232e)),
        CivilianTileAction::DevelopResource => match kind {
            Some(CivilianUnitKind::Miner) => Some(SoundId::new(0x232d)),
            Some(CivilianUnitKind::Farmer) => Some(SoundId::new(0x2332)),
            Some(CivilianUnitKind::Forester) => Some(SoundId::new(0x2331)),
            Some(CivilianUnitKind::Rancher) => Some(SoundId::new(0x2333)),
            Some(CivilianUnitKind::Developer) => Some(SoundId::new(0x2335)),
            Some(CivilianUnitKind::Driller) => Some(SoundId::new(0x2339)),
            _ => None,
        },
        _ => None,
    }
}

fn apply_navy_selection(
    commands: &mut Commands,
    session: &mut GameSession,
    interaction: &mut StrategicInteraction,
    viewport: &mut StrategicViewport,
    tile: TileId,
    nation: NationId,
) -> bool {
    match session
        .game
        .navy_selection_click(tile, interaction.navy.zone, nation)
    {
        NavySelectionClick::Ignored => false,
        NavySelectionClick::SelectZone { zone, force } => {
            activate_navy_selection(session, interaction, viewport, zone, force);
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
            if let Some(force) = interaction.navy.force {
                spawn_navy_roster(commands, force);
            }
            true
        }
    }
}

fn apply_navy_tile_click(
    commands: &mut Commands,
    session: &mut GameSession,
    interaction: &mut StrategicInteraction,
    viewport: &mut StrategicViewport,
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
                    activate_navy_selection(session, interaction, viewport, zone, force);
                }
                NavySelectionClick::Intelligence { .. } => spawn_fleet_report(commands, false),
                NavySelectionClick::InspectForce(_) => spawn_fleet_report(commands, true),
                NavySelectionClick::Roster => {
                    if let Some(force) = interaction.navy.force {
                        spawn_navy_roster(commands, force);
                    }
                }
                NavySelectionClick::Ignored => {}
            }
            false
        }
        NavyTileClick::Submitted => true,
        NavyTileClick::Roster => {
            if let Some(force) = interaction.navy.force {
                spawn_navy_roster(commands, force);
            }
            true
        }
    }
}

fn sync_strategic_map_cursor(
    session: Res<GameSession>,
    maps: Query<(Ref<StrategicInteraction>, &StrategicViewport)>,
    land: Query<&RelativeCursorPosition, With<StrategicBaseTerrainCanvas>>,
    ocean: Query<&RelativeCursorPosition, With<OceanMapCanvas>>,
    mut requested: ResMut<RequestedCursor>,
) {
    let Ok((interaction, viewport)) = maps.single() else {
        return;
    };
    let tile = if viewport.projection == MapProjection::Overview {
        ocean
            .iter()
            .find_map(|cursor| ocean_tile_at_cursor(&session.game, cursor, &viewport.ocean))
    } else {
        land.iter().find_map(|cursor| {
            strategic_base_terrain_tile_at_cursor(&session.game, session.map_view_origin, cursor)
        })
    };
    let Some(tile) = tile else {
        request_arrow_cursor(&mut requested);
        return;
    };
    let has_selection = has_active_map_interaction_selection(&interaction);
    let nation = session.game.turn().active_nation;
    let token =
        match interaction.mode {
            MapInteractionMode::Civilian => {
                if let Some(unit) = interaction.civilian {
                    civilian_cursor_token(session.game.civilian_tile_action(unit, tile))
                } else {
                    let army_token = army_unselected_cursor_token(
                        session
                            .game
                            .army_map_cursor_state(nation, None, tile, 0, has_selection),
                    );
                    if army_token != 0 {
                        army_token
                    } else {
                        let navy_token =
                            navy_action_cursor_token(&session.game, tile, interaction.navy.zone);
                        if navy_token != 0 { navy_token } else { 0 }
                    }
                }
            }
            MapInteractionMode::Army => {
                let army_token = army_unselected_cursor_token(session.game.army_map_cursor_state(
                    nation,
                    None,
                    tile,
                    0,
                    has_selection,
                ));
                if army_token != 0 {
                    army_token
                } else if let Some(pending) = interaction.army {
                    army_selected_cursor_token(session.game.army_map_cursor_state(
                        nation,
                        Some(pending),
                        tile,
                        0,
                        has_selection,
                    ))
                } else {
                    navy_action_cursor_token(&session.game, tile, interaction.navy.zone)
                }
            }
            MapInteractionMode::Navy => {
                let army_token = army_unselected_cursor_token(session.game.army_map_cursor_state(
                    nation,
                    None,
                    tile,
                    0,
                    has_selection,
                ));
                if army_token != 0 {
                    army_token
                } else {
                    navy_selection_cursor_token(
                        &session.game,
                        tile,
                        interaction.navy.force,
                        interaction.navy.zone,
                    )
                }
            }
            MapInteractionMode::None => army_unselected_cursor_token(
                session
                    .game
                    .army_map_cursor_state(nation, None, tile, 0, has_selection),
            ),
        };
    if token == 0 || token == 0x3e7 {
        request_arrow_cursor(&mut requested);
    } else {
        request_turn_event_cursor(&mut requested, token);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civilian_order_sounds_match_tcivmgr_order_acceptance_cues() {
        assert_eq!(
            civilian_order_sound(CivilianTileAction::MoveUnit, None),
            Some(SoundId::new(0x2328))
        );
        assert_eq!(
            civilian_order_sound(
                CivilianTileAction::EngineerDirection14,
                Some(CivilianUnitKind::Engineer),
            ),
            Some(SoundId::new(0x2329))
        );
        assert_eq!(
            civilian_order_sound(
                CivilianTileAction::DevelopResource,
                Some(CivilianUnitKind::Miner),
            ),
            Some(SoundId::new(0x232d))
        );
        assert_eq!(
            civilian_order_sound(
                CivilianTileAction::DevelopResource,
                Some(CivilianUnitKind::Fisherman),
            ),
            None
        );
        assert_eq!(
            civilian_order_sound(
                CivilianTileAction::DevelopResource,
                Some(CivilianUnitKind::Driller),
            ),
            Some(SoundId::new(0x2339))
        );
    }

    fn two_frigates_in_player_port() -> (GameState, OceanZoneId, TaskForceId, ShipId) {
        let mut parts = crate::ui::test_support::beginning_of_game_parts();
        let nation = parts.turn.active_nation;
        let location = parts
            .ocean
            .zones
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, kind)| {
                let ZoneKind::PortZone(port) = kind else {
                    return None;
                };
                (parts.map[port.port_tile]
                    .former_owner_nation
                    .and_then(TileOwnerTag::nation)
                    == Some(nation))
                .then_some(OceanZoneId::new(index as u16))
            })
            .expect("active nation has a port zone");
        let first = parts.object_ids.ship();
        let second = parts.object_ids.ship();
        let force = parts.object_ids.task_force();
        let ship = |name: &str| ShipState {
            ship_type: ShipType::Frigate,
            location,
            aggression: NavalAggression::Balanced,
            nation,
            name: name.to_string(),
            strength: 900,
            experience: 0,
            selection: ShipSelection::Available,
        };
        parts.ships.insert(first, ship("Alpha"));
        parts.ships.insert(second, ship("Beta"));
        parts.task_forces.insert(
            force,
            TaskForceState::from_parts(
                NavalAggression::Balanced,
                TaskForceOrder::None,
                TaskForceTarget::None,
                location,
                nation,
                false,
                -1,
                [(first, true), (second, true)]
                    .into_iter()
                    .collect::<indexmap::IndexMap<_, _>>(),
            ),
        );
        (GameState::from_parts(parts), location, force, first)
    }

    fn first_navy_mission_tile(
        state: &GameState,
        force: TaskForceId,
        zone: OceanZoneId,
    ) -> Option<(TileId, i32)> {
        let geometry = state.map().geometry();
        for row in 0..STRATEGIC_MAP_HEIGHT {
            for column in 0..STRATEGIC_MAP_WIDTH {
                let Some(tile) = geometry.tile(row, column) else {
                    continue;
                };
                if state.navy_map_action_code(tile, Some(zone)) != 0 {
                    continue;
                }
                let command = state.navy_command_for_tile(force, tile);
                if matches!(command, 0x0c | 0x0d | 0x0e | 0x0f | 0x10) {
                    return Some((tile, command));
                }
            }
        }
        None
    }

    #[test]
    fn navy_mission_flow_selects_a_map_target_without_mission_buttons() {
        let (state, zone, force, first) = two_frigates_in_player_port();
        let nation = state.turn().active_nation;
        let mut session = GameSession::new(state);
        let mut interaction = StrategicInteraction::default();
        let mut viewport = StrategicViewport::default();

        activate_navy_selection(
            &mut session,
            &mut interaction,
            &mut viewport,
            zone,
            Some(force),
        );
        assert_eq!(interaction.mode, MapInteractionMode::Navy);
        assert_eq!(interaction.navy.force, Some(force));

        session
            .game
            .set_task_force_ship_selected(force, first, false);
        assert_eq!(
            session.game.navy_toolbar_counts(Some(force)).selected[NavyToolbarClass::Class1],
            1
        );

        session
            .game
            .set_task_force_aggression(force, NavalAggression::Aggressive);
        assert_eq!(
            session.game.task_force(force).map(|entry| entry.aggression),
            Some(NavalAggression::Aggressive)
        );

        let (tile, command) = first_navy_mission_tile(&session.game, force, zone)
            .expect("selected frigates can reach a map target");
        let token = navy_cursor_token(command);
        assert_ne!(token, 0);
        assert_eq!(
            navy_selection_cursor_token(&session.game, tile, Some(force), Some(zone)),
            token
        );

        assert_eq!(
            session
                .game
                .navy_do_tile_click(tile, Some(force), Some(zone), nation),
            NavyTileClick::Submitted
        );
        let order = session.game.task_force(force).map(|entry| entry.order);
        assert_ne!(order, Some(TaskForceOrder::None));

        cycle_map_interaction_selection(&mut session, &mut interaction, &mut viewport);
        assert_ne!(
            session.game.task_force(force).map(|entry| entry.order),
            Some(TaskForceOrder::None)
        );
    }
}
