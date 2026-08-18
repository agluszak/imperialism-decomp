//! `TMapUberPicture::SetMapInteractionMode` and selection cycling.

use crate::ui::GameSession;
use bevy::prelude::*;
use imperialism_core::*;

/// Retail `activeUnitCategoryIndex96`: 0 civilian, 1 army, 2 navy, 3 none.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum MapInteractionMode {
    #[default]
    Civilian,
    Army,
    Navy,
    None,
}

/// Navy zone context (`orderEntryContext98`) and its task force (`selectedTaskForce14`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct NavySelection {
    pub zone: Option<OceanZoneId>,
    pub force: Option<TaskForceId>,
}

/// `TMapUberPicture::invalidationFlag94 == 0` is the `DOOG` ocean view.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct OceanView {
    pub active: bool,
    pub origin_column: i32,
    pub origin_row: i32,
}

impl OceanView {
    pub(crate) fn center_on(&mut self, tile: TileId, geometry: &MapGeometry) {
        let (row, column) = geometry.row_column(tile);
        self.origin_column = i32::from(column) - 0x10;
        self.origin_row = i32::from(row) - 0x0e;
        self.clamp();
    }

    pub(crate) fn nudge(&mut self, edges: MapEdges) {
        if edges.contains(MapEdges::TOP) {
            self.origin_row -= 4;
        } else if edges.contains(MapEdges::BOTTOM) {
            self.origin_row += 4;
        }
        if edges.contains(MapEdges::RIGHT) {
            self.origin_column += 4;
        } else if edges.contains(MapEdges::LEFT) {
            self.origin_column -= 4;
        }
        self.clamp();
    }

    fn clamp(&mut self) {
        while self.origin_column < 0 {
            self.origin_column += i32::from(STRATEGIC_MAP_WIDTH);
        }
        while self.origin_column >= i32::from(STRATEGIC_MAP_WIDTH) {
            self.origin_column -= i32::from(STRATEGIC_MAP_WIDTH);
        }
        self.origin_row = self.origin_row.clamp(0, 0x20);
    }
}

#[derive(Component, Default)]
pub(crate) struct StrategicInteraction {
    pub mode: MapInteractionMode,
    pub civilian: Option<CivilianUnitId>,
    /// `TArmyMgr::pendingMapActionIndex`. Transient; not saved.
    pub army: Option<ProvinceId>,
    pub navy: NavySelection,
    pub ocean: OceanView,
}

/// `TMapUberPicture::SetMapInteractionMode` (0x00596cb0).
///
/// Does not mutate `GameState`. Leaving civilian clears civilian selection; leaving
/// army clears the selected province without touching units.
pub(crate) fn set_map_interaction_mode(
    interaction: &mut StrategicInteraction,
    next: MapInteractionMode,
) {
    if interaction.mode == next {
        return;
    }
    match interaction.mode {
        MapInteractionMode::Civilian => interaction.civilian = None,
        MapInteractionMode::Army => interaction.army = None,
        MapInteractionMode::Navy | MapInteractionMode::None => {}
    }
    interaction.mode = next;
}

pub(crate) fn has_active_map_interaction_selection(interaction: &StrategicInteraction) -> bool {
    match interaction.mode {
        MapInteractionMode::Civilian => interaction.civilian.is_some(),
        MapInteractionMode::Army => interaction.army.is_some(),
        MapInteractionMode::Navy => interaction.navy.force.is_some(),
        MapInteractionMode::None => false,
    }
}

/// `TMapUberPicture::CycleMapInteractionSelectionAfterHandledClick` (0x00597a80).
pub(crate) fn cycle_map_interaction_selection(
    session: &mut GameSession,
    interaction: &mut StrategicInteraction,
) {
    let nation = session.game.turn().active_nation;
    let mut cursor = interaction.mode;
    let mut previous = interaction.mode;
    let mut visited = 0_u8;
    if MajorNationId::from_nation(nation).is_none_or(|major| {
        !session
            .game
            .nations()
            .major(major)
            .economy
            .diplomacy_eligible
    }) {
        visited = 7;
    }

    loop {
        if visited == 7 {
            break;
        }
        match cursor {
            MapInteractionMode::Civilian => {
                if previous != MapInteractionMode::Civilian {
                    visited |= 1;
                }
                if let Some((id, unit)) = session.game.first_idle_civilian(nation) {
                    let tile = unit.location().tile();
                    set_map_interaction_mode(interaction, MapInteractionMode::Civilian);
                    interaction.civilian = Some(id);
                    session.game.activate_civilian_selection(id);
                    if let Some(tile) = tile {
                        session.game.center_map_on(tile);
                    }
                    return;
                }
                cursor = MapInteractionMode::Army;
                previous = MapInteractionMode::Civilian;
                if interaction.mode != MapInteractionMode::Civilian {
                    visited |= 1;
                }
            }
            MapInteractionMode::Army => {
                if previous != MapInteractionMode::Army {
                    session
                        .game
                        .clear_province_selection_highlights_for_nation(nation);
                    visited |= 2;
                }
                if let Some(province) = session
                    .game
                    .find_next_selectable_army_province(nation, None)
                {
                    set_map_interaction_mode(interaction, MapInteractionMode::Army);
                    session.game.apply_army_province_selection(Some(province));
                    interaction.army = Some(province);
                    if let Some(tile) = session.game.map().provinces[province].city_tile() {
                        session.game.center_map_on(tile);
                    }
                    return;
                }
                cursor = MapInteractionMode::Navy;
                previous = MapInteractionMode::Army;
                if interaction.mode != MapInteractionMode::Army {
                    visited |= 2;
                }
            }
            MapInteractionMode::Navy => {
                if let Some(zone) = session
                    .game
                    .next_navy_order_zone(nation, interaction.navy.zone)
                {
                    set_map_interaction_mode(interaction, MapInteractionMode::Navy);
                    interaction.navy.zone = Some(zone);
                    interaction.navy.force = session.game.demand_task_force_for_zone(zone, nation);
                    if let Some(tile) = navy_zone_center_tile(&session.game, zone) {
                        session.game.center_map_on(tile);
                    }
                    return;
                }
                cursor = MapInteractionMode::Civilian;
                interaction.navy.zone = None;
                interaction.navy.force = None;
                previous = MapInteractionMode::Navy;
                visited |= 4;
            }
            MapInteractionMode::None => cursor = MapInteractionMode::Civilian,
        }
        if visited == 7 {
            break;
        }
    }

    if visited == 7
        && let Some(zone) = session.game.next_navy_order_zone(nation, None)
    {
        set_map_interaction_mode(interaction, MapInteractionMode::Navy);
        interaction.navy.zone = Some(zone);
        interaction.navy.force = session.game.demand_task_force_for_zone(zone, nation);
        return;
    }

    match interaction.mode {
        MapInteractionMode::Civilian => interaction.civilian = None,
        MapInteractionMode::Army => {
            interaction.army = None;
            set_map_interaction_mode(interaction, MapInteractionMode::None);
        }
        MapInteractionMode::Navy => {
            interaction.navy.zone = None;
            interaction.navy.force = None;
            set_map_interaction_mode(interaction, MapInteractionMode::None);
        }
        MapInteractionMode::None => {}
    }
}

pub(crate) fn navy_zone_center_tile(state: &GameState, zone: OceanZoneId) -> Option<TileId> {
    let zone = state.ocean().zones.get(usize::from(zone.get()))?;
    match zone {
        imperialism_core::ZoneKind::PortZone(port) => {
            port.zone.target_tile.or(Some(port.port_tile))
        }
        imperialism_core::ZoneKind::Zone(zone) => zone.target_tile.or(zone.active_tile),
    }
}
