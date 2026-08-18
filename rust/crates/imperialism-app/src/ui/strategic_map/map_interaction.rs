//! `TMapUberPicture::SetMapInteractionMode` and selection cycling.

use crate::ui::GameSession;
use bevy::prelude::*;
use imperialism_core::*;
use std::ops::{BitOr, BitOrAssign};

/// Retail strategic-map edge-scroll bits (`TMapDialog` cursor-edge mask).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct MapEdges(u8);

impl MapEdges {
    pub(crate) const TOP: Self = Self(0x01);
    pub(crate) const BOTTOM: Self = Self(0x02);
    pub(crate) const RIGHT: Self = Self(0x04);
    pub(crate) const LEFT: Self = Self(0x08);

    pub(crate) const fn empty() -> Self {
        Self(0)
    }

    pub(crate) const fn is_empty(self) -> bool {
        self.0 == 0
    }

    pub(crate) const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub(crate) const fn row_delta(self) -> i32 {
        if self.contains(Self::TOP) {
            -1
        } else if self.contains(Self::BOTTOM) {
            1
        } else {
            0
        }
    }

    pub(crate) const fn column_delta(self) -> i32 {
        if self.contains(Self::RIGHT) {
            1
        } else if self.contains(Self::LEFT) {
            -1
        } else {
            0
        }
    }
}

impl BitOr for MapEdges {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for MapEdges {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

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
        self.set_upper_left(self.origin_column, self.origin_row, geometry);
    }

    pub(crate) fn nudge(&mut self, edges: MapEdges, geometry: &MapGeometry) {
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
        self.set_upper_left(self.origin_column, self.origin_row, geometry);
    }

    pub(crate) fn set_upper_left(&mut self, column: i32, row: i32, geometry: &MapGeometry) {
        self.origin_column = if geometry.wraps_horizontally() {
            column.rem_euclid(i32::from(STRATEGIC_MAP_WIDTH))
        } else {
            column.clamp(0, 0x4c)
        };
        self.origin_row = row;
        self.origin_row = self.origin_row.clamp(0, 0x20);
    }

    pub(crate) fn center_tile(self, geometry: &MapGeometry) -> TileId {
        geometry
            .tile(
                (self.origin_row + 0x0e) as u16,
                (self.origin_column + 0x10).rem_euclid(i32::from(STRATEGIC_MAP_WIDTH)) as u16,
            )
            .expect("retail ocean center is inside the map")
    }
}

#[derive(Component)]
pub(crate) struct MapZoomControl;

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
/// army clears the selected province without touching units. A change into civilian
/// mode restores the detailed map, as retail does before placing the civilian page.
pub(crate) fn set_map_interaction_mode(
    session: &mut GameSession,
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
    if next == MapInteractionMode::Civilian {
        zoom_in(session, interaction);
    }
}

pub(crate) fn detailed_center_tile(session: &GameSession) -> TileId {
    let geometry = session.game.map().geometry();
    let (row, column) = geometry.row_column(session.map_view_origin);
    geometry
        .tile(row + 4, (column + 4) % STRATEGIC_MAP_WIDTH)
        .expect("retail detailed-map center is inside the map")
}

pub(crate) fn zoom_out(session: &GameSession, interaction: &mut StrategicInteraction) {
    if interaction.ocean.active {
        return;
    }
    interaction.ocean.center_on(
        detailed_center_tile(session),
        &session.game.map().geometry(),
    );
    interaction.ocean.active = true;
}

pub(crate) fn zoom_in(session: &mut GameSession, interaction: &mut StrategicInteraction) {
    if !interaction.ocean.active {
        return;
    }
    let center = interaction
        .ocean
        .center_tile(&session.game.map().geometry());
    session.center_map_on(center);
    interaction.ocean.active = false;
}

pub(crate) fn toggle_zoom(session: &mut GameSession, interaction: &mut StrategicInteraction) {
    if interaction.ocean.active {
        zoom_in(session, interaction);
    } else {
        zoom_out(session, interaction);
    }
}

pub(crate) fn center_active_map(
    session: &mut GameSession,
    interaction: &mut StrategicInteraction,
    tile: TileId,
) {
    if interaction.ocean.active {
        interaction
            .ocean
            .center_on(tile, &session.game.map().geometry());
    } else {
        session.center_map_on(tile);
    }
}

pub(crate) fn set_active_map_upper_left(
    session: &mut GameSession,
    interaction: &mut StrategicInteraction,
    column: i32,
    row: i32,
) {
    if interaction.ocean.active {
        interaction
            .ocean
            .set_upper_left(column, row, &session.game.map().geometry());
    } else {
        session.set_map_viewport_upper_left(column, row);
    }
}

pub(crate) fn scroll_active_map(
    session: &mut GameSession,
    interaction: &mut StrategicInteraction,
    edges: MapEdges,
) {
    if interaction.ocean.active {
        interaction
            .ocean
            .nudge(edges, &session.game.map().geometry());
    } else {
        session.scroll_map_viewport(edges.row_delta(), edges.column_delta());
    }
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
                    set_map_interaction_mode(session, interaction, MapInteractionMode::Civilian);
                    interaction.civilian = Some(id);
                    session.game.activate_civilian_selection(id);
                    if let Some(tile) = tile {
                        center_active_map(session, interaction, tile);
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
                    set_map_interaction_mode(session, interaction, MapInteractionMode::Army);
                    session.game.apply_army_province_selection(Some(province));
                    interaction.army = Some(province);
                    if let Some(tile) = session.game.map().provinces[province].city_tile() {
                        center_active_map(session, interaction, tile);
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
                    set_map_interaction_mode(session, interaction, MapInteractionMode::Navy);
                    interaction.navy.zone = Some(zone);
                    interaction.navy.force = session.game.demand_task_force_for_zone(zone, nation);
                    if let Some(tile) = navy_zone_center_tile(&session.game, zone) {
                        center_active_map(session, interaction, tile);
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
        set_map_interaction_mode(session, interaction, MapInteractionMode::Navy);
        interaction.navy.zone = Some(zone);
        interaction.navy.force = session.game.demand_task_force_for_zone(zone, nation);
        return;
    }

    match interaction.mode {
        MapInteractionMode::Civilian => interaction.civilian = None,
        MapInteractionMode::Army => {
            interaction.army = None;
            set_map_interaction_mode(session, interaction, MapInteractionMode::None);
        }
        MapInteractionMode::Navy => {
            interaction.navy.zone = None;
            interaction.navy.force = None;
            set_map_interaction_mode(session, interaction, MapInteractionMode::None);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::test_support::{beginning_of_game_with, strategic_map_beginning_context};

    fn session() -> GameSession {
        GameSession::new(beginning_of_game_with(strategic_map_beginning_context()))
    }

    #[test]
    fn zoom_transfers_retail_dialog_centers_and_civilian_transition_only() {
        let mut session = session();
        session.set_map_viewport_upper_left(10, 10);
        let mut interaction = StrategicInteraction::default();
        let detailed_center = detailed_center_tile(&session);

        zoom_out(&session, &mut interaction);
        assert!(interaction.ocean.active);
        assert_eq!(
            interaction
                .ocean
                .center_tile(&session.game.map().geometry()),
            detailed_center
        );

        interaction
            .ocean
            .nudge(MapEdges::RIGHT, &session.game.map().geometry());
        let ocean_center = interaction
            .ocean
            .center_tile(&session.game.map().geometry());
        zoom_in(&mut session, &mut interaction);
        assert!(!interaction.ocean.active);
        let (ocean_row, ocean_column) = session.game.map().geometry().row_column(ocean_center);
        let (detailed_row, detailed_column) = session
            .game
            .map()
            .geometry()
            .row_column(detailed_center_tile(&session));
        assert_eq!(detailed_column, ocean_column);
        assert_eq!(detailed_row, ocean_row + 1);

        set_map_interaction_mode(&mut session, &mut interaction, MapInteractionMode::Army);
        zoom_out(&session, &mut interaction);
        set_map_interaction_mode(&mut session, &mut interaction, MapInteractionMode::Civilian);
        assert!(!interaction.ocean.active);
        zoom_out(&session, &mut interaction);
        set_map_interaction_mode(&mut session, &mut interaction, MapInteractionMode::Civilian);
        assert!(interaction.ocean.active);
    }

    #[test]
    fn ocean_upper_left_wraps_or_clamps_like_retail() {
        let mut ocean = OceanView::default();
        ocean.set_upper_left(-4, -4, &MapGeometry::new(MapTopology::Wrapping));
        assert_eq!((ocean.origin_column, ocean.origin_row), (104, 0));
        ocean.set_upper_left(100, 60, &MapGeometry::new(MapTopology::Bounded));
        assert_eq!((ocean.origin_column, ocean.origin_row), (0x4c, 0x20));
    }
}
