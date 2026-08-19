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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum MapProjection {
    #[default]
    Detailed,
    Overview,
}

/// Retail `DOOG` upper-left map cell coordinates.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct OceanViewport {
    pub origin: IVec2,
}

impl OceanViewport {
    pub(crate) fn center_on(&mut self, tile: TileId, geometry: &MapGeometry) {
        let MapPosition { row, column } = geometry.position(tile);
        self.set_upper_left(
            IVec2::new(i32::from(column) - 0x10, i32::from(row) - 0x0e),
            geometry,
        );
    }

    pub(crate) fn nudge(&mut self, edges: MapEdges, geometry: &MapGeometry) {
        if edges.contains(MapEdges::TOP) {
            self.origin.y -= 4;
        } else if edges.contains(MapEdges::BOTTOM) {
            self.origin.y += 4;
        }
        if edges.contains(MapEdges::RIGHT) {
            self.origin.x += 4;
        } else if edges.contains(MapEdges::LEFT) {
            self.origin.x -= 4;
        }
        self.set_upper_left(self.origin, geometry);
    }

    pub(crate) fn set_upper_left(&mut self, origin: IVec2, geometry: &MapGeometry) {
        self.origin.x = if geometry.wraps_horizontally() {
            origin.x.rem_euclid(i32::from(STRATEGIC_MAP_WIDTH))
        } else {
            origin.x.clamp(0, 0x4c)
        };
        self.origin.y = origin.y.clamp(0, 0x20);
    }

    pub(crate) fn center_tile(self, geometry: &MapGeometry) -> TileId {
        geometry
            .tile(MapPosition::new(
                self.origin.y + 0x0e,
                (self.origin.x + 0x10).rem_euclid(STRATEGIC_MAP_WIDTH),
            ))
            .expect("retail ocean center is inside the map")
    }
}

#[derive(Component, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct StrategicViewport {
    pub projection: MapProjection,
    pub ocean: OceanViewport,
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MapTransition {
    ToggleZoom,
    Center(TileId),
    SetUpperLeft(IVec2),
    Scroll(MapEdges),
    SetMode(MapInteractionMode),
}

pub(crate) fn detailed_center_tile(session: &GameSession) -> TileId {
    let geometry = session.game.map().geometry();
    let MapPosition { row, column } = geometry.position(session.map_view_origin);
    geometry
        .tile(MapPosition::new(
            row + 4,
            (column + 4) % STRATEGIC_MAP_WIDTH,
        ))
        .expect("retail detailed-map center is inside the map")
}

/// Applies the strategic map's semantic viewport operations in one place.
pub(crate) fn apply_map_transition(
    session: &mut GameSession,
    interaction: &mut StrategicInteraction,
    viewport: &mut StrategicViewport,
    transition: MapTransition,
) {
    let geometry = session.game.map().geometry();
    match transition {
        MapTransition::ToggleZoom => match viewport.projection {
            MapProjection::Detailed => {
                viewport
                    .ocean
                    .center_on(detailed_center_tile(session), &geometry);
                viewport.projection = MapProjection::Overview;
            }
            MapProjection::Overview => {
                session.center_map_on(viewport.ocean.center_tile(&geometry));
                viewport.projection = MapProjection::Detailed;
            }
        },
        MapTransition::Center(tile) => match viewport.projection {
            MapProjection::Detailed => session.center_map_on(tile),
            MapProjection::Overview => viewport.ocean.center_on(tile, &geometry),
        },
        MapTransition::SetUpperLeft(origin) => match viewport.projection {
            MapProjection::Detailed => session.set_map_viewport_upper_left(origin.x, origin.y),
            MapProjection::Overview => viewport.ocean.set_upper_left(origin, &geometry),
        },
        MapTransition::Scroll(edges) => match viewport.projection {
            MapProjection::Detailed => {
                session.scroll_map_viewport(edges.row_delta(), edges.column_delta());
            }
            MapProjection::Overview => viewport.ocean.nudge(edges, &geometry),
        },
        MapTransition::SetMode(next) => {
            if interaction.mode == next {
                return;
            }
            match interaction.mode {
                MapInteractionMode::Civilian => interaction.civilian = None,
                MapInteractionMode::Army => interaction.army = None,
                MapInteractionMode::Navy | MapInteractionMode::None => {}
            }
            interaction.mode = next;
            if next == MapInteractionMode::Civilian
                && viewport.projection == MapProjection::Overview
            {
                session.center_map_on(viewport.ocean.center_tile(&geometry));
                viewport.projection = MapProjection::Detailed;
            }
        }
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
    viewport: &mut StrategicViewport,
) {
    let nation = session.game.turn().active_nation;
    let mut cursor = interaction.mode;
    let mut previous = interaction.mode;
    let mut visited = 0_u8;
    if NationId::as_major(nation).is_none_or(|major| {
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
                    apply_map_transition(
                        session,
                        interaction,
                        viewport,
                        MapTransition::SetMode(MapInteractionMode::Civilian),
                    );
                    interaction.civilian = Some(id);
                    session.game.activate_civilian_selection(id);
                    if let Some(tile) = tile {
                        apply_map_transition(
                            session,
                            interaction,
                            viewport,
                            MapTransition::Center(tile),
                        );
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
                    apply_map_transition(
                        session,
                        interaction,
                        viewport,
                        MapTransition::SetMode(MapInteractionMode::Army),
                    );
                    session.game.apply_army_province_selection(Some(province));
                    interaction.army = Some(province);
                    if let Some(tile) = session.game.map().provinces[province].city_tile() {
                        apply_map_transition(
                            session,
                            interaction,
                            viewport,
                            MapTransition::Center(tile),
                        );
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
                    apply_map_transition(
                        session,
                        interaction,
                        viewport,
                        MapTransition::SetMode(MapInteractionMode::Navy),
                    );
                    interaction.navy.zone = Some(zone);
                    interaction.navy.force = session.game.demand_task_force_for_zone(zone, nation);
                    if let Some(tile) = navy_zone_center_tile(&session.game, zone) {
                        apply_map_transition(
                            session,
                            interaction,
                            viewport,
                            MapTransition::Center(tile),
                        );
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
        apply_map_transition(
            session,
            interaction,
            viewport,
            MapTransition::SetMode(MapInteractionMode::Navy),
        );
        interaction.navy.zone = Some(zone);
        interaction.navy.force = session.game.demand_task_force_for_zone(zone, nation);
        return;
    }

    match interaction.mode {
        MapInteractionMode::Civilian => interaction.civilian = None,
        MapInteractionMode::Army => {
            interaction.army = None;
            apply_map_transition(
                session,
                interaction,
                viewport,
                MapTransition::SetMode(MapInteractionMode::None),
            );
        }
        MapInteractionMode::Navy => {
            interaction.navy.zone = None;
            interaction.navy.force = None;
            apply_map_transition(
                session,
                interaction,
                viewport,
                MapTransition::SetMode(MapInteractionMode::None),
            );
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
        let mut viewport = StrategicViewport::default();
        let detailed_center = detailed_center_tile(&session);

        apply_map_transition(
            &mut session,
            &mut interaction,
            &mut viewport,
            MapTransition::ToggleZoom,
        );
        assert_eq!(viewport.projection, MapProjection::Overview);
        assert_eq!(
            viewport.ocean.center_tile(&session.game.map().geometry()),
            detailed_center
        );

        viewport
            .ocean
            .nudge(MapEdges::RIGHT, &session.game.map().geometry());
        let ocean_center = viewport.ocean.center_tile(&session.game.map().geometry());
        apply_map_transition(
            &mut session,
            &mut interaction,
            &mut viewport,
            MapTransition::ToggleZoom,
        );
        assert_eq!(viewport.projection, MapProjection::Detailed);
        let MapPosition {
            row: ocean_row,
            column: ocean_column,
        } = session.game.map().geometry().position(ocean_center);
        let MapPosition {
            row: detailed_row,
            column: detailed_column,
        } = session
            .game
            .map()
            .geometry()
            .position(detailed_center_tile(&session));
        assert_eq!(detailed_column, ocean_column);
        assert_eq!(detailed_row, ocean_row + 1);

        for transition in [
            MapTransition::SetMode(MapInteractionMode::Army),
            MapTransition::ToggleZoom,
            MapTransition::SetMode(MapInteractionMode::Civilian),
        ] {
            apply_map_transition(&mut session, &mut interaction, &mut viewport, transition);
        }
        assert_eq!(viewport.projection, MapProjection::Detailed);
        apply_map_transition(
            &mut session,
            &mut interaction,
            &mut viewport,
            MapTransition::ToggleZoom,
        );
        apply_map_transition(
            &mut session,
            &mut interaction,
            &mut viewport,
            MapTransition::SetMode(MapInteractionMode::Civilian),
        );
        assert_eq!(viewport.projection, MapProjection::Overview);
    }

    #[test]
    fn ocean_upper_left_wraps_or_clamps_like_retail() {
        let mut ocean = OceanViewport::default();
        ocean.set_upper_left(IVec2::new(-4, -4), &MapGeometry::new(MapTopology::Wrapping));
        assert_eq!(ocean.origin, IVec2::new(104, 0));
        ocean.set_upper_left(IVec2::new(100, 60), &MapGeometry::new(MapTopology::Bounded));
        assert_eq!(ocean.origin, IVec2::new(0x4c, 0x20));
    }
}
