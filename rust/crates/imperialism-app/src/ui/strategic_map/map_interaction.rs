//! `TMapUberPicture::SetMapInteractionMode` and selection cycling.

use super::civilian_orders::StrategicSelection;
use crate::AppState;
use crate::ui::GameSession;
use bevy::prelude::*;
use imperialism_core::*;

/// Retail `activeUnitCategoryIndex96`: 0 civilian, 1 army, 2 navy, 3 none.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Resource)]
pub(crate) enum MapInteractionMode {
    #[default]
    Civilian,
    Army,
    Navy,
    None,
}

impl MapInteractionMode {
    #[allow(dead_code)]
    pub(crate) const fn retail(self) -> i32 {
        match self {
            Self::Civilian => 0,
            Self::Army => 1,
            Self::Navy => 2,
            Self::None => 3,
        }
    }
}

/// `TArmyMgr::pendingMapActionIndex`. Transient; not saved.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Resource)]
pub(crate) struct ArmySelection(pub Option<ProvinceId>);

/// Navy zone context (`orderEntryContext98`) and its task force (`selectedTaskForce14`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Resource)]
pub(crate) struct NavySelection {
    pub zone: Option<OceanZoneId>,
    pub force: Option<TaskForceId>,
}

/// `TMapUberPicture::invalidationFlag94 == 0` is the `DOOG` ocean view.
#[derive(Clone, Copy, Debug, Default, Resource)]
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

pub(crate) fn register(app: &mut App) {
    app.init_resource::<MapInteractionMode>()
        .init_resource::<ArmySelection>()
        .init_resource::<NavySelection>()
        .init_resource::<OceanView>()
        .add_systems(OnEnter(AppState::StrategicMap), reset_map_interaction);
}

fn reset_map_interaction(
    mut mode: ResMut<MapInteractionMode>,
    mut army: ResMut<ArmySelection>,
    mut navy: ResMut<NavySelection>,
    mut ocean: ResMut<OceanView>,
) {
    *mode = MapInteractionMode::Civilian;
    army.0 = None;
    *navy = NavySelection::default();
    *ocean = OceanView::default();
}

/// `TMapUberPicture::SetMapInteractionMode` (0x00596cb0).
///
/// Does not mutate `GameState`. Leaving civilian clears civilian selection; leaving
/// army clears the selected province without touching units.
pub(crate) fn set_map_interaction_mode(
    mode: &mut MapInteractionMode,
    next: MapInteractionMode,
    civilian: &mut StrategicSelection,
    army: &mut ArmySelection,
) {
    if *mode == next {
        return;
    }
    match *mode {
        MapInteractionMode::Civilian => civilian.0 = None,
        MapInteractionMode::Army => army.0 = None,
        MapInteractionMode::Navy | MapInteractionMode::None => {}
    }
    *mode = next;
}

pub(crate) fn has_active_map_interaction_selection(
    mode: MapInteractionMode,
    civilian: Option<CivilianUnitId>,
    army: Option<ProvinceId>,
    navy_force: Option<TaskForceId>,
) -> bool {
    match mode {
        MapInteractionMode::Civilian => civilian.is_some(),
        MapInteractionMode::Army => army.is_some(),
        MapInteractionMode::Navy => navy_force.is_some(),
        MapInteractionMode::None => false,
    }
}

/// `TMapUberPicture::CycleMapInteractionSelectionAfterHandledClick` (0x00597a80).
pub(crate) fn cycle_map_interaction_selection(
    session: &mut GameSession,
    mode: &mut MapInteractionMode,
    civilian: &mut StrategicSelection,
    army: &mut ArmySelection,
    navy: &mut NavySelection,
) {
    let nation = session.game.turn().active_nation;
    let mut cursor = *mode;
    let mut previous = *mode;
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
                if let Some(unit) = session.game.first_idle_civilian(nation) {
                    set_map_interaction_mode(mode, MapInteractionMode::Civilian, civilian, army);
                    civilian.0 = Some(unit.id());
                    if let Some(tile) = unit.location().tile() {
                        session.game.center_map_on(tile);
                    }
                    return;
                }
                cursor = MapInteractionMode::Army;
                previous = MapInteractionMode::Civilian;
                if *mode != MapInteractionMode::Civilian {
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
                    set_map_interaction_mode(mode, MapInteractionMode::Army, civilian, army);
                    session.game.apply_army_province_selection(Some(province));
                    army.0 = Some(province);
                    if let Some(tile) = session.game.map().provinces[province].city_tile() {
                        session.game.center_map_on(tile);
                    }
                    return;
                }
                cursor = MapInteractionMode::Navy;
                previous = MapInteractionMode::Army;
                if *mode != MapInteractionMode::Army {
                    visited |= 2;
                }
            }
            MapInteractionMode::Navy => {
                if let Some(zone) = session.game.next_navy_order_zone(nation, navy.zone) {
                    set_map_interaction_mode(mode, MapInteractionMode::Navy, civilian, army);
                    navy.zone = Some(zone);
                    navy.force = session.game.demand_task_force_for_zone(zone, nation);
                    if let Some(tile) = navy_zone_center_tile(&session.game, zone) {
                        session.game.center_map_on(tile);
                    }
                    return;
                }
                cursor = MapInteractionMode::Civilian;
                navy.zone = None;
                navy.force = None;
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
        set_map_interaction_mode(mode, MapInteractionMode::Navy, civilian, army);
        navy.zone = Some(zone);
        navy.force = session.game.demand_task_force_for_zone(zone, nation);
        return;
    }

    match *mode {
        MapInteractionMode::Civilian => civilian.0 = None,
        MapInteractionMode::Army => {
            army.0 = None;
            set_map_interaction_mode(mode, MapInteractionMode::None, civilian, army);
        }
        MapInteractionMode::Navy => {
            navy.zone = None;
            navy.force = None;
            set_map_interaction_mode(mode, MapInteractionMode::None, civilian, army);
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

    #[test]
    fn leaving_civilian_clears_civilian_selection() {
        let mut mode = MapInteractionMode::Civilian;
        let mut civilian = StrategicSelection(Some(CivilianUnitId::from_serialized(1)));
        let mut army = ArmySelection(Some(ProvinceId::new(3)));
        set_map_interaction_mode(
            &mut mode,
            MapInteractionMode::Army,
            &mut civilian,
            &mut army,
        );
        assert_eq!(mode, MapInteractionMode::Army);
        assert_eq!(civilian.0, None);
        assert_eq!(army.0, Some(ProvinceId::new(3)));
        assert_eq!(mode.retail(), 1);
    }

    #[test]
    fn leaving_army_clears_province_without_touching_navy() {
        let mut mode = MapInteractionMode::Army;
        let mut civilian = StrategicSelection(None);
        let mut army = ArmySelection(Some(ProvinceId::new(4)));
        set_map_interaction_mode(
            &mut mode,
            MapInteractionMode::Navy,
            &mut civilian,
            &mut army,
        );
        assert_eq!(mode, MapInteractionMode::Navy);
        assert_eq!(army.0, None);
    }
}
