//! One owner for strategic-map selection and viewport.

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

/// Retail `DOOG` upper-left map cell coordinates.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct OceanViewport {
    pub origin: IVec2,
}

impl OceanViewport {
    pub(crate) fn center_on(&mut self, tile: TileId, geometry: &MapGeometry) {
        let (row, column) = geometry.row_column(tile);
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
            .tile(
                (self.origin.y + 0x0e) as u16,
                (self.origin.x + 0x10).rem_euclid(i32::from(STRATEGIC_MAP_WIDTH)) as u16,
            )
            .expect("retail ocean center is inside the map")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrategicSelection {
    None,
    Civilian(Option<CivilianUnitId>),
    Army(Option<ProvinceId>),
    Navy {
        zone: Option<OceanZoneId>,
        force: Option<TaskForceId>,
    },
}

impl Default for StrategicSelection {
    fn default() -> Self {
        Self::Civilian(None)
    }
}

impl StrategicSelection {
    pub(crate) fn civilian(self) -> Option<CivilianUnitId> {
        match self {
            Self::Civilian(unit) => unit,
            _ => None,
        }
    }

    pub(crate) fn army(self) -> Option<ProvinceId> {
        match self {
            Self::Army(province) => province,
            _ => None,
        }
    }

    pub(crate) fn navy_zone(self) -> Option<OceanZoneId> {
        match self {
            Self::Navy { zone, .. } => zone,
            _ => None,
        }
    }

    pub(crate) fn navy_force(self) -> Option<TaskForceId> {
        match self {
            Self::Navy { force, .. } => force,
            _ => None,
        }
    }

    pub(crate) fn has_target(self) -> bool {
        match self {
            Self::Civilian(unit) => unit.is_some(),
            Self::Army(province) => province.is_some(),
            Self::Navy { force, .. } => force.is_some(),
            Self::None => false,
        }
    }

    fn kind(self) -> SelectionKind {
        match self {
            Self::None => SelectionKind::None,
            Self::Civilian(_) => SelectionKind::Civilian,
            Self::Army(_) => SelectionKind::Army,
            Self::Navy { .. } => SelectionKind::Navy,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SelectionKind {
    None,
    Civilian,
    Army,
    Navy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StrategicView {
    Detailed { origin: TileId },
    Overview { origin: IVec2 },
}

impl Default for StrategicView {
    fn default() -> Self {
        Self::Detailed {
            origin: TileId::new(1),
        }
    }
}

impl StrategicView {
    pub(crate) fn is_overview(self) -> bool {
        matches!(self, Self::Overview { .. })
    }

    pub(crate) fn detailed_origin(self, game: &GameState) -> TileId {
        match self {
            Self::Detailed { origin } => origin,
            Self::Overview { origin } => game.map().viewport_origin_centered_on(
                OceanViewport { origin }.center_tile(&game.map().geometry()),
            ),
        }
    }

    pub(crate) fn ocean(self) -> OceanViewport {
        match self {
            Self::Overview { origin } => OceanViewport { origin },
            Self::Detailed { .. } => OceanViewport::default(),
        }
    }

    fn toggle_zoom(&mut self, game: &GameState) {
        let geometry = game.map().geometry();
        *self = match *self {
            Self::Detailed { origin } => {
                let mut ocean = OceanViewport::default();
                ocean.center_on(detailed_center_tile(game, origin), &geometry);
                Self::Overview {
                    origin: ocean.origin,
                }
            }
            Self::Overview { origin } => Self::Detailed {
                origin: game
                    .map()
                    .viewport_origin_centered_on(OceanViewport { origin }.center_tile(&geometry)),
            },
        };
    }

    fn center_on(&mut self, game: &GameState, tile: TileId) {
        match self {
            Self::Detailed { origin } => {
                *origin = game.map().viewport_origin_centered_on(tile);
            }
            Self::Overview { origin } => {
                let mut ocean = OceanViewport { origin: *origin };
                ocean.center_on(tile, &game.map().geometry());
                *origin = ocean.origin;
            }
        }
    }

    fn set_upper_left(&mut self, game: &GameState, upper_left: IVec2) {
        match self {
            Self::Detailed { origin } => {
                *origin = game
                    .map()
                    .viewport_origin_from_upper_left(upper_left.x, upper_left.y);
            }
            Self::Overview { origin } => {
                let mut ocean = OceanViewport { origin: *origin };
                ocean.set_upper_left(upper_left, &game.map().geometry());
                *origin = ocean.origin;
            }
        }
    }

    fn scroll(&mut self, game: &GameState, edges: MapEdges) {
        match self {
            Self::Detailed { origin } => {
                *origin = game.map().scrolled_viewport_origin(
                    *origin,
                    edges.row_delta(),
                    edges.column_delta(),
                );
            }
            Self::Overview { origin } => {
                let mut ocean = OceanViewport { origin: *origin };
                ocean.nudge(edges, &game.map().geometry());
                *origin = ocean.origin;
            }
        }
    }

    fn show_detailed_from_overview_center(&mut self, game: &GameState) {
        if let Self::Overview { origin } = *self {
            *self = Self::Detailed {
                origin: game.map().viewport_origin_centered_on(
                    OceanViewport { origin }.center_tile(&game.map().geometry()),
                ),
            };
        }
    }
}

#[derive(Component)]
pub(crate) struct MapZoomControl;

/// Presentation selection and camera for the strategic map. Separate from
/// [`crate::ui::GameSession`] so scrolling and mode changes do not mark gameplay changed.
#[derive(Resource, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct StrategicMapSession {
    pub selection: StrategicSelection,
    pub view: StrategicView,
}

impl StrategicMapSession {
    pub(crate) fn from_origin(origin: TileId) -> Self {
        Self {
            selection: StrategicSelection::Civilian(None),
            view: StrategicView::Detailed { origin },
        }
    }

    pub(crate) fn apply(&mut self, game: &mut GameState, action: MapAction) {
        match action {
            MapAction::ToggleZoom => self.view.toggle_zoom(game),
            MapAction::Center(tile) => self.view.center_on(game, tile),
            MapAction::SetUpperLeft(upper_left) => self.view.set_upper_left(game, upper_left),
            MapAction::Scroll(edges) => self.view.scroll(game, edges),
            MapAction::Select(next) => {
                if self.selection.kind() != next.kind()
                    && matches!(next, StrategicSelection::Civilian(_))
                {
                    self.view.show_detailed_from_overview_center(game);
                }
                self.selection = next;
            }
        }
    }

    /// `TMapUberPicture::CycleMapInteractionSelectionAfterHandledClick` (0x00597a80).
    pub(crate) fn cycle_selection(&mut self, game: &mut GameState) {
        let nation = game.turn().active_nation;
        let start = self.selection.kind();
        let mut cursor = start;
        let mut previous = start;
        let mut visited = 0_u8;
        if MajorNationId::from_nation(nation)
            .is_none_or(|major| !game.nations().major(major).economy.diplomacy_eligible)
        {
            visited = 7;
        }

        loop {
            if visited == 7 {
                break;
            }
            match cursor {
                SelectionKind::Civilian => {
                    if previous != SelectionKind::Civilian {
                        visited |= 1;
                    }
                    if self.try_select_next_civilian(game) {
                        return;
                    }
                    cursor = SelectionKind::Army;
                    previous = SelectionKind::Civilian;
                    if start != SelectionKind::Civilian {
                        visited |= 1;
                    }
                }
                SelectionKind::Army => {
                    if previous != SelectionKind::Army {
                        game.clear_province_selection_highlights_for_nation(nation);
                        visited |= 2;
                    }
                    if self.try_select_next_army(game) {
                        return;
                    }
                    cursor = SelectionKind::Navy;
                    previous = SelectionKind::Army;
                    if start != SelectionKind::Army {
                        visited |= 2;
                    }
                }
                SelectionKind::Navy => {
                    let from_zone = self.selection.navy_zone();
                    if self.try_select_next_navy(game, from_zone) {
                        return;
                    }
                    cursor = SelectionKind::Civilian;
                    if let StrategicSelection::Navy { .. } = self.selection {
                        self.selection = StrategicSelection::Navy {
                            zone: None,
                            force: None,
                        };
                    }
                    previous = SelectionKind::Navy;
                    visited |= 4;
                }
                SelectionKind::None => cursor = SelectionKind::Civilian,
            }
            if visited == 7 {
                break;
            }
        }

        if visited == 7 && self.try_select_next_navy(game, None) {
            return;
        }

        match self.selection {
            StrategicSelection::Civilian(_) => {
                self.selection = StrategicSelection::Civilian(None);
            }
            StrategicSelection::Army(_) => {
                self.apply(game, MapAction::Select(StrategicSelection::None));
            }
            StrategicSelection::Navy { .. } => {
                self.apply(game, MapAction::Select(StrategicSelection::None));
            }
            StrategicSelection::None => {}
        }
    }

    /// `TMapUberPicture::SetActiveMapOrderEntry` presentation: navy mode, zone/force, and center.
    pub(crate) fn select_navy(
        &mut self,
        game: &mut GameState,
        zone: OceanZoneId,
        force: Option<TaskForceId>,
    ) {
        self.apply(
            game,
            MapAction::Select(StrategicSelection::Navy {
                zone: Some(zone),
                force,
            }),
        );
        if let Some(tile) = navy_zone_center_tile(game, zone) {
            self.apply(game, MapAction::Center(tile));
        }
    }

    fn try_select_next_civilian(&mut self, game: &mut GameState) -> bool {
        let nation = game.turn().active_nation;
        let Some((id, tile)) = game
            .first_idle_civilian(nation)
            .map(|(id, unit)| (id, unit.location().tile()))
        else {
            return false;
        };
        self.apply(
            game,
            MapAction::Select(StrategicSelection::Civilian(Some(id))),
        );
        game.activate_civilian_selection(id);
        if let Some(tile) = tile {
            self.apply(game, MapAction::Center(tile));
        }
        true
    }

    fn try_select_next_army(&mut self, game: &mut GameState) -> bool {
        let nation = game.turn().active_nation;
        let Some(province) = game.find_next_selectable_army_province(nation, None) else {
            return false;
        };
        self.apply(
            game,
            MapAction::Select(StrategicSelection::Army(Some(province))),
        );
        game.apply_army_province_selection(Some(province));
        if let Some(tile) = game.map().provinces[province].city_tile() {
            self.apply(game, MapAction::Center(tile));
        }
        true
    }

    fn try_select_next_navy(
        &mut self,
        game: &mut GameState,
        from_zone: Option<OceanZoneId>,
    ) -> bool {
        let nation = game.turn().active_nation;
        let Some(zone) = game.next_navy_order_zone(nation, from_zone) else {
            return false;
        };
        let force = game.demand_task_force_for_zone(zone, nation);
        self.select_navy(game, zone, force);
        true
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MapAction {
    ToggleZoom,
    Center(TileId),
    SetUpperLeft(IVec2),
    Scroll(MapEdges),
    Select(StrategicSelection),
}

pub(crate) fn detailed_center_tile(game: &GameState, origin: TileId) -> TileId {
    let geometry = game.map().geometry();
    let (row, column) = geometry.row_column(origin);
    geometry
        .tile(row + 4, (column + 4) % STRATEGIC_MAP_WIDTH)
        .expect("retail detailed-map center is inside the map")
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
    use crate::ui::session::GameSession;
    use crate::ui::test_support::{beginning_of_game_with, strategic_map_beginning_context};

    fn session() -> GameSession {
        GameSession::new(beginning_of_game_with(strategic_map_beginning_context()))
    }

    #[test]
    fn zoom_transfers_retail_dialog_centers_and_civilian_transition_only() {
        let mut session = session();
        let mut map = StrategicMapSession::from_origin(TileId::new(1));
        map.view.set_upper_left(&session.game, IVec2::new(10, 10));
        let StrategicView::Detailed { origin } = map.view else {
            panic!("loaded origin is detailed");
        };
        let detailed_center = detailed_center_tile(&session.game, origin);

        map.apply(&mut session.game, MapAction::ToggleZoom);
        let StrategicView::Overview { origin: ocean } = map.view else {
            panic!("toggle zoom from detailed enters overview");
        };
        assert_eq!(
            OceanViewport { origin: ocean }.center_tile(&session.game.map().geometry()),
            detailed_center
        );

        map.view.scroll(&session.game, MapEdges::RIGHT);
        let StrategicView::Overview { origin: ocean } = map.view else {
            panic!("scroll keeps overview");
        };
        let ocean_center =
            OceanViewport { origin: ocean }.center_tile(&session.game.map().geometry());
        map.apply(&mut session.game, MapAction::ToggleZoom);
        let StrategicView::Detailed { origin } = map.view else {
            panic!("toggle zoom from overview enters detailed");
        };
        let (ocean_row, ocean_column) = session.game.map().geometry().row_column(ocean_center);
        let (detailed_row, detailed_column) = session
            .game
            .map()
            .geometry()
            .row_column(detailed_center_tile(&session.game, origin));
        assert_eq!(detailed_column, ocean_column);
        assert_eq!(detailed_row, ocean_row + 1);

        for action in [
            MapAction::Select(StrategicSelection::Army(None)),
            MapAction::ToggleZoom,
            MapAction::Select(StrategicSelection::Civilian(None)),
        ] {
            map.apply(&mut session.game, action);
        }
        assert!(
            !map.view.is_overview(),
            "switching into civilian from overview forces detailed"
        );
        map.apply(&mut session.game, MapAction::ToggleZoom);
        map.apply(
            &mut session.game,
            MapAction::Select(StrategicSelection::Civilian(None)),
        );
        assert!(
            map.view.is_overview(),
            "already-civilian select leaves overview in place"
        );
    }

    #[test]
    fn ocean_upper_left_wraps_or_clamps_like_retail() {
        let mut ocean = OceanViewport::default();
        ocean.set_upper_left(IVec2::new(-4, -4), &MapGeometry::new(MapTopology::Wrapping));
        assert_eq!(ocean.origin, IVec2::new(104, 0));
        ocean.set_upper_left(IVec2::new(100, 60), &MapGeometry::new(MapTopology::Bounded));
        assert_eq!(ocean.origin, IVec2::new(0x4c, 0x20));
    }

    #[test]
    fn activate_navy_selection_sets_mode_zone_force_and_centers() {
        let mut session = session();
        let mut map = StrategicMapSession::from_origin(TileId::new(1));
        map.view.set_upper_left(&session.game, IVec2::new(10, 10));
        let StrategicView::Detailed {
            origin: origin_before,
        } = map.view
        else {
            panic!("loaded origin is detailed");
        };
        let zone = OceanZoneId::new(0);
        let force = TaskForceId::new(1);

        map.select_navy(&mut session.game, zone, Some(force));

        assert_eq!(
            map.selection,
            StrategicSelection::Navy {
                zone: Some(zone),
                force: Some(force),
            }
        );
        let center = navy_zone_center_tile(&session.game, zone).expect("zone 0 has a center tile");
        let StrategicView::Detailed { origin } = map.view else {
            panic!("navy center stays on the detailed map");
        };
        assert_eq!(
            origin,
            session.game.map().viewport_origin_centered_on(center)
        );
        assert_ne!(origin, origin_before);
    }

    #[test]
    fn selection_cannot_carry_a_foreign_payload() {
        let mut session = session();
        let mut map = StrategicMapSession::from_origin(TileId::new(1));
        map.apply(
            &mut session.game,
            MapAction::Select(StrategicSelection::Civilian(Some(
                CivilianUnitId::from_serialized(1),
            ))),
        );
        map.apply(
            &mut session.game,
            MapAction::Select(StrategicSelection::Army(Some(ProvinceId::new(1)))),
        );
        assert_eq!(map.selection.civilian(), None);
        assert_eq!(map.selection.army(), Some(ProvinceId::new(1)));
        assert_eq!(map.selection.navy_zone(), None);
    }
}
