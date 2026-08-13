use crate::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GameState {
    pub(crate) turn: TurnState,
    pub(crate) unit_ids: UnitIdAllocator,
    pub(crate) map: MapMgr,
    /// Persisted strategic-map viewport origin. Retail saves this with the map blob.
    pub(crate) map_view_origin: TileId,
    pub(crate) ocean: Ocean,
    pub(crate) rng: RngState,
    pub(crate) market: TradeMarketState,
    pub(crate) technology: TechnologyState,
    pub(crate) diplomacy: DiplomacyState,
    pub(crate) nations: Nations,
    pub(crate) military_units: Vec<MilitaryUnitState>,
    pub(crate) civilian_units: Vec<CivilianUnitState>,
    pub(crate) ships: Vec<ShipState>,
    pub(crate) task_forces: Vec<TaskForceState>,
    pub(crate) missions: Vec<MissionState>,
    pub(crate) news: NewsState,
    pub(crate) pending: PendingWorkState,
    /// Live `TTradeMgr` deal cursor and pending Offer Sheet. Not part of `.imp`.
    #[serde(skip)]
    pub(crate) trade_session: Option<crate::trade_phase::TradeSession>,
}

/// Construction-only parameter object for assembling [`GameState`].
///
/// Formats loaders consume this immediately. It is not a second long-lived game
/// representation and must not be serialized or retained beside `GameState`.
#[derive(Clone, Debug)]
pub struct GameStateParts {
    pub turn: TurnState,
    pub unit_ids: UnitIdAllocator,
    pub map: MapMgr,
    pub map_view_origin: TileId,
    pub ocean: Ocean,
    pub rng: RngState,
    pub market: TradeMarketState,
    pub technology: TechnologyState,
    pub diplomacy: DiplomacyState,
    pub nations: Nations,
    pub military_units: Vec<MilitaryUnitState>,
    pub civilian_units: Vec<CivilianUnitState>,
    pub ships: Vec<ShipState>,
    pub task_forces: Vec<TaskForceState>,
    pub missions: Vec<MissionState>,
    pub news: NewsState,
    pub pending: PendingWorkState,
}

impl GameState {
    /// Assembles authoritative state from loader-built parts.
    pub fn from_parts(parts: GameStateParts) -> Self {
        Self {
            turn: parts.turn,
            unit_ids: parts.unit_ids,
            map: parts.map,
            map_view_origin: parts.map_view_origin,
            ocean: parts.ocean,
            rng: parts.rng,
            market: parts.market,
            technology: parts.technology,
            diplomacy: parts.diplomacy,
            nations: parts.nations,
            military_units: parts.military_units,
            civilian_units: parts.civilian_units,
            ships: parts.ships,
            task_forces: parts.task_forces,
            missions: parts.missions,
            news: parts.news,
            pending: parts.pending,
            trade_session: None,
        }
    }

    pub const fn turn(&self) -> &TurnState {
        &self.turn
    }

    pub const fn unit_ids(&self) -> &UnitIdAllocator {
        &self.unit_ids
    }

    pub const fn rng(&self) -> &RngState {
        &self.rng
    }

    pub const fn market(&self) -> &TradeMarketState {
        &self.market
    }

    pub const fn technology(&self) -> &TechnologyState {
        &self.technology
    }

    pub const fn diplomacy(&self) -> &DiplomacyState {
        &self.diplomacy
    }

    pub const fn nations(&self) -> &Nations {
        &self.nations
    }

    pub fn nation(&self, id: NationId) -> Option<&NationCommonState> {
        self.nations.common(id)
    }

    pub fn city(&self, id: MajorNationId) -> &CityState {
        self.nations.city(id)
    }

    pub fn military_units(&self) -> &[MilitaryUnitState] {
        &self.military_units
    }

    pub fn civilian_units(&self) -> &[CivilianUnitState] {
        &self.civilian_units
    }

    pub fn ships(&self) -> &[ShipState] {
        &self.ships
    }

    pub fn task_forces(&self) -> &[TaskForceState] {
        &self.task_forces
    }

    pub fn missions(&self) -> &[MissionState] {
        &self.missions
    }

    pub const fn news(&self) -> &NewsState {
        &self.news
    }

    pub const fn pending(&self) -> &PendingWorkState {
        &self.pending
    }

    pub const fn map(&self) -> &MapMgr {
        &self.map
    }

    pub fn map_mut(&mut self) -> &mut MapMgr {
        &mut self.map
    }

    pub const fn map_view_origin(&self) -> TileId {
        self.map_view_origin
    }

    pub const fn ocean(&self) -> &Ocean {
        &self.ocean
    }

    /// Applies the retail map edge-scroll mask to the strategic viewport.
    pub fn scroll_map_viewport(&mut self, edge_mask: u8) -> bool {
        let next = self
            .map
            .scrolled_viewport_origin(self.map_view_origin, edge_mask);
        if next == self.map_view_origin {
            return false;
        }
        self.map_view_origin = next;
        true
    }

    pub fn set_map_view_origin(&mut self, origin: TileId) {
        self.map_view_origin = origin;
    }

    /// Centers the strategic viewport on `tile` using retail 9-by-7 origin math.
    pub fn center_map_on(&mut self, tile: TileId) {
        self.map_view_origin = self.map.viewport_origin_centered_on(tile);
    }

    /// Sets whether a civilian unit kind is unlocked in the nation's University.
    pub fn set_university_civilian_available(
        &mut self,
        nation: MajorNationId,
        kind: crate::CivilianUnitKind,
        available: bool,
    ) {
        self.technology.city_capabilities_by_nation[nation]
            .university
            .available[kind] = available;
    }

    /// First idle civilian for `nation` that is on the map, if any.
    pub fn first_idle_civilian_tile(&self, nation: NationId) -> Option<TileId> {
        self.civilian_units
            .iter()
            .find(|unit| unit.nation == nation && unit.order == CivilianWorkOrder::Idle)
            .and_then(|unit| unit.location.tile())
    }
}
