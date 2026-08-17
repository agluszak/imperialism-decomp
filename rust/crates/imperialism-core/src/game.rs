use crate::*;
use indexmap::IndexMap;
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
    pub(crate) military_units: IndexMap<MilitaryUnitId, MilitaryUnitState>,
    pub(crate) civilian_units: IndexMap<CivilianUnitId, CivilianUnitState>,
    #[serde(default)]
    pub(crate) object_ids: ObjectIdAllocator,
    pub(crate) ships: IndexMap<ShipId, ShipState>,
    pub(crate) admirals: IndexMap<AdmiralId, AdmiralState>,
    pub(crate) task_forces: IndexMap<TaskForceId, TaskForceState>,
    pub(crate) missions: IndexMap<MissionId, MissionState>,
    pub(crate) news: NewsState,
    pub(crate) pending: PendingWorkState,
    /// `TArmyMgr::mapContextActionRecordList04`. Marker fields are omitted from `.imp`.
    #[serde(default)]
    pub(crate) battle_reports: Vec<crate::BattleReport>,
    /// Live interruptible-phase resume state. Not written to `.imp`.
    #[serde(default)]
    pub(crate) continuation: crate::turn_flow::TurnContinuation,
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
    pub admirals: Vec<AdmiralState>,
    pub task_forces: Vec<TaskForceState>,
    pub missions: Vec<MissionState>,
    pub news: NewsState,
    pub pending: PendingWorkState,
    pub battle_reports: Vec<crate::BattleReport>,
    pub continuation: crate::turn_flow::TurnContinuation,
}

impl GameState {
    /// Assembles authoritative state from loader-built parts.
    pub fn from_parts(parts: GameStateParts) -> Self {
        let mut object_ids = ObjectIdAllocator::from_existing(
            parts.ships.iter().map(|ship| ship.id),
            parts.task_forces.iter().map(|force| force.id),
        );
        let admirals = parts
            .admirals
            .into_iter()
            .map(|admiral| (object_ids.admiral(), admiral))
            .collect();
        let missions = parts
            .missions
            .into_iter()
            .map(|mission| (object_ids.mission(), mission))
            .collect();
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
            military_units: parts
                .military_units
                .into_iter()
                .map(|unit| (unit.id, unit))
                .collect(),
            civilian_units: parts
                .civilian_units
                .into_iter()
                .map(|unit| (unit.id, unit))
                .collect(),
            object_ids,
            ships: parts
                .ships
                .into_iter()
                .map(|ship| (ship.id, ship))
                .collect(),
            admirals,
            task_forces: parts
                .task_forces
                .into_iter()
                .map(|force| (force.id, force))
                .collect(),
            missions,
            news: parts.news,
            pending: parts.pending,
            battle_reports: parts.battle_reports,
            continuation: parts.continuation,
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

    pub fn military_units(
        &self,
    ) -> impl ExactSizeIterator<Item = (MilitaryUnitId, &MilitaryUnitState)> {
        self.military_units.iter().map(|(&id, unit)| (id, unit))
    }

    pub fn military_unit(&self, id: MilitaryUnitId) -> Option<&MilitaryUnitState> {
        self.military_units.get(&id)
    }

    pub fn civilian_units(
        &self,
    ) -> impl ExactSizeIterator<Item = (CivilianUnitId, &CivilianUnitState)> {
        self.civilian_units.iter().map(|(&id, unit)| (id, unit))
    }

    pub fn civilian_unit(&self, id: CivilianUnitId) -> Option<&CivilianUnitState> {
        self.civilian_units.get(&id)
    }

    pub fn ships(&self) -> impl ExactSizeIterator<Item = (ShipId, &ShipState)> {
        self.ships.iter().map(|(&id, ship)| (id, ship))
    }

    pub fn admirals(&self) -> impl ExactSizeIterator<Item = (AdmiralId, &AdmiralState)> {
        self.admirals.iter().map(|(&id, admiral)| (id, admiral))
    }

    pub fn task_forces(&self) -> impl ExactSizeIterator<Item = (TaskForceId, &TaskForceState)> {
        self.task_forces.iter().map(|(&id, force)| (id, force))
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

    pub const fn map_view_origin(&self) -> TileId {
        self.map_view_origin
    }

    pub const fn ocean(&self) -> &Ocean {
        &self.ocean
    }

    /// Applies the retail map edge-scroll mask to the strategic viewport.
    pub fn scroll_map_viewport(&mut self, edges: MapEdges) -> bool {
        let next = self
            .map
            .scrolled_viewport_origin(self.map_view_origin, edges);
        if next == self.map_view_origin {
            return false;
        }
        self.map_view_origin = next;
        true
    }

    pub fn set_map_view_origin(&mut self, origin: TileId) {
        self.map_view_origin = origin;
    }

    /// Retail mini-map `SetUpperLeft`: commit a toolbar-minimap click as the viewport origin.
    pub fn set_map_viewport_upper_left(&mut self, column: i32, row: i32) {
        self.map_view_origin = self.map.viewport_origin_from_upper_left(column, row);
    }

    /// Centers the strategic viewport on `tile` using retail 9-by-7 origin math.
    pub fn center_map_on(&mut self, tile: TileId) {
        self.map_view_origin = self.map.viewport_origin_centered_on(tile);
    }

    /// `ComputeRepresentativeTileIndexForNation` used by the strategic `X` key and mode-3 `C`.
    pub fn representative_tile_for_nation(&self, nation: NationId) -> Option<TileId> {
        self.map
            .representative_tile_index_for_nation(nation, self.nations.home_tile(nation), false)
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
        self.first_idle_civilian(nation)
            .and_then(|unit| unit.location().tile())
    }

    /// `TCivMgr::SelectFirstAvailableCivilianForNation` candidate (list order).
    pub fn first_idle_civilian(&self, nation: NationId) -> Option<&CivilianUnitState> {
        self.civilian_units
            .iter()
            .find(|unit| unit.nation() == nation && *unit.order() == CivilianWorkOrder::Idle)
    }

    /// Centers the strategic viewport on the first idle civilian for `nation`.
    ///
    /// Retail uses this from `TMapUberPicture::CycleMapInteractionSelectionAfterHandledClick`,
    /// not from every strategic-map enter.
    pub fn center_map_on_first_idle_civilian(&mut self) {
        if let Some(tile) = self.first_idle_civilian_tile(self.turn.active_nation) {
            self.center_map_on(tile);
        }
    }
}
