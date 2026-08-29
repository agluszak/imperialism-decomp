use crate::*;
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

/// Immutable retail catalogs used by simulation.
///
/// Loaded once for a session and owned beside the mutable [`GameState`]. Not
/// written to `.imp` saves; restore from retail data after load.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GameData {
    news_story_ids: Vec<i32>,
}

impl GameData {
    pub fn from_news_story_ids(news_story_ids: Vec<i32>) -> Self {
        Self { news_story_ids }
    }

    pub fn news_story_ids(&self) -> &[i32] {
        &self.news_story_ids
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GameState {
    pub(crate) turn: TurnState,
    pub(crate) unit_ids: UnitIdAllocator,
    pub(crate) map: MapMgr,
    pub(crate) ocean: Ocean,
    pub(crate) rng: RngState,
    pub(crate) market: TradeMarketState,
    pub(crate) technology: TechnologyState,
    pub(crate) diplomacy: DiplomacyState,
    pub(crate) nations: Nations,
    pub(crate) military_units: IndexMap<MilitaryUnitId, MilitaryUnitState>,
    pub(crate) civilian_units: IndexMap<CivilianUnitId, CivilianUnitState>,
    #[serde(default)]
    pub(crate) civilian_stack_order: Vec<CivilianUnitId>,
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
    /// Live interrupt/resume state for the turn driver. Not written to `.imp`.
    #[serde(default, rename = "continuation")]
    pub(crate) turn_flow: crate::turn_flow::TurnFlow,
    /// Immutable catalogs for this session. Restored from retail data on load.
    #[serde(skip)]
    pub(crate) data: GameData,
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
    pub ocean: Ocean,
    pub rng: RngState,
    pub market: TradeMarketState,
    pub technology: TechnologyState,
    pub diplomacy: DiplomacyState,
    pub nations: Nations,
    pub military_units: IndexMap<MilitaryUnitId, MilitaryUnitState>,
    pub civilian_units: IndexMap<CivilianUnitId, CivilianUnitState>,
    pub object_ids: ObjectIdAllocator,
    pub ships: IndexMap<ShipId, ShipState>,
    pub admirals: IndexMap<AdmiralId, AdmiralState>,
    pub task_forces: IndexMap<TaskForceId, TaskForceState>,
    pub missions: IndexMap<MissionId, MissionState>,
    pub news: NewsState,
    pub pending: PendingWorkState,
    pub battle_reports: Vec<crate::BattleReport>,
}

impl GameState {
    /// Assembles authoritative state from loader-built parts.
    pub fn from_parts(parts: GameStateParts) -> Self {
        let mut state = Self {
            turn: parts.turn,
            unit_ids: parts.unit_ids,
            map: parts.map,
            ocean: parts.ocean,
            rng: parts.rng,
            market: parts.market,
            technology: parts.technology,
            diplomacy: parts.diplomacy,
            nations: parts.nations,
            military_units: parts.military_units,
            civilian_units: parts.civilian_units,
            civilian_stack_order: Vec::new(),
            object_ids: parts.object_ids,
            ships: parts.ships,
            admirals: parts.admirals,
            task_forces: parts.task_forces,
            missions: parts.missions,
            news: parts.news,
            pending: parts.pending,
            battle_reports: parts.battle_reports,
            turn_flow: TurnFlow::Running,
            data: GameData::default(),
        };
        for force in state.task_forces.keys().copied().collect::<Vec<_>>() {
            if state.task_forces[&force].flagship.is_none() {
                state.elect_task_force_flagship(force);
            }
        }
        state.rebuild_civilian_stack_order();
        state
    }

    pub const fn game_data(&self) -> &GameData {
        &self.data
    }

    pub fn set_game_data(&mut self, data: GameData) {
        self.data = data;
    }

    pub const fn turn(&self) -> &TurnState {
        &self.turn
    }

    /// Restores runtime turn-flow state from the native oracle ephemeral overlay.
    #[doc(hidden)]
    pub fn restore_native_turn_flow(&mut self, flow: TurnFlow) {
        self.turn_flow = flow;
    }

    pub const fn unit_ids(&self) -> &UnitIdAllocator {
        &self.unit_ids
    }

    pub const fn rng(&self) -> &RngState {
        &self.rng
    }

    /// Retail UI animations consume the same process-global CRT `rand()` stream
    /// as gameplay code rather than owning a presentation-only generator.
    pub fn next_civilian_animation_rand(&mut self) -> i32 {
        self.rng.next_crt_rand()
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

    /// Retail's primary ship list, whose newest link is visited first.
    pub fn ships_in_retail_order(&self) -> impl ExactSizeIterator<Item = (ShipId, &ShipState)> {
        self.ships.iter().rev().map(|(&id, ship)| (id, ship))
    }

    pub fn admirals(&self) -> impl ExactSizeIterator<Item = (AdmiralId, &AdmiralState)> {
        self.admirals.iter().map(|(&id, admiral)| (id, admiral))
    }

    /// Retail's secondary admiral list, whose newest link is visited first.
    pub fn admirals_in_retail_order(
        &self,
    ) -> impl ExactSizeIterator<Item = (AdmiralId, &AdmiralState)> {
        self.admirals
            .iter()
            .rev()
            .map(|(&id, admiral)| (id, admiral))
    }

    pub fn task_forces(&self) -> impl ExactSizeIterator<Item = (TaskForceId, &TaskForceState)> {
        self.task_forces.iter().map(|(&id, force)| (id, force))
    }

    /// Retail's order queue, whose newest force is traversed first.
    pub fn task_forces_in_retail_order(
        &self,
    ) -> impl ExactSizeIterator<Item = (TaskForceId, &TaskForceState)> {
        self.task_forces
            .iter()
            .rev()
            .map(|(&id, force)| (id, force))
    }

    pub fn missions(&self) -> impl ExactSizeIterator<Item = (MissionId, &MissionState)> {
        self.missions.iter().map(|(&id, mission)| (id, mission))
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

    pub const fn ocean(&self) -> &Ocean {
        &self.ocean
    }

    /// `ComputeRepresentativeTileIndexForNation` used by the strategic `X` key and mode-3 `C`.
    pub fn representative_tile_for_nation(&self, nation: NationId) -> Option<TileId> {
        self.map
            .representative_tile_index_for_nation(nation, self.nations.home_tile(nation), false)
    }

    /// `TCountry::GetOrComputeOverlayAnchorTileIndex`: the country's diplomacy-map
    /// overlay anchor. Computed once (from the wrapped-world representative tile)
    /// and cached in `NationCommonState`, matching retail's lazy, serialized cache.
    pub fn overlay_anchor_for_nation(&mut self, nation: NationId) -> Option<TileId> {
        if let Some(anchor) = self.nations.common(nation)?.overlay_anchor_tile {
            return Some(anchor);
        }
        let home = self.nations.home_tile(nation);
        let computed = self
            .map
            .representative_tile_index_for_nation(nation, home, true);
        if let Some(common) = self.nations.common_mut(nation) {
            common.overlay_anchor_tile = computed;
        }
        computed
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
            .and_then(|(_, unit)| unit.location().tile())
    }

    /// `TCivMgr::SelectFirstAvailableCivilianForNation` candidate (list order).
    pub fn first_idle_civilian(
        &self,
        nation: NationId,
    ) -> Option<(CivilianUnitId, &CivilianUnitState)> {
        self.civilian_units.iter().find_map(|(&id, unit)| {
            (unit.nation() == nation && *unit.order() == CivilianWorkOrder::Idle)
                .then_some((id, unit))
        })
    }
}
