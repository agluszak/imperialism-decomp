use crate::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GameState {
    pub(crate) turn: TurnState,
    pub(crate) unit_ids: UnitIdAllocator,
    pub map: MapMgr,
    pub ocean: Ocean,
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
        }
    }

    /// Restores session-only fields after projecting a save-backed differential capture.
    ///
    /// Retail `.imp` bytes carry the persistable bulk; the native oracle publishes the
    /// remaining live fields beside the save so complete `GameState` comparison stays exact.
    pub fn apply_save_backed_ephemeral(
        &mut self,
        turn: TurnState,
        unit_ids: UnitIdAllocator,
        rng: RngState,
        news: NewsState,
        pending: Option<PendingWorkState>,
        ai_development_pressure: Option<[Option<AiDevelopmentPressureState>; MAJOR_NATION_COUNT]>,
    ) {
        self.turn = turn;
        self.unit_ids = unit_ids;
        self.rng = rng;
        self.news = news;
        if let Some(pending) = pending {
            self.pending = pending;
        }
        if let Some(pressures) = ai_development_pressure {
            for (slot, pressure) in pressures.into_iter().enumerate() {
                let nation = MajorNationId::new(slot as u8);
                self.nations
                    .major_mut(nation)
                    .economy
                    .ai_development_pressure = pressure;
            }
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
