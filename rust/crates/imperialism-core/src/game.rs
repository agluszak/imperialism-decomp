use crate::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GameState {
    pub(crate) turn: TurnState,
    pub(crate) unit_ids: UnitIdAllocator,
    pub(crate) world: StrategicMap,
    pub(crate) provinces: ProvinceTable<ProvinceState>,
    pub(crate) port_zone_owners: Vec<PortZoneOwner>,
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

/// Construction-only parameter object for assembling a validated [`GameState`].
///
/// Formats loaders consume this immediately. It is not a second long-lived game
/// representation and must not be serialized or retained beside `GameState`.
#[derive(Clone, Debug)]
pub struct GameStateParts {
    pub turn: TurnState,
    pub unit_ids: UnitIdAllocator,
    pub world: StrategicMap,
    pub provinces: ProvinceTable<ProvinceState>,
    pub port_zone_owners: Vec<PortZoneOwner>,
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
    ///
    /// Callers must already have normalized retail values; territory-index
    /// validation remains the caller's responsibility after construction.
    pub fn from_parts(parts: GameStateParts) -> Self {
        Self {
            turn: parts.turn,
            unit_ids: parts.unit_ids,
            world: parts.world,
            provinces: parts.provinces,
            port_zone_owners: parts.port_zone_owners,
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

    pub const fn turn(&self) -> &TurnState {
        &self.turn
    }

    pub const fn unit_ids(&self) -> &UnitIdAllocator {
        &self.unit_ids
    }

    pub const fn world(&self) -> &StrategicMap {
        &self.world
    }

    pub fn tile_mut(&mut self, index: TileId) -> &mut TileState {
        self.world.tile_mut(index)
    }

    pub fn world_mut(&mut self) -> &mut StrategicMap {
        &mut self.world
    }

    pub const fn provinces(&self) -> &ProvinceTable<ProvinceState> {
        &self.provinces
    }

    pub const fn port_zone_owners(&self) -> &Vec<PortZoneOwner> {
        &self.port_zone_owners
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

    /// Enters the retail strategic-map view by selecting the active nation's first idle
    /// civilian and centering the 9-by-7 tile viewport on it.
    pub fn enter_strategic_map_view(&mut self) {
        const VIEWPORT_TILE_SPAN: i32 = 9;

        let Some(tile) = self
            .civilian_units
            .iter()
            .find(|unit| {
                unit.nation == self.turn.active_nation && unit.order == CivilianWorkOrder::Idle
            })
            .and_then(|unit| unit.location.tile())
        else {
            return;
        };

        let geometry = self.world.geometry();
        let (row, column) = geometry.row_column(tile);
        let mut column = i32::from(column) - VIEWPORT_TILE_SPAN / 2;
        if self.world.topology() == MapTopology::Bounded {
            column = column.clamp(1, 0x6e - VIEWPORT_TILE_SPAN);
        }
        if column < 0 {
            column += i32::from(STRATEGIC_MAP_WIDTH);
        } else if column >= i32::from(STRATEGIC_MAP_WIDTH) {
            column -= i32::from(STRATEGIC_MAP_WIDTH);
        }
        let row = (i32::from(row) - 3).clamp(0, 0x35);
        self.world.set_view_origin(
            geometry
                .tile(row as u16, column as u16)
                .expect("retail strategic-map viewport origin is inside the map"),
        );
    }
}
