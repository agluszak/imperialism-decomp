use crate::{
    CivilianUnitId, CivilianUnitKind, CivilianUnitTable, CivilianWorkOrder, Difficulty,
    HexDirection, LaborPool, MajorNationTable, MapTopology, MilitaryUnitId, MilitaryUnitKind,
    MilitaryUnitTable, MinorNationTable, NationCapacities, NationId, NationTable,
    PendingActionTable, ProductionTable, ProvinceId, ResourceTable, RetailCrtRng, RetailLcg,
    STRATEGIC_TILE_COUNT, ShipId, ShipType, ShipTypeTable, TaskForceId, TileId, TileOwnerTag,
    TradeMarketState,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{Index, IndexMut};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GameState {
    pub turn: TurnState,
    pub unit_ids: UnitIdAllocator,
    pub world: StrategicMap,
    pub rng: RngState,
    pub market: TradeMarketState,
    pub nations: Nations,
    pub military_units: Vec<MilitaryUnitState>,
    pub civilian_units: Vec<CivilianUnitState>,
    pub ships: Vec<ShipState>,
    pub task_forces: Vec<TaskForceState>,
    pub missions: Vec<MissionState>,
    pub pending: PendingWorkState,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct UnitIdAllocator(i32);
impl UnitIdAllocator {
    pub const fn from_retail(value: i32) -> Self {
        Self(value)
    }
    pub const fn current(self) -> i32 {
        self.0
    }
    pub fn next_civilian(&mut self) -> CivilianUnitId {
        self.0 += 1;
        CivilianUnitId::new(self.0)
    }
    pub fn next_military(&mut self) -> MilitaryUnitId {
        self.0 += 1;
        MilitaryUnitId::new(self.0)
    }
}

/// Every nation slot, split into the two populations that carry different
/// domain state. Every major slot is a complete major nation; minor slots may
/// still be absent until their save projection is normalized separately.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Nations {
    pub(crate) majors: MajorNationTable<MajorNation>,
    pub(crate) minors: MinorNationTable<Option<MinorNation>>,
}

impl Nations {
    pub const fn new(
        majors: MajorNationTable<MajorNation>,
        minors: MinorNationTable<Option<MinorNation>>,
    ) -> Self {
        Self { majors, minors }
    }

    pub fn major(&self, nation: crate::MajorNationId) -> &MajorNation {
        &self.majors[nation]
    }

    pub fn major_mut(&mut self, nation: crate::MajorNationId) -> &mut MajorNation {
        &mut self.majors[nation]
    }

    pub fn city(&self, nation: crate::MajorNationId) -> &CityState {
        &self.majors[nation].city
    }

    pub fn city_mut(&mut self, nation: crate::MajorNationId) -> &mut CityState {
        &mut self.majors[nation].city
    }

    pub fn major_count(&self) -> usize {
        self.majors.iter().count()
    }

    pub fn majors(&self) -> impl ExactSizeIterator<Item = &MajorNation> {
        self.majors.iter()
    }

    pub fn minor_count(&self) -> usize {
        self.minors.iter().flatten().count()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MajorNation {
    pub(crate) common: NationCommonState,
    pub(crate) economy: GreatPowerState,
    pub(crate) city: CityState,
}

impl MajorNation {
    pub const fn from_parts(
        common: NationCommonState,
        economy: GreatPowerState,
        city: CityState,
    ) -> Self {
        Self {
            common,
            economy,
            city,
        }
    }

    /// Builds a random-game start major nation from the resolved starting
    /// `treasury`, whether the slot is the `human` player, and its scenario
    /// `city`. Homes are unset until capital selection places them.
    pub fn for_random_start(treasury: i32, human: bool, city: CityState) -> Self {
        Self {
            common: NationCommonState {
                treasury,
                home_tile: None,
                trade_policy_by_nation: NationTable::default(),
            },
            economy: GreatPowerState::for_random_start(human),
            city,
        }
    }

    pub const fn common(&self) -> &NationCommonState {
        &self.common
    }

    pub const fn economy(&self) -> &GreatPowerState {
        &self.economy
    }

    pub const fn city(&self) -> &CityState {
        &self.city
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MinorNation {
    pub common: NationCommonState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TurnState {
    pub scenario_map: Option<ScenarioMapId>,
    pub economic_turn: i32,
    pub phase: PhaseCode,
    pub difficulty: Difficulty,
    pub active_nation: NationId,
    pub selected_nation: NationId,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ScenarioMapId(u16);
impl ScenarioMapId {
    pub const fn new(index: u16) -> Self {
        Self(index)
    }

    pub const fn index(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PhaseCode(i32);
impl PhaseCode {
    pub const CAPITAL_SELECTION: Self = Self(2);
    pub const PRE_MAP: Self = Self(3);
    pub const HOME_PLACEMENT: Self = Self(4);
    pub const STRATEGIC_MAP: Self = Self(5);
    pub const TURN: Self = Self(6);
    pub const fn from_retail(value: i32) -> Self {
        Self(value)
    }
    pub const fn retail(self) -> i32 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StrategicMap {
    topology: MapTopology,
    tiles: Box<[TileState]>,
}

impl<'de> Deserialize<'de> for StrategicMap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedStrategicMap {
            topology: MapTopology,
            tiles: Box<[TileState]>,
        }

        let map = SerializedStrategicMap::deserialize(deserializer)?;
        Self::new(map.topology, map.tiles).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("strategic map has {actual} tiles; expected {STRATEGIC_TILE_COUNT}")]
pub struct StrategicMapSizeError {
    pub actual: usize,
}

impl StrategicMap {
    pub fn new(
        topology: MapTopology,
        tiles: impl Into<Box<[TileState]>>,
    ) -> Result<Self, StrategicMapSizeError> {
        let tiles = tiles.into();
        if tiles.len() != STRATEGIC_TILE_COUNT {
            return Err(StrategicMapSizeError {
                actual: tiles.len(),
            });
        }
        Ok(Self { topology, tiles })
    }

    /// Accepts tiles derived one-for-one from an already validated generated map.
    pub(crate) fn from_generated_tiles(topology: MapTopology, tiles: Box<[TileState]>) -> Self {
        debug_assert_eq!(tiles.len(), STRATEGIC_TILE_COUNT);
        Self { topology, tiles }
    }

    pub const fn geometry(&self) -> crate::MapGeometry {
        crate::MapGeometry::new(self.topology)
    }

    pub const fn topology(&self) -> MapTopology {
        self.topology
    }

    pub const fn len(&self) -> usize {
        STRATEGIC_TILE_COUNT
    }

    pub const fn is_empty(&self) -> bool {
        false
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &TileState> {
        self.tiles.iter()
    }
}

impl Index<TileId> for StrategicMap {
    type Output = TileState;

    fn index(&self, index: TileId) -> &Self::Output {
        &self.tiles[usize::from(index.get())]
    }
}

impl IndexMut<TileId> for StrategicMap {
    fn index_mut(&mut self, index: TileId) -> &mut Self::Output {
        &mut self.tiles[usize::from(index.get())]
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TileState {
    pub terrain: TerrainKind,
    pub owner_nation: Option<TileOwnerTag>,
    pub former_owner_nation: Option<TileOwnerTag>,
    pub province: Option<ProvinceId>,
    pub development: TileDevelopment,
    pub edge_resources: [Option<crate::ResourceKind>; 2],
    /// Completed directional transport links from this tile.
    pub transport_links: TileTransportLinks,
    /// Directional rail sections that have been ordered but not yet completed.
    pub pending_rail_links: TileTransportLinks,
    pub action: Option<TileAction>,
    pub flags: TileFlags,
    pub region: Option<RegionId>,
    pub river: Option<RiverSegment>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[repr(u8)]
#[serde(rename_all = "snake_case")]
pub enum TerrainKind {
    Plains,
    Forest,
    Hills,
    Mountain,
    Swamp,
    Water,
    Desert,
    Farmland,
}

impl TerrainKind {
    pub const fn from_retail(value: i8) -> Option<Self> {
        match value {
            0 => Some(Self::Plains),
            1 => Some(Self::Forest),
            2 => Some(Self::Hills),
            3 => Some(Self::Mountain),
            4 => Some(Self::Swamp),
            5 => Some(Self::Water),
            6 => Some(Self::Desert),
            7 => Some(Self::Farmland),
            _ => None,
        }
    }

    pub const fn retail(self) -> i8 {
        self as i8
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TileAction(i16);

impl<'de> Deserialize<'de> for TileAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = i16::deserialize(deserializer)?;
        Self::try_from_retail(value)
            .ok_or_else(|| serde::de::Error::custom("tile action -1 is represented by None"))
    }
}

impl TileAction {
    pub const fn try_from_retail(value: i16) -> Option<Self> {
        if value == -1 { None } else { Some(Self(value)) }
    }

    pub const fn retail(self) -> i16 {
        self.0
    }
}

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(transparent)]
    pub struct TileFlags: u16 {
        /// Set by `ResetTileToBaseTransportFlag`; consumers use this as the base-transport test.
        const BASE_TRANSPORT = 1 << 0;
        const RECRUITMENT_RESERVED = 1 << 1;
        /// Set by `SetProvinceCapitalTileFlagBit08`, which also advances the province fort level.
        const PROVINCE_CAPITAL_FORTIFICATION = 1 << 3;
        /// The city marker bit tested independently by map and unit consumers.
        const CITY_MARKER = 1 << 5;

        /// Complete state written for a fallback or re-anchored province capital.
        const PROVINCE_ANCHOR_STATE = 0x22;
        /// Complete state written for a minor nation's home tile.
        const MINOR_HOME_STATE = 0x21;
        /// Complete state written by `PlaceCity`.
        const PLACED_CITY_STATE = 0x37;
    }
}

impl TileFlags {
    pub fn has_base_transport(self) -> bool {
        self.contains(Self::BASE_TRANSPORT)
    }

    pub fn is_city(self) -> bool {
        self.contains(Self::CITY_MARKER)
    }

    pub fn clear_city_marker(&mut self) {
        self.remove(Self::CITY_MARKER);
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RegionId(u8);

impl RegionId {
    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RiverSegment {
    sprite: u8,
    flow: Option<HexDirection>,
}

impl RiverSegment {
    pub(crate) const fn new(sprite: u8, flow: Option<HexDirection>) -> Self {
        Self { sprite, flow }
    }

    #[cfg(test)]
    pub(crate) const fn sprite(self) -> u8 {
        self.sprite
    }

    pub const fn flow_direction(self) -> Option<HexDirection> {
        self.flow
    }
}

impl Default for TileState {
    fn default() -> Self {
        Self {
            terrain: TerrainKind::Plains,
            owner_nation: None,
            former_owner_nation: None,
            province: None,
            development: TileDevelopment::default(),
            edge_resources: [None; 2],
            transport_links: TileTransportLinks::default(),
            pending_rail_links: TileTransportLinks::default(),
            action: None,
            flags: TileFlags::empty(),
            region: None,
            river: None,
        }
    }
}

bitflags::bitflags! {
    /// The six directional links that may leave a strategic-map tile.
    #[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
    pub struct TileTransportLinks: u8 {
        const NORTH_EAST = 1 << 0;
        const EAST = 1 << 1;
        const SOUTH_EAST = 1 << 2;
        const SOUTH_WEST = 1 << 3;
        const WEST = 1 << 4;
        const NORTH_WEST = 1 << 5;
    }
}

impl TileTransportLinks {
    pub(crate) const fn for_direction(direction: HexDirection) -> Self {
        match direction {
            HexDirection::NorthEast => Self::NORTH_EAST,
            HexDirection::East => Self::EAST,
            HexDirection::SouthEast => Self::SOUTH_EAST,
            HexDirection::SouthWest => Self::SOUTH_WEST,
            HexDirection::West => Self::WEST,
            HexDirection::NorthWest => Self::NORTH_WEST,
        }
    }

    pub(crate) fn insert_direction(&mut self, direction: HexDirection) {
        self.insert(Self::for_direction(direction));
    }
}

/// One independently-progressed resource-development channel on a map tile.
///
/// Retail stores both channels in one byte, but game rules operate on them as
/// separate levels.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct DevelopmentLevel(u8);

impl DevelopmentLevel {
    pub const ZERO: Self = Self(0);

    pub const fn new(value: u8) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u8 {
        self.0
    }

    pub(crate) fn advance(&mut self) {
        self.0 += 1;
    }
}

impl Default for DevelopmentLevel {
    fn default() -> Self {
        Self::ZERO
    }
}

/// The two resource-development channels and their discovery visibility.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TileDevelopment {
    pub surface: DevelopmentLevel,
    pub extractive: DevelopmentLevel,
    /// Major nations that can see the tile's resource information.
    pub resource_visible_to_majors: MajorNationTable<bool>,
}

impl Default for TileDevelopment {
    fn default() -> Self {
        Self {
            surface: DevelopmentLevel::ZERO,
            extractive: DevelopmentLevel::ZERO,
            resource_visible_to_majors: MajorNationTable::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RngState {
    pub crt_rand: RetailCrtRng,
    pub map_generation: RetailLcg,
    pub zone_status: RetailLcg,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NationCommonState {
    pub treasury: i32,
    pub home_tile: Option<TileId>,
    pub trade_policy_by_nation: NationTable<TradePolicyScore>,
}

/// A bilateral trade-preference score.
///
/// Retail recognizes several named steps, but save data can carry other
/// scores, so this is deliberately not a closed enum.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TradePolicyScore(i32);

impl TradePolicyScore {
    pub const NEUTRAL: Self = Self(100);
    pub const BOYCOTT: Self = Self(300);

    pub const fn new(score: i32) -> Self {
        Self(score)
    }

    pub(crate) const fn decrement_step(self, treasury: i32) -> Self {
        match self.0 {
            100 => Self(95),
            95 => Self(90),
            90 => Self(75),
            75 if treasury > 10_000 => Self(50),
            _ => self,
        }
    }
}

impl Default for TradePolicyScore {
    fn default() -> Self {
        Self::NEUTRAL
    }
}

/// A current diplomatic grant to one nation.
///
/// `None` in the owning table means no grant. A present zero-valued grant is
/// retained because it still participates in retail diplomacy processing.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiplomacyGrant {
    pub amount: i32,
    pub recurring: bool,
}

/// A proposed diplomatic relationship with one nation.
///
/// The retail save stores these as numeric proposal codes. The core keeps the
/// relationship meaning; absent entries have no current policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiplomacyPolicy {
    JoinEmpire,
    Alliance,
    NonAggressionPact,
    PeaceTreaty,
    DeclareWar,
    JoinEmpireWithWarEntanglements,
    BuildConsulate,
    BuildEmbassy,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GreatPowerState {
    pub controller: MajorNationController,
    pub capacities: NationCapacities,
    pub grant_total_cost: i32,
    pub unfilled_trade_offer_count: i16,
    pub diplomacy_policy_by_nation: NationTable<Option<DiplomacyPolicy>>,
    pub diplomacy_grants_by_nation: NationTable<Option<DiplomacyGrant>>,
    pub need_current_by_type: ResourceTable<i16>,
    pub need_target_by_type: ResourceTable<i16>,
    pub relation_delta_current: ResourceTable<i16>,
    pub purchased_items_by_resource: ResourceTable<i16>,
    pub item_potentials: ResourceTable<i16>,
    pub unfilled_trade_turns_by_resource: ResourceTable<i16>,
    pub transported_items_by_resource: ResourceTable<i16>,
    pub remembered_trade_offers_by_resource: ResourceTable<i16>,
    pub aid_allocation_by_minor_nation: MinorNationTable<ResourceTable<i32>>,
    pub budget_pool_base: i32,
    pub budget_pool_delta: i32,
    pub special_resource_trade_balance: i32,
    pub candidate_nation_flags: NationTable<u8>,
    pub scenario_initialized: bool,
    pub turn_finished: bool,
    pub pending_actions: PendingActionTable<PendingActionState>,
    pub diplomacy_budget_base: i32,
    pub escalation_counter: i16,
    pub pending_commitment_cost: i32,
    pub pressure_counter: i16,
    pub aid_allocation_total: i32,
    pub colony_boycott_flags: NationTable<u8>,
    pub military_expenses: i32,
}

impl GreatPowerState {
    /// The post-`IGreatPower`/`IAutoGreatPower` construction state a major nation
    /// carries at the random-game start boundary. Only the human is diplomacy
    /// eligible before capital selection.
    pub fn for_random_start(human: bool) -> Self {
        Self {
            controller: if human {
                MajorNationController::Human
            } else {
                MajorNationController::Computer
            },
            capacities: NationCapacities::from_array([0, 0, 0x0f, 0]),
            grant_total_cost: 0,
            unfilled_trade_offer_count: 0,
            diplomacy_policy_by_nation: NationTable::default(),
            diplomacy_grants_by_nation: NationTable::default(),
            need_current_by_type: ResourceTable::default(),
            need_target_by_type: ResourceTable::default(),
            relation_delta_current: ResourceTable::default(),
            purchased_items_by_resource: ResourceTable::default(),
            item_potentials: ResourceTable::default(),
            unfilled_trade_turns_by_resource: ResourceTable::default(),
            transported_items_by_resource: ResourceTable::default(),
            remembered_trade_offers_by_resource: ResourceTable::default(),
            aid_allocation_by_minor_nation: MinorNationTable::default(),
            budget_pool_base: 0,
            budget_pool_delta: 0,
            special_resource_trade_balance: 0,
            candidate_nation_flags: NationTable::default(),
            scenario_initialized: false,
            turn_finished: true,
            pending_actions: PendingActionTable::default(),
            diplomacy_budget_base: 20_000,
            escalation_counter: 0,
            pending_commitment_cost: 0,
            pressure_counter: 0,
            aid_allocation_total: 0,
            colony_boycott_flags: NationTable::default(),
            military_expenses: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MajorNationController {
    Human,
    Computer,
}
impl MajorNationController {
    pub const fn is_human(self) -> bool {
        matches!(self, Self::Human)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct PendingActionState {
    status: PendingActionStatus,
    payload: Option<i16>,
}

impl<'de> Deserialize<'de> for PendingActionState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedPendingActionState {
            status: PendingActionStatus,
            payload: Option<i16>,
        }

        let state = SerializedPendingActionState::deserialize(deserializer)?;
        if state.status == PendingActionStatus::None && state.payload.is_some() {
            return Err(serde::de::Error::custom(
                "an inactive pending action cannot have a payload",
            ));
        }
        Ok(Self {
            status: state.status,
            payload: state.payload,
        })
    }
}

impl PendingActionState {
    pub const fn new(status: PendingActionStatus, payload: Option<i16>) -> Self {
        assert!(
            !matches!(status, PendingActionStatus::None) || payload.is_none(),
            "an inactive pending action cannot have a payload"
        );
        Self { status, payload }
    }
    pub const fn status_only(status: PendingActionStatus) -> Self {
        Self::new(status, None)
    }
    pub const fn queued(payload: i16) -> Self {
        Self::new(PendingActionStatus::Queued, Some(payload))
    }
    pub const fn is_pending(self) -> bool {
        !matches!(self.status, PendingActionStatus::None)
    }
    pub fn has_reached(self, status: PendingActionStatus) -> bool {
        self.status.has_reached(status)
    }
    pub const fn status(self) -> PendingActionStatus {
        self.status
    }
    pub const fn payload(self) -> Option<i16> {
        self.payload
    }
    pub fn queue(&mut self, payload: i16) {
        self.status = PendingActionStatus::Queued;
        self.payload = Some(payload);
    }
    pub const fn level(self) -> Option<i16> {
        match self.status {
            PendingActionStatus::Queued => None,
            PendingActionStatus::None | PendingActionStatus::Level3 => Some(0),
            PendingActionStatus::Level4 => Some(1),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingActionStatus {
    #[default]
    None,
    Queued,
    Level3,
    Level4,
}
impl PendingActionStatus {
    pub fn has_reached(self, other: Self) -> bool {
        self >= other
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CityState {
    pub power_plant_upgrade_queued: bool,
    pub food_substitution_count: i16,
    pub starvation_population_loss: i16,
    pub serialized_state: i16,
    pub phase_counter: i16,
    /// Cumulative military recruit deltas by [`MilitaryUnitKind`].
    pub military_recruit_count_by_kind: MilitaryUnitTable<i16>,
    /// Cumulative civilian recruit deltas by [`CivilianUnitKind`].
    pub civilian_recruit_count_by_kind: CivilianUnitTable<i16>,
    pub ship_order_count_by_type: ShipTypeTable<i16>,
    pub rolling_item_production_score: i32,
    pub low_production: bool,
    pub low_stock: bool,
    pub reserved_by_type: ResourceTable<i16>,
    pub home_town_tile: Option<TileId>,
    pub power_available: i16,
    pub stockpile: Stockpile,
    pub production_orders: ProductionTable<i16>,
    pub production_accum: ProductionTable<i16>,
    pub production_flags: ProductionTable<u8>,
    pub production_current: ProductionTable<i16>,
    pub production_progress: ProductionTable<i16>,
    pub population_growth_penalty_ticks: i16,
    pub unmet_resource_retries: ResourceTable<i16>,
    pub consumed_production_input_by_type: ResourceTable<i16>,
    pub population: PopulationState,
}

impl CityState {
    /// Builds the scenario start city. `stockpile` and `production` come from
    /// the difficulty presets, `labor` is the `SetPopulation` triple, and only
    /// the human capital gets the Frog City marker at tile 0.
    pub fn for_random_start(
        stockpile: ResourceTable<i16>,
        production: ProductionTable<i16>,
        labor: LaborPool,
        human: bool,
    ) -> Self {
        Self {
            power_plant_upgrade_queued: false,
            food_substitution_count: 0,
            starvation_population_loss: 0,
            serialized_state: 0,
            phase_counter: 0,
            military_recruit_count_by_kind: MilitaryUnitTable::default(),
            civilian_recruit_count_by_kind: CivilianUnitTable::default(),
            ship_order_count_by_type: ShipTypeTable::default(),
            rolling_item_production_score: 0,
            low_production: false,
            low_stock: false,
            reserved_by_type: ResourceTable::default(),
            home_town_tile: human.then(|| TileId::new(0)),
            // Human Frog City marker sits at tile 0 without PlaceCity. AI
            // capitals are placed later once tile post-passes and frog-city
            // scoring land.
            power_available: 0,
            stockpile: Stockpile::from_table(stockpile),
            production_orders: production.clone(),
            production_accum: production,
            production_flags: ProductionTable::default(),
            production_current: ProductionTable::default(),
            production_progress: ProductionTable::default(),
            population_growth_penalty_ticks: 0,
            unmet_resource_retries: ResourceTable::default(),
            consumed_production_input_by_type: ResourceTable::default(),
            population: PopulationState::from_labor(labor),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Stockpile(ResourceTable<i16>);

impl<'de> Deserialize<'de> for Stockpile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(Self::from_table(ResourceTable::deserialize(deserializer)?))
    }
}

impl Stockpile {
    pub fn from_table(mut amounts: ResourceTable<i16>) -> Self {
        amounts
            .values_mut()
            .for_each(|amount| *amount = (*amount).max(0));
        Self(amounts)
    }
    pub fn amount(&self, resource: crate::ResourceKind) -> i16 {
        self.0[resource]
    }
    pub fn credit(&mut self, resource: crate::ResourceKind, amount: i16) {
        self.0[resource] = self.0[resource].saturating_add(amount).max(0);
    }
    pub fn debit_clamped(&mut self, resource: crate::ResourceKind, amount: i16) {
        self.0[resource] = self.0[resource].saturating_sub(amount).max(0);
    }
    pub fn set_nonnegative(&mut self, resource: crate::ResourceKind, amount: i16) {
        self.0[resource] = amount.max(0);
    }
    pub fn as_table(&self) -> &ResourceTable<i16> {
        &self.0
    }
    pub fn iter(&self) -> impl Iterator<Item = (crate::ResourceKind, &i16)> {
        self.0.iter()
    }
}

impl std::ops::Index<crate::ResourceKind> for Stockpile {
    type Output = i16;
    fn index(&self, resource: crate::ResourceKind) -> &Self::Output {
        &self.0[resource]
    }
}

#[cfg(test)]
impl std::ops::IndexMut<crate::ResourceKind> for Stockpile {
    fn index_mut(&mut self, resource: crate::ResourceKind) -> &mut Self::Output {
        &mut self.0[resource]
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PopulationState {
    pub(crate) count: i16,
    pub(crate) accumulator: PopulationAccumulator,
    pub(crate) strength: i16,
    pub(crate) extra: i16,
    pub(crate) strike_phase: StrikePhase,
    pub(crate) baseline_labor: LaborPool,
    pub(crate) production_labor: LaborPool,
    pub(crate) pending_labor_delta: LaborPool,
    pub(crate) predicted_need_by_resource: ResourceTable<i16>,
}

impl PopulationState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        count: i16,
        accumulator: PopulationAccumulator,
        strength: i16,
        extra: i16,
        strike_phase: StrikePhase,
        baseline_labor: LaborPool,
        production_labor: LaborPool,
        pending_labor_delta: LaborPool,
        predicted_need_by_resource: ResourceTable<i16>,
    ) -> Self {
        Self {
            count,
            accumulator,
            strength,
            extra,
            strike_phase,
            baseline_labor,
            production_labor,
            pending_labor_delta,
            predicted_need_by_resource,
        }
    }

    /// Builds a fresh population whose baseline and production bands both equal
    /// `labor`, with no pending reassignment. Mirrors the retail
    /// `SetPopulation`-time state used when a city first appears.
    pub fn from_labor(labor: LaborPool) -> Self {
        let count = labor.low + labor.medium + labor.high;
        Self::new(
            count,
            PopulationAccumulator::from_count(count),
            labor.strength(),
            0,
            StrikePhase::default(),
            labor,
            labor,
            LaborPool::default(),
            ResourceTable::default(),
        )
    }

    pub const fn count(&self) -> i16 {
        self.count
    }

    pub const fn accumulator(&self) -> PopulationAccumulator {
        self.accumulator
    }

    pub const fn strength(&self) -> i16 {
        self.strength
    }

    pub const fn baseline_labor(&self) -> LaborPool {
        self.baseline_labor
    }
}

/// A finite semantic population total.
///
/// The retail save stores its IEEE-754 bits, but core state exposes the value
/// itself. The retained bits preserve exact arithmetic between rule steps.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PopulationAccumulator(u32);

impl PopulationAccumulator {
    pub fn new(value: f32) -> Option<Self> {
        value.is_finite().then_some(Self(value.to_bits()))
    }

    #[cfg(test)]
    pub(crate) fn from_bits(bits: u32) -> Self {
        Self::new(f32::from_bits(bits)).expect("population accumulator stays finite")
    }

    pub fn from_count(count: i16) -> Self {
        Self(f32::from(count).to_bits())
    }

    pub fn get(self) -> f32 {
        f32::from_bits(self.0)
    }
    pub fn add(&mut self, amount: f32) {
        let total = self.get() + amount;
        assert!(
            total.is_finite(),
            "population accumulator must remain finite"
        );
        self.0 = total.to_bits();
    }
    pub fn remove(&mut self, amount: i16) {
        self.0 = (self.get() - f32::from(amount)).to_bits();
    }
}

impl Serialize for PopulationAccumulator {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.get().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PopulationAccumulator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = f32::deserialize(deserializer)?;
        Self::new(value)
            .ok_or_else(|| serde::de::Error::custom("population accumulator must be finite"))
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[repr(u8)]
pub enum StrikePhase {
    #[default]
    Clothing,
    Furniture,
    Hardware,
    Arms,
}

impl StrikePhase {
    pub const fn from_retail(value: i16) -> Option<Self> {
        match value {
            0 => Some(Self::Clothing),
            1 => Some(Self::Furniture),
            2 => Some(Self::Hardware),
            3 => Some(Self::Arms),
            _ => None,
        }
    }
    pub const fn retail(self) -> i16 {
        self as i16
    }
    pub const fn index(self) -> usize {
        self as usize
    }
    pub const fn next(self) -> Self {
        match self {
            Self::Clothing => Self::Furniture,
            Self::Furniture => Self::Hardware,
            Self::Hardware => Self::Arms,
            Self::Arms => Self::Clothing,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MilitaryUnitState {
    pub(crate) id: MilitaryUnitId,
    pub(crate) nation: NationId,
    pub(crate) unit_type: MilitaryUnitKind,
    pub(crate) stationed_province: Option<ProvinceId>,
    pub(crate) order: MilitaryOrder,
    pub(crate) owner_nation: NationId,
    pub(crate) roster_id: i16,
    pub(crate) registered: bool,
    pub(crate) name: String,
    pub(crate) strength: i16,
    pub(crate) era: i16,
    pub(crate) experience: i16,
    pub(crate) battle_flags: i16,
}

impl MilitaryUnitState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: MilitaryUnitId,
        nation: NationId,
        unit_type: MilitaryUnitKind,
        stationed_province: Option<ProvinceId>,
        order: MilitaryOrder,
        owner_nation: NationId,
        roster_id: i16,
        registered: bool,
        name: String,
        strength: i16,
        era: i16,
        experience: i16,
        battle_flags: i16,
    ) -> Self {
        Self {
            id,
            nation,
            unit_type,
            stationed_province,
            order,
            owner_nation,
            roster_id,
            registered,
            name,
            strength,
            era,
            experience,
            battle_flags,
        }
    }

    pub const fn id(&self) -> MilitaryUnitId {
        self.id
    }

    pub const fn nation(&self) -> NationId {
        self.nation
    }

    pub const fn unit_type(&self) -> MilitaryUnitKind {
        self.unit_type
    }

    pub const fn order(&self) -> &MilitaryOrder {
        &self.order
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MilitaryOrder {
    Idle {
        targets: [Option<ProvinceId>; 3],
        target_mirrors: [Option<ProvinceId>; 3],
    },
    Retail {
        code: MilitaryOrderCode,
        target: Option<ProvinceId>,
        targets: [Option<ProvinceId>; 3],
        target_mirrors: [Option<ProvinceId>; 3],
    },
}

impl MilitaryOrder {
    pub const fn idle(
        targets: [Option<ProvinceId>; 3],
        target_mirrors: [Option<ProvinceId>; 3],
    ) -> Self {
        Self::Idle {
            targets,
            target_mirrors,
        }
    }

    pub const fn retail(
        code: MilitaryOrderCode,
        target: Option<ProvinceId>,
        targets: [Option<ProvinceId>; 3],
        target_mirrors: [Option<ProvinceId>; 3],
    ) -> Self {
        Self::Retail {
            code,
            target,
            targets,
            target_mirrors,
        }
    }

    pub const fn targets(&self) -> &[Option<ProvinceId>; 3] {
        match self {
            Self::Idle { targets, .. } | Self::Retail { targets, .. } => targets,
        }
    }

    pub const fn target_mirrors(&self) -> &[Option<ProvinceId>; 3] {
        match self {
            Self::Idle { target_mirrors, .. } | Self::Retail { target_mirrors, .. } => {
                target_mirrors
            }
        }
    }
}

/// An unrecovered retail military order discriminator retained only inside an
/// otherwise data-carrying order.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct MilitaryOrderCode(i32);
impl MilitaryOrderCode {
    pub const fn from_retail(value: i32) -> Self {
        Self(value)
    }
    pub const fn retail(self) -> i32 {
        self.0
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CivilianUnitState {
    pub(crate) id: CivilianUnitId,
    pub(crate) nation: NationId,
    pub(crate) unit_type: CivilianUnitKind,
    pub(crate) location: CivilianLocation,
    pub(crate) order: CivilianWorkOrder,
    pub(crate) owner_nation: NationId,
    pub(crate) roster_id: i16,
    pub(crate) registered: bool,
}

impl<'de> Deserialize<'de> for CivilianUnitState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedCivilianUnit {
            id: CivilianUnitId,
            nation: NationId,
            unit_type: CivilianUnitKind,
            location: CivilianLocation,
            order: CivilianWorkOrder,
            owner_nation: NationId,
            roster_id: i16,
            registered: bool,
        }

        let unit = SerializedCivilianUnit::deserialize(deserializer)?;
        Self::new(
            unit.id,
            unit.nation,
            unit.unit_type,
            unit.location,
            unit.order,
            unit.owner_nation,
            unit.roster_id,
            unit.registered,
        )
        .ok_or_else(|| serde::de::Error::custom("civilian order is inconsistent with location"))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum CivilianLocation {
    OnMap(TileId),
    OffMap,
}
impl CivilianLocation {
    pub const fn tile(self) -> Option<TileId> {
        match self {
            Self::OnMap(tile) => Some(tile),
            Self::OffMap => None,
        }
    }
}

impl CivilianUnitState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: CivilianUnitId,
        nation: NationId,
        unit_type: CivilianUnitKind,
        location: CivilianLocation,
        order: CivilianWorkOrder,
        owner_nation: NationId,
        roster_id: i16,
        registered: bool,
    ) -> Option<Self> {
        let valid_location = match order {
            CivilianWorkOrder::Idle
            | CivilianWorkOrder::Sleep
            | CivilianWorkOrder::Redeploy { .. } => true,
            CivilianWorkOrder::LayRail { segment, .. } => {
                location.tile() == Some(segment.destination())
            }
            _ => location.tile().is_some(),
        };
        valid_location.then_some(Self {
            id,
            nation,
            unit_type,
            location,
            order,
            owner_nation,
            roster_id,
            registered,
        })
    }
    pub const fn id(&self) -> CivilianUnitId {
        self.id
    }
    pub const fn nation(&self) -> NationId {
        self.nation
    }
    pub const fn location(&self) -> CivilianLocation {
        self.location
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShipState {
    pub ship_type: ShipType,
    pub location: i16,
    pub task_force: Option<TaskForceId>,
    pub aggression: i32,
    pub nation: NationId,
    pub name: String,
    pub strength: i16,
    pub experience: i16,
    pub selection: i32,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "target", rename_all = "snake_case")]
pub enum TaskForceTarget {
    None,
    Zone(SeaZoneId),
    Province(ProvinceId),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct SeaZoneId(i32);
impl SeaZoneId {
    pub const fn new(value: i32) -> Self {
        Self(value)
    }
    pub const fn get(self) -> i32 {
        self.0
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaskForceState {
    pub aggression: i32,
    pub order: i32,
    pub target: TaskForceTarget,
    pub location: i16,
    pub nation: i16,
    pub ship_counts: [i16; 4],
    pub ingot_tile: i16,
    pub flagship: Option<ShipId>,
    pub ships: Vec<SelectedShip>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SelectedShip {
    pub ship: ShipId,
    pub selected: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ArmyMissionState {
    pub present_location: i16,
    pub required_equipage_bits: [u32; 5],
    pub units: Vec<MilitaryUnitId>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NavyMissionState {
    pub target_zone: i16,
    pub resolved_port_zone: i16,
    pub selected_ship: Option<ShipId>,
    pub task_force: Option<TaskForceId>,
    pub state: i32,
    pub required_equipage_bits: [u32; 4],
    pub ships: Vec<SelectedShip>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AttackMissionState {
    pub army: ArmyMissionState,
    pub target_province: i16,
    pub amassing_province: i16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MissionData {
    AttackProvince(AttackMissionState),
    Invade {
        attack: AttackMissionState,
        beachhead: Option<NavyMissionState>,
    },
    DefendProvince(ArmyMissionState),
    ControlSeaZone(NavyMissionState),
    Escort(NavyMissionState),
    ScatteredShips(NavyMissionState),
    BlockadePort {
        navy: NavyMissionState,
        port_zone: i16,
    },
    Beachhead(NavyMissionState),
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MissionState {
    pub nation: NationId,
    pub queue_index: u32,
    pub data: MissionData,
    pub source_nation: i16,
    pub path_marker: i16,
    pub state: u8,
    pub importance_bits: u32,
    pub marker: u8,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingWorkState {
    pub nations: MajorNationTable<NationPendingWork>,
    pub war_transitions: Vec<WarTransition>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WarTransition {
    pub first: NationId,
    pub second: NationId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NationPendingWork {
    pub turn_events: Vec<TaggedValue>,
    pub proposals: Vec<TaggedValue>,
    pub turn_summary: Vec<TurnSummary>,
    pub turn_start_events: Vec<TurnStartEvent>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaggedValue {
    pub tag: i16,
    pub value: i16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TurnSummary {
    MilitaryRecruit {
        turn_tick: i32,
        unit_type: MilitaryUnitKind,
        count: i16,
    },
}
impl TurnSummary {
    pub const fn order_key(self) -> i16 {
        match self {
            Self::MilitaryRecruit { .. } => 3,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TurnStartEvent {
    LandSale { tag: i32, sale: LandSale },
    Tagged { class: String, tag: i32 },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LandSale {
    pub province: ProvinceId,
    pub nation: NationId,
}

#[cfg(test)]
mod tests {
    use super::{
        PendingActionState, PendingActionStatus, PopulationAccumulator, Stockpile, TileAction,
        TileFlags,
    };
    use crate::{ResourceKind, ResourceTable};

    #[test]
    fn population_accumulator_exposes_a_finite_semantic_value() {
        let accumulator = PopulationAccumulator::new(7.5).unwrap();

        assert_eq!(accumulator.get(), 7.5);
        assert_eq!(serde_json::to_string(&accumulator).unwrap(), "7.5");
        assert!(PopulationAccumulator::new(f32::NAN).is_none());
        assert!(PopulationAccumulator::new(f32::INFINITY).is_none());
    }

    #[test]
    #[should_panic(expected = "population accumulator must remain finite")]
    fn population_accumulator_rejects_nonfinite_additions() {
        let mut accumulator = PopulationAccumulator::from_count(1);
        accumulator.add(f32::INFINITY);
    }

    #[test]
    fn stockpile_deserialization_normalizes_each_resource_once() {
        let serialized = serde_json::to_string(&ResourceTable::from_array([-1; 23])).unwrap();
        let stockpile: Stockpile = serde_json::from_str(&serialized).unwrap();

        assert_eq!(stockpile.amount(ResourceKind::Paper), 0);
        assert!(stockpile.iter().all(|(_, amount)| *amount >= 0));
    }

    #[test]
    fn pending_action_deserialization_rejects_a_payload_without_an_action() {
        let state = r#"{"status":"none","payload":1}"#;

        assert!(serde_json::from_str::<PendingActionState>(state).is_err());
    }

    #[test]
    fn pending_action_level_is_derived_from_status_not_payload() {
        assert_eq!(
            PendingActionState::status_only(PendingActionStatus::None).level(),
            Some(0)
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::Queued, Some(6)).level(),
            None
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::Level3, Some(6)).level(),
            Some(0)
        );
        assert_eq!(
            PendingActionState::new(PendingActionStatus::Level4, Some(6)).level(),
            Some(1)
        );
    }

    #[test]
    fn tile_action_deserialization_does_not_restore_the_no_action_sentinel() {
        assert!(serde_json::from_str::<TileAction>("-1").is_err());
    }

    #[test]
    fn tile_flags_keep_city_marker_and_complete_state_writes_separate() {
        assert!(TileFlags::PROVINCE_ANCHOR_STATE.is_city());
        assert!(TileFlags::MINOR_HOME_STATE.is_city());
        assert!(TileFlags::PLACED_CITY_STATE.is_city());
        assert!(!TileFlags::PROVINCE_ANCHOR_STATE.has_base_transport());
        assert!(TileFlags::MINOR_HOME_STATE.has_base_transport());

        let mut sibling = TileFlags::PLACED_CITY_STATE | TileFlags::PROVINCE_CAPITAL_FORTIFICATION;
        sibling.clear_city_marker();
        assert_eq!(sibling.bits(), 0x1f);
    }
}
