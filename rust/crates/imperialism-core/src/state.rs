use crate::{
    CivilianUnitId, CivilianUnitKind, CivilianUnitTable, CivilianWorkOrder, Difficulty,
    HexDirection, IndustryActionSlot, IndustryActionTable, LaborPool, MajorNationTable,
    MilitaryUnitId, MilitaryUnitKind, MilitaryUnitTable, MinorNationTable, NationCapacityTable,
    NationId, NationTable, PendingActionTable, ProductionTable, ProvinceId, RecruitKind,
    ResourceTable, RetailCrtRng, RetailLcg, ShipId, TaskForceId, TileId, TileOwnerTag,
    TradeMarketState,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct GameState {
    pub turn: TurnState,
    pub persistent_unit_id_counter: i32,
    pub world: WorldState,
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

/// Every nation slot, split into the two retail populations that carry
/// different state. A present major always has both common and major-nation
/// state and may hold a city; a present minor carries only common state.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Nations {
    pub majors: MajorNationTable<Option<MajorNation>>,
    pub minors: MinorNationTable<Option<MinorNation>>,
}

impl Nations {
    pub fn major(&self, nation: crate::MajorNationId) -> Option<&MajorNation> {
        self.majors[nation].as_ref()
    }

    pub fn major_mut(&mut self, nation: crate::MajorNationId) -> Option<&mut MajorNation> {
        self.majors[nation].as_mut()
    }

    pub fn city(&self, nation: crate::MajorNationId) -> Option<&CityState> {
        self.majors[nation]
            .as_ref()
            .and_then(|major| major.city.as_ref())
    }

    pub fn city_mut(&mut self, nation: crate::MajorNationId) -> Option<&mut CityState> {
        self.majors[nation]
            .as_mut()
            .and_then(|major| major.city.as_mut())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MajorNation {
    pub common: NationCommonState,
    pub state: MajorNationState,
    pub city: Option<CityState>,
}

impl MajorNation {
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
            state: MajorNationState::for_random_start(human),
            city: Some(city),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MinorNation {
    pub common: NationCommonState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TurnState {
    pub scenario_map_index_plus_one: i32,
    pub economic_turn: i32,
    pub phase_code: i32,
    pub difficulty: Difficulty,
    pub active_nation: NationId,
    pub selected_nation: NationId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorldState {
    pub wraps_horizontally: bool,
    pub tiles: Vec<TileState>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TileState {
    pub terrain_kind: i8,
    pub owner_nation: Option<TileOwnerTag>,
    pub former_owner_nation: Option<TileOwnerTag>,
    pub province: Option<ProvinceId>,
    pub development: TileDevelopment,
    pub edge_resources: [Option<i8>; 2],
    /// Completed directional transport links from this tile.
    pub transport_links: TileTransportLinks,
    /// Directional rail sections that have been ordered but not yet completed.
    pub pending_rail_links: TileTransportLinks,
    pub action_state: i16,
    pub active_flags: u16,
    /// `TTerrainStateRecord::regionSubtypeTag05`. Unassigned is `-1`.
    pub region_marker: i8,
    /// `TTerrainStateRecord::riverSpriteCode`. Zero means no river.
    pub river_sprite_code: u8,
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

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
    #[serde(transparent)]
    pub struct DiplomacyGrantFlags: u8 {
        const RECURRING = 0b0000_0001;
    }
}

/// A current diplomatic grant to one nation.
///
/// `None` in the owning table means no grant. A present zero-valued grant is
/// retained because it still participates in retail diplomacy processing.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiplomacyGrant {
    pub amount: i32,
    pub flags: DiplomacyGrantFlags,
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
pub struct MajorNationState {
    pub diplomacy_eligible: bool,
    pub capacities: NationCapacityTable<i16>,
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
    pub pending_action_status: PendingActionTable<i8>,
    pub pending_action_payload_by_action: PendingActionTable<i16>,
    pub diplomacy_budget_base: i32,
    pub escalation_counter: i16,
    pub pending_commitment_cost: i32,
    pub pressure_counter: i16,
    pub aid_allocation_total: i32,
    pub colony_boycott_flags: NationTable<u8>,
    pub military_expenses: i32,
}

impl MajorNationState {
    /// The post-`IGreatPower`/`IAutoGreatPower` construction state a major nation
    /// carries at the random-game start boundary. Only the human is diplomacy
    /// eligible before capital selection.
    pub fn for_random_start(human: bool) -> Self {
        Self {
            diplomacy_eligible: human,
            capacities: NationCapacityTable::from_array([0, 0, 0x0f, 0]),
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
            pending_action_status: PendingActionTable::default(),
            pending_action_payload_by_action: PendingActionTable::default(),
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
    pub order_count_by_type: IndustryActionTable<i16>,
    pub rolling_item_production_score: i32,
    pub low_production: bool,
    pub low_stock: bool,
    pub reserved_by_type: ResourceTable<i16>,
    pub home_town_tile: Option<TileId>,
    pub power_available: i16,
    pub stock_by_type: ResourceTable<i16>,
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
    /// Builds the scenario start city. `stock_by_type` and `production` come from
    /// the difficulty presets, `labor` is the `SetPopulation` triple, and only
    /// the human capital gets the Frog City marker at tile 0.
    pub fn for_random_start(
        stock_by_type: ResourceTable<i16>,
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
            order_count_by_type: IndustryActionTable::default(),
            rolling_item_production_score: 0,
            low_production: false,
            low_stock: false,
            reserved_by_type: ResourceTable::default(),
            // Human Frog City marker sits at tile 0 without PlaceCity. AI
            // capitals are placed later once tile post-passes and frog-city
            // scoring land.
            home_town_tile: human.then(|| TileId::new(0)),
            power_available: 0,
            stock_by_type,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PopulationState {
    pub count: i16,
    pub count_float_bits: u32,
    pub strength: i16,
    pub extra: i16,
    pub phase_value: i16,
    pub baseline_labor: LaborPool,
    pub production_labor: LaborPool,
    pub pending_labor_delta: LaborPool,
    pub predicted_need_by_resource: ResourceTable<i16>,
}

impl PopulationState {
    /// Builds a fresh population whose baseline and production bands both equal
    /// `labor`, with no pending reassignment. Mirrors the retail
    /// `SetPopulation`-time state used when a city first appears.
    pub fn from_labor(labor: LaborPool) -> Self {
        let count = labor.low + labor.medium + labor.high;
        Self {
            count,
            count_float_bits: f32::from(count).to_bits(),
            strength: labor.strength(),
            extra: 0,
            phase_value: 0,
            baseline_labor: labor,
            production_labor: labor,
            pending_labor_delta: LaborPool::default(),
            predicted_need_by_resource: ResourceTable::default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MilitaryUnitState {
    pub id: MilitaryUnitId,
    pub nation: NationId,
    pub unit_type: MilitaryUnitKind,
    pub stationed_province: i16,
    pub order: i32,
    pub order_target: i16,
    pub owner_nation: NationId,
    pub roster_id: i16,
    pub registered: bool,
    pub order_target_tiles: [i16; 3],
    pub order_target_mirrors: [i16; 3],
    pub name: String,
    pub strength: i16,
    pub era: i16,
    pub experience: i16,
    pub battle_flags: i16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CivilianUnitState {
    pub id: CivilianUnitId,
    pub nation: NationId,
    pub unit_type: CivilianUnitKind,
    pub tile: Option<TileId>,
    pub order: CivilianWorkOrder,
    pub order_target: Option<TileId>,
    pub owner_nation: NationId,
    pub roster_id: i16,
    pub registered: bool,
    pub remaining_turns: i16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShipState {
    pub ship_type: IndustryActionSlot,
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
    Zone(i32),
    Province(i32),
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
    pub turn_start_events: Vec<TurnStartEventState>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaggedValue {
    pub tag: i16,
    pub value: i16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TurnSummary {
    pub turn_tick: i32,
    pub order_kind: i16,
    pub payload: i16,
    pub flags: i16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TurnStartEventState {
    pub class: String,
    pub tag: i32,
    pub land_sale: Option<LandSale>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LandSale {
    pub province: i16,
    pub nation: NationId,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GameEvent {
    PhaseAdvanceRequested,
    CivilianUnitRecruited {
        id: CivilianUnitId,
        nation: NationId,
        unit_type: CivilianUnitKind,
        tile: TileId,
    },
    MilitaryUnitRecruited {
        id: MilitaryUnitId,
        nation: NationId,
        unit_type: MilitaryUnitKind,
        province: i16,
        experience: i16,
    },
    NationPendingActionQueued {
        nation: NationId,
        action: crate::PendingActionKind,
        payload: i16,
    },
    TradeBidPlaced {
        nation: NationId,
        resource: crate::ResourceKind,
        amount: i16,
    },
    TradeBidsRemembered {
        nation: NationId,
    },
    TradeSettled {
        nation: NationId,
        resource: crate::ResourceKind,
        amount: i16,
        price: i16,
    },
    PurchasedItemsCommitted {
        nation: NationId,
    },
    RecruitmentAnnounced {
        nation: NationId,
        recruit_kind: RecruitKind,
        requested: i16,
    },
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct StepOutcome {
    pub events: Vec<GameEvent>,
}
