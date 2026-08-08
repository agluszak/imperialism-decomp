use crate::{
    CivilianUnitId, LaborPool, MajorNationTable, MilitaryUnitId, MissionId, NationId, NationTable,
    PendingActionTable, ProductionTable, ResourceTable, ShipId, TaskForceId, TileId,
};
use serde::{Deserialize, Serialize};

pub const AID_ALLOCATION_COUNT: usize = 0x170;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AidAllocationTable([i32; AID_ALLOCATION_COUNT]);

impl AidAllocationTable {
    pub const fn from_array(values: [i32; AID_ALLOCATION_COUNT]) -> Self {
        Self(values)
    }

    pub fn as_slice(&self) -> &[i32] {
        &self.0
    }
}

impl Default for AidAllocationTable {
    fn default() -> Self {
        Self([0; AID_ALLOCATION_COUNT])
    }
}

impl Serialize for AidAllocationTable {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.as_slice().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for AidAllocationTable {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let values = Vec::<i32>::deserialize(deserializer)?;
        let actual = values.len();
        let values = values.try_into().map_err(|_| {
            serde::de::Error::invalid_length(actual, &"exactly 368 aid-allocation entries")
        })?;
        Ok(Self(values))
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GameState {
    pub turn: TurnState,
    pub persistent_unit_id_counter: i32,
    pub world: WorldState,
    pub rng: RngState,
    pub nations: NationTable<Option<NationState>>,
    pub cities: MajorNationTable<Option<CityState>>,
    pub military_units: Vec<MilitaryUnitState>,
    pub civilian_units: Vec<CivilianUnitState>,
    pub ships: Vec<ShipState>,
    pub task_forces: Vec<TaskForceState>,
    pub missions: Vec<MissionState>,
    pub pending: PendingWorkState,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TurnState {
    pub scenario_map_index_plus_one: i32,
    pub economic_turn: i16,
    pub phase_code: i32,
    pub difficulty: i32,
    pub active_nation: i32,
    pub selected_nation: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WorldState {
    pub width: u16,
    pub height: u16,
    pub wraps_horizontally: bool,
    pub tiles: Vec<TileState>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TileState {
    pub terrain_kind: i8,
    pub owner_nation: Option<i8>,
    pub former_owner_nation: Option<i8>,
    pub province: Option<i16>,
    pub development_classes: i8,
    pub edge_resources: [Option<i8>; 2],
    pub rail_flags: u8,
    pub action_state: i16,
    pub active_flags: u16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RngState {
    pub crt_rand: u32,
    pub map_generation: u32,
    pub zone_status: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NationState {
    pub id: NationId,
    pub common: NationCommonState,
    pub data: NationData,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NationCommonState {
    pub encoded_nation_slot: i16,
    pub owner_nation: i16,
    pub treasury: i32,
    pub home_tile: i32,
    pub need_level_by_nation: NationTable<i16>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NationData {
    Major(MajorNationState),
    Minor,
}

impl NationState {
    pub const fn major(&self) -> Option<&MajorNationState> {
        match &self.data {
            NationData::Major(major) => Some(major),
            NationData::Minor => None,
        }
    }

    pub const fn major_mut(&mut self) -> Option<&mut MajorNationState> {
        match &mut self.data {
            NationData::Major(major) => Some(major),
            NationData::Minor => None,
        }
    }

    pub fn major_parts_mut(&mut self) -> Option<(&mut NationCommonState, &mut MajorNationState)> {
        match &mut self.data {
            NationData::Major(major) => Some((&mut self.common, major)),
            NationData::Minor => None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MajorNationState {
    pub diplomacy_eligible: bool,
    pub capacities: [i16; 4],
    pub grant_total_cost: i32,
    pub unfilled_trade_offer_count: i16,
    pub diplomacy_policy_by_nation: NationTable<i16>,
    pub diplomacy_grant_by_nation: NationTable<i16>,
    pub need_current_by_type: ResourceTable<i16>,
    pub need_target_by_type: ResourceTable<i16>,
    pub relation_delta_current: ResourceTable<i16>,
    pub purchased_items_by_resource: ResourceTable<i16>,
    pub item_potentials: ResourceTable<i16>,
    pub unfilled_trade_turns_by_resource: ResourceTable<i16>,
    pub transported_items_by_resource: ResourceTable<i16>,
    pub remembered_trade_offers_by_resource: ResourceTable<i16>,
    pub aid_allocation_matrix: AidAllocationTable,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CityState {
    pub nation: NationId,
    pub power_plant_upgrade_queued: bool,
    pub food_substitution_count: i16,
    pub starvation_population_loss: i16,
    pub serialized_state: i16,
    pub phase_counter: i16,
    pub metrics_0e: [i16; 30],
    pub metrics_4a: [i16; 9],
    pub order_count_by_type: [i16; 14],
    pub rolling_item_production_score: i32,
    pub low_production: bool,
    pub low_stock: bool,
    pub reserved_by_type: ResourceTable<i16>,
    pub home_town_tile: i16,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PopulationState {
    pub count: i16,
    pub count_float_bits: u32,
    pub strength: i16,
    pub extra: i16,
    pub phase_value: i16,
    pub baseline_labor: Option<LaborPool>,
    pub production_labor: Option<LaborPool>,
    pub pending_labor_delta: Option<LaborPool>,
    pub predicted_need_by_resource: ResourceTable<i16>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MilitaryUnitState {
    pub id: MilitaryUnitId,
    pub nation: NationId,
    pub roster_index: u32,
    pub unit_type: i16,
    pub stationed_province: i16,
    pub order: i32,
    pub order_target: i16,
    pub owner_nation: i16,
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
    pub roster_index: u32,
    pub unit_type: i16,
    pub tile: Option<TileId>,
    pub order: i32,
    pub order_target: i16,
    pub owner_nation: i16,
    pub roster_id: i16,
    pub registered: bool,
    pub remaining_turns: i16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShipState {
    pub id: ShipId,
    pub ship_type: i16,
    pub location: i16,
    pub task_force: Option<TaskForceId>,
    pub aggression: i32,
    pub nation: i16,
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
    pub id: TaskForceId,
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
    pub id: MissionId,
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
    pub turn_flow_status_flags: u32,
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
    pub nation: NationId,
    pub turn_events: Vec<TaggedValue>,
    pub proposals: Vec<TaggedValue>,
    pub turn_summary: Vec<[i16; 4]>,
    pub turn_start_events: Vec<TurnStartEventState>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TaggedValue {
    pub tag: i16,
    pub value: i16,
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
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GameCommand {
    PlaceTradeBid {
        nation: NationId,
        resource: crate::ResourceKind,
        amount: i16,
    },
    PurchaseItem {
        nation: NationId,
        resource: crate::ResourceKind,
        amount: i16,
        price: i16,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GameEvent {
    PhaseAdvanceRequested,
    CivilianUnitRecruited {
        id: CivilianUnitId,
        nation: NationId,
        unit_type: i16,
        tile: TileId,
    },
    MilitaryUnitRecruited {
        id: MilitaryUnitId,
        nation: NationId,
        unit_type: i16,
        province: i16,
        experience: i16,
    },
    NationPendingActionQueued {
        nation: NationId,
        action: u8,
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
        specialist: bool,
        unit_type: i16,
        requested: i16,
    },
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct StepOutcome {
    pub events: Vec<GameEvent>,
}
