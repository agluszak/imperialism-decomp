use crate::{
    CivilianUnitId, CivilianUnitKind, CivilianUnitTable, Difficulty, IndustryActionTable,
    LaborPool, MajorNationId, MajorNationTable, MilitaryUnitId, MilitaryUnitKind,
    MilitaryUnitTable, MinorNationId, MinorNationTable, NationCapacities, NationId, NationTable,
    PendingActionTable, ProductionTable, ProvinceId, ResourceTable, ShipId, TaskForceId, TileId,
    TileOwnerTag,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GameState {
    pub turn: TurnState,
    pub persistent_unit_id_counter: i32,
    pub world: WorldState,
    pub rng: RngState,
    pub major_nations: MajorNationTable<Option<MajorNation>>,
    pub minor_nations: MinorNationTable<Option<MinorNation>>,
    pub military_units: Vec<MilitaryUnitState>,
    pub civilian_units: Vec<CivilianUnitState>,
    pub ships: Vec<ShipState>,
    pub task_forces: Vec<TaskForceState>,
    pub missions: Vec<MissionState>,
    pub pending: PendingWorkState,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MajorNation {
    pub common: NationCommonState,
    pub state: MajorNationState,
    pub city: Option<CityState>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MinorNation {
    pub common: NationCommonState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum StateError {
    #[error("major nation {} is not present", .nation.get())]
    MissingMajorNation { nation: MajorNationId },
    #[error("major nation {} has no city state", .nation.get())]
    MissingCity { nation: MajorNationId },
    #[error("minor nation {} is not present", .nation.nation().get())]
    MissingMinorNation { nation: MinorNationId },
}

impl GameState {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn major(&self, id: MajorNationId) -> Result<&MajorNation, StateError> {
        self.major_nations[id]
            .as_ref()
            .ok_or(StateError::MissingMajorNation { nation: id })
    }

    pub(crate) fn major_mut(&mut self, id: MajorNationId) -> Result<&mut MajorNation, StateError> {
        self.major_nations[id]
            .as_mut()
            .ok_or(StateError::MissingMajorNation { nation: id })
    }

    pub(crate) fn major_city_parts_mut(
        &mut self,
        id: MajorNationId,
    ) -> Result<
        (
            &mut NationCommonState,
            &mut MajorNationState,
            &mut CityState,
        ),
        StateError,
    > {
        let major = self.major_nations[id]
            .as_mut()
            .ok_or(StateError::MissingMajorNation { nation: id })?;
        let city = major
            .city
            .as_mut()
            .ok_or(StateError::MissingCity { nation: id })?;
        Ok((&mut major.common, &mut major.state, city))
    }

    #[allow(dead_code)]
    pub(crate) fn minor(&self, id: MinorNationId) -> Result<&MinorNation, StateError> {
        self.minor_nations[id]
            .as_ref()
            .ok_or(StateError::MissingMinorNation { nation: id })
    }

    #[allow(dead_code)]
    pub(crate) fn minor_mut(&mut self, id: MinorNationId) -> Result<&mut MinorNation, StateError> {
        self.minor_nations[id]
            .as_mut()
            .ok_or(StateError::MissingMinorNation { nation: id })
    }
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
    pub development_classes: i8,
    pub edge_resources: [Option<i8>; 2],
    pub rail_flags: u8,
    pub action_state: i16,
    pub active_flags: u16,
    /// `TTerrainStateRecord::regionSubtypeTag05`. Unassigned is `-1`.
    pub region_marker: i8,
    /// `TTerrainStateRecord::riverSpriteCode`. Zero means no river.
    pub river_sprite_code: u8,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RngState {
    pub crt_rand: u32,
    pub map_generation: u32,
    pub zone_status: u32,
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
pub struct MajorNationState {
    pub diplomacy_eligible: bool,
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

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MilitaryUnitState {
    pub id: MilitaryUnitId,
    pub nation: NationId,
    pub unit_type: MilitaryUnitKind,
    pub stationed_province: i16,
    /// Opaque retail order code.
    pub raw_order_code: i32,
    pub order_target: i16,
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
    /// Opaque retail order code.
    pub raw_order_code: i32,
    pub order_target: i16,
    pub roster_id: i16,
    pub registered: bool,
    pub remaining_turns: i16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ShipState {
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

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::{Difficulty, LaborPool, ResourceTable};

    pub fn population() -> PopulationState {
        let labor = LaborPool::new(4, 2, 1);
        PopulationState {
            count: labor.low + labor.medium + labor.high,
            count_float_bits: f32::from(labor.low + labor.medium + labor.high).to_bits(),
            strength: labor.strength(),
            extra: 0,
            phase_value: 0,
            baseline_labor: labor,
            production_labor: labor,
            pending_labor_delta: LaborPool::default(),
            predicted_need_by_resource: ResourceTable::default(),
        }
    }

    pub fn city() -> CityState {
        CityState {
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
            home_town_tile: Some(TileId::new(0)),
            power_available: 0,
            stock_by_type: ResourceTable::default(),
            production_orders: ProductionTable::default(),
            production_accum: ProductionTable::default(),
            production_flags: ProductionTable::default(),
            production_current: ProductionTable::default(),
            production_progress: ProductionTable::default(),
            population_growth_penalty_ticks: 0,
            unmet_resource_retries: ResourceTable::default(),
            consumed_production_input_by_type: ResourceTable::default(),
            population: population(),
        }
    }

    pub fn major_nation_state() -> MajorNationState {
        MajorNationState {
            diplomacy_eligible: true,
            capacities: NationCapacities {
                available_merchant: 10,
                trade_offer: 4,
                transport: 15,
                reserved_transport: 0,
            },
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
            turn_finished: false,
            pending_action_status: PendingActionTable::default(),
            pending_action_payload_by_action: PendingActionTable::default(),
            diplomacy_budget_base: 0,
            escalation_counter: 0,
            pending_commitment_cost: 0,
            pressure_counter: 0,
            aid_allocation_total: 0,
            colony_boycott_flags: NationTable::default(),
            military_expenses: 0,
        }
    }

    pub fn major_nation() -> MajorNation {
        MajorNation {
            common: NationCommonState {
                treasury: 1_000,
                home_tile: Some(TileId::new(0)),
                trade_policy_by_nation: NationTable::default(),
            },
            state: major_nation_state(),
            city: Some(city()),
        }
    }

    pub fn game_state() -> GameState {
        let mut major_nations = MajorNationTable::default();
        major_nations[MajorNationId::new(6)] = Some(major_nation());
        GameState {
            turn: TurnState {
                scenario_map_index_plus_one: 0,
                economic_turn: 0,
                phase_code: 0,
                difficulty: Difficulty::Normal,
                active_nation: NationId::new(6),
                selected_nation: NationId::new(6),
            },
            persistent_unit_id_counter: 0,
            world: WorldState {
                wraps_horizontally: true,
                tiles: Vec::new(),
            },
            rng: RngState {
                crt_rand: 0,
                map_generation: 0,
                zone_status: 0,
            },
            major_nations,
            minor_nations: MinorNationTable::default(),
            military_units: Vec::new(),
            civilian_units: Vec::new(),
            ships: Vec::new(),
            task_forces: Vec::new(),
            missions: Vec::new(),
            pending: PendingWorkState {
                nations: MajorNationTable::from_fn(|_| NationPendingWork {
                    turn_events: Vec::new(),
                    proposals: Vec::new(),
                    turn_summary: Vec::new(),
                    turn_start_events: Vec::new(),
                }),
                war_transitions: Vec::new(),
            },
        }
    }
}
