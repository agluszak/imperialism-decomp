use crate::{
    CivilianUnitId, GameSnapshotV1, LaborPool, MAJOR_NATION_COUNT, MajorNationTable,
    MilitaryUnitId, MissionId, NATION_COUNT, NationId, NationTable, PENDING_ACTION_COUNT,
    PendingActionTable, ProductionSlot, ProductionTable, ResourceKind, ResourceTable, ShipId,
    SnapshotArmyMission, SnapshotCity, SnapshotCivilianUnit, SnapshotMajorNation,
    SnapshotMilitaryUnit, SnapshotMission, SnapshotNation, SnapshotNavyMission, SnapshotPopulation,
    SnapshotShip, SnapshotTaskForce, SnapshotValidationError, TaskForceId, TileId, TileSnapshot,
};
use enum_map::Enum;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GameState {
    pub turn: TurnState,
    pub persistent_unit_id_counter: i32,
    pub world: WorldState,
    pub rng: RngState,
    pub nations: Vec<Option<NationState>>,
    pub cities: Vec<Option<CityState>>,
    pub military_units: Vec<MilitaryUnitState>,
    pub civilian_units: Vec<CivilianUnitState>,
    pub ships: Vec<ShipState>,
    pub task_forces: Vec<TaskForceState>,
    pub missions: Vec<MissionState>,
    pub pending: PendingWorkState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TurnState {
    pub scenario_map_index_plus_one: i32,
    pub economic_turn: i16,
    pub phase_code: i32,
    pub difficulty: i32,
    pub active_nation: i32,
    pub selected_nation: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorldState {
    pub width: u16,
    pub height: u16,
    pub wraps_horizontally: bool,
    pub tiles: Vec<TileState>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TileState {
    pub terrain_kind: i64,
    pub owner_nation: i64,
    pub former_owner_nation: i64,
    pub city_or_province_index: i64,
    pub development_classes: i64,
    pub edge_resources: [i64; 2],
    pub rail_flags: i64,
    pub action_state: i64,
    pub active_flags: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RngState {
    pub crt_rand: u32,
    pub map_generation: u32,
    pub zone_status: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NationKind {
    Major,
    Minor,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NationState {
    pub id: NationId,
    pub kind: NationKind,
    pub encoded_nation_slot: i16,
    pub owner_nation: i16,
    pub treasury: i32,
    pub home_tile: i32,
    pub need_level_by_nation: NationTable<i16>,
    pub major: Option<MajorNationState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
    pub aid_allocation_matrix: Vec<i32>,
    pub budget_pool_base: i32,
    pub budget_pool_delta: i32,
    pub special_resource_trade_balance: i32,
    pub candidate_nation_flags: Vec<u8>,
    pub scenario_initialized: bool,
    pub turn_finished: bool,
    pub pending_action_status: PendingActionTable<i8>,
    pub pending_action_payload_by_action: PendingActionTable<i16>,
    pub diplomacy_budget_base: i32,
    pub escalation_counter: i16,
    pub pending_commitment_cost: i32,
    pub pressure_counter: i16,
    pub aid_allocation_total: i32,
    pub colony_boycott_flags: Vec<u8>,
    pub military_expenses: i32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CityState {
    pub nation: NationId,
    pub power_plant_upgrade_queued: bool,
    pub food_substitution_count: i16,
    pub starvation_population_loss: i16,
    pub serialized_state: i16,
    pub phase_counter: i16,
    pub metrics_0e: Vec<i16>,
    pub metrics_4a: Vec<i16>,
    pub order_count_by_type: Vec<i16>,
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

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskForceTarget {
    None,
    Zone(i32),
    Province(i32),
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
    pub ships: Vec<(ShipId, bool)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MissionKind {
    AttackProvince,
    Invade,
    DefendProvince,
    ControlSeaZone,
    Escort,
    ScatteredShips,
    BlockadePort,
    Beachhead,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArmyMissionState {
    pub present_location: i16,
    pub required_equipage_bits: [u32; 5],
    pub units: Vec<MilitaryUnitId>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NavyMissionState {
    pub target_zone: i16,
    pub resolved_port_zone: i16,
    pub selected_ship: Option<ShipId>,
    pub task_force: Option<TaskForceId>,
    pub state: i32,
    pub required_equipage_bits: [u32; 4],
    pub ships: Vec<(ShipId, bool)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MissionState {
    pub id: MissionId,
    pub nation: NationId,
    pub queue_index: u32,
    pub kind: MissionKind,
    pub source_nation: i16,
    pub path_marker: i16,
    pub state: u8,
    pub importance_bits: u32,
    pub marker: u8,
    pub army: Option<ArmyMissionState>,
    pub navy: Option<NavyMissionState>,
    pub target_province: Option<i16>,
    pub amassing_province: Option<i16>,
    pub beachhead: Option<NavyMissionState>,
    pub blockade_port_zone: Option<i16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingWorkState {
    pub turn_flow_status_flags: u32,
    pub nations: MajorNationTable<NationPendingWork>,
    pub war_transitions: Vec<(NationId, NationId)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NationPendingWork {
    pub nation: NationId,
    pub turn_events: Vec<(i16, i16)>,
    pub proposals: Vec<(i16, i16)>,
    pub turn_summary: Vec<[i16; 4]>,
    pub turn_start_events: Vec<TurnStartEventState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TurnStartEventState {
    pub class: String,
    pub tag: i32,
    pub land_sale: Option<(i16, NationId)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct StepOutcome {
    pub events: Vec<GameEvent>,
}

impl TryFrom<GameSnapshotV1> for GameState {
    type Error = SnapshotValidationError;

    fn try_from(snapshot: GameSnapshotV1) -> Result<Self, Self::Error> {
        snapshot.verify_hashes()?;
        Ok(Self {
            turn: TurnState {
                scenario_map_index_plus_one: snapshot.metadata.scenario_map_index_plus_one,
                economic_turn: i16::try_from(snapshot.metadata.economic_turn).map_err(|_| {
                    SnapshotValidationError::Shape(format!(
                        "economic turn {} does not fit the retail signed 16-bit field",
                        snapshot.metadata.economic_turn
                    ))
                })?,
                phase_code: snapshot.metadata.turn_state,
                difficulty: snapshot.metadata.difficulty,
                active_nation: snapshot.metadata.active_nation,
                selected_nation: snapshot.metadata.selected_nation,
            },
            persistent_unit_id_counter: snapshot.metadata.persistent_unit_id_counter,
            world: WorldState {
                width: snapshot.world.width,
                height: snapshot.world.height,
                wraps_horizontally: snapshot.world.wraps_horizontally,
                tiles: snapshot
                    .world
                    .tiles
                    .into_iter()
                    .map(TileState::from)
                    .collect(),
            },
            rng: RngState {
                crt_rand: snapshot.rng.crt_rand_state,
                map_generation: snapshot.rng.map_generation_lcg,
                zone_status: snapshot.rng.zone_status_lcg,
            },
            nations: snapshot
                .nations
                .records
                .into_iter()
                .map(nation_state)
                .collect::<Result<_, _>>()?,
            cities: snapshot
                .economy
                .cities
                .into_iter()
                .map(city_state)
                .collect::<Result<_, _>>()?,
            military_units: snapshot
                .military
                .units
                .into_iter()
                .map(military_unit_state)
                .collect::<Result<_, _>>()?,
            civilian_units: snapshot
                .military
                .civilians
                .into_iter()
                .map(civilian_unit_state)
                .collect::<Result<_, _>>()?,
            ships: snapshot
                .military
                .ships
                .into_iter()
                .map(ship_state)
                .collect::<Result<_, _>>()?,
            task_forces: snapshot
                .military
                .task_forces
                .into_iter()
                .map(task_force_state)
                .collect::<Result<_, _>>()?,
            missions: snapshot
                .missions
                .records
                .into_iter()
                .map(mission_state)
                .collect::<Result<_, _>>()?,
            pending: PendingWorkState {
                turn_flow_status_flags: snapshot.pending.turn_flow_status_flags,
                nations: major_nation_table(
                    snapshot
                        .pending
                        .nations
                        .into_iter()
                        .map(|pending| NationPendingWork {
                            nation: NationId::new(pending.nation),
                            turn_events: pending
                                .turn_events
                                .into_iter()
                                .map(|record| (record[0], record[1]))
                                .collect(),
                            proposals: pending
                                .proposals
                                .into_iter()
                                .map(|record| (record[0], record[1]))
                                .collect(),
                            turn_summary: pending.turn_summary,
                            turn_start_events: pending
                                .turn_start_events
                                .into_iter()
                                .map(|event| TurnStartEventState {
                                    class: event.class,
                                    tag: event.tag,
                                    land_sale: event
                                        .land_sale
                                        .map(|record| (record[0], NationId::new(record[1] as u8))),
                                })
                                .collect(),
                        })
                        .collect(),
                    "pending nation records",
                )?,
                war_transitions: snapshot
                    .pending
                    .war_transitions
                    .into_iter()
                    .map(|pair| (NationId::new(pair[0] as u8), NationId::new(pair[1] as u8)))
                    .collect(),
            },
        })
    }
}

fn nation_state(snapshot: SnapshotNation) -> Result<Option<NationState>, SnapshotValidationError> {
    if !snapshot.present {
        return Ok(None);
    }
    let slot = snapshot.slot;
    let kind = if snapshot.kind == "major" {
        NationKind::Major
    } else {
        NationKind::Minor
    };
    Ok(Some(NationState {
        id: NationId::new(slot),
        kind,
        encoded_nation_slot: required(snapshot.encoded_nation_slot, "encoded nation slot")?,
        owner_nation: required(snapshot.owner_nation, "owner nation")?,
        treasury: required(snapshot.treasury, "treasury")?,
        home_tile: required(snapshot.home_tile, "home tile")?,
        need_level_by_nation: nation_table(
            required(snapshot.need_level_by_nation, "nation need levels")?,
            "nation need levels",
        )?,
        major: snapshot.major.map(MajorNationState::try_from).transpose()?,
    }))
}

impl TryFrom<SnapshotMajorNation> for MajorNationState {
    type Error = SnapshotValidationError;

    fn try_from(snapshot: SnapshotMajorNation) -> Result<Self, Self::Error> {
        Ok(Self {
            diplomacy_eligible: snapshot.diplomacy_eligible != 0,
            capacities: snapshot.capacities,
            grant_total_cost: snapshot.grant_total_cost,
            unfilled_trade_offer_count: snapshot.unfilled_trade_offer_count,
            diplomacy_policy_by_nation: nation_table(
                snapshot.diplomacy_policy_by_nation,
                "major nation diplomacy policy",
            )?,
            diplomacy_grant_by_nation: nation_table(
                snapshot.diplomacy_grant_by_nation,
                "major nation diplomacy grants",
            )?,
            need_current_by_type: resource_table(
                snapshot.need_current_by_type,
                "major nation current needs",
            )?,
            need_target_by_type: resource_table(
                snapshot.need_target_by_type,
                "major nation target needs",
            )?,
            relation_delta_current: resource_table(
                snapshot.relation_delta_current,
                "major nation relation deltas",
            )?,
            purchased_items_by_resource: resource_table(
                snapshot.purchased_items_by_resource,
                "major nation purchased items",
            )?,
            item_potentials: resource_table(
                snapshot.item_potentials,
                "major nation item potentials",
            )?,
            unfilled_trade_turns_by_resource: resource_table(
                snapshot.unfilled_trade_turns_by_resource,
                "major nation unfilled trade turns",
            )?,
            transported_items_by_resource: resource_table(
                snapshot.transported_items_by_resource,
                "major nation transported items",
            )?,
            remembered_trade_offers_by_resource: resource_table(
                snapshot.remembered_trade_offers_by_resource,
                "major nation remembered trade offers",
            )?,
            aid_allocation_matrix: snapshot.aid_allocation_matrix,
            budget_pool_base: snapshot.budget_pool_base,
            budget_pool_delta: snapshot.budget_pool_delta,
            special_resource_trade_balance: snapshot.special_resource_trade_balance,
            candidate_nation_flags: snapshot.candidate_nation_flags,
            scenario_initialized: snapshot.scenario_initialized != 0,
            turn_finished: snapshot.turn_finished != 0,
            pending_action_status: pending_action_table(
                snapshot.pending_action_status,
                "major nation pending action status",
            )?,
            pending_action_payload_by_action: pending_action_table(
                snapshot.pending_action_payload_by_action,
                "major nation pending action payloads",
            )?,
            diplomacy_budget_base: snapshot.diplomacy_budget_base,
            escalation_counter: snapshot.escalation_counter,
            pending_commitment_cost: snapshot.pending_commitment_cost,
            pressure_counter: snapshot.pressure_counter,
            aid_allocation_total: snapshot.aid_allocation_total,
            colony_boycott_flags: snapshot.colony_boycott_flags,
            military_expenses: snapshot.military_expenses,
        })
    }
}

fn city_state(snapshot: SnapshotCity) -> Result<Option<CityState>, SnapshotValidationError> {
    if !snapshot.present {
        return Ok(None);
    }
    Ok(Some(CityState {
        nation: NationId::new(snapshot.nation),
        power_plant_upgrade_queued: required(
            snapshot.power_plant_upgrade_queued,
            "power plant upgrade flag",
        )? != 0,
        food_substitution_count: required(
            snapshot.food_substitution_count,
            "food substitution count",
        )?,
        starvation_population_loss: required(
            snapshot.starvation_population_loss,
            "starvation population loss",
        )?,
        serialized_state: required(snapshot.serialized_state, "city serialized state")?,
        phase_counter: required(snapshot.phase_counter, "city phase counter")?,
        metrics_0e: required(snapshot.metrics_0e, "city metrics_0e")?,
        metrics_4a: required(snapshot.metrics_4a, "city metrics_4a")?,
        order_count_by_type: required(snapshot.order_count_by_type, "city order counts")?,
        rolling_item_production_score: required(
            snapshot.rolling_item_production_score,
            "rolling production score",
        )?,
        low_production: required(snapshot.low_production, "low production flag")? != 0,
        low_stock: required(snapshot.low_stock, "low stock flag")? != 0,
        reserved_by_type: resource_table(
            required(snapshot.reserved_by_type, "city reservations")?,
            "city reservations",
        )?,
        home_town_tile: required(snapshot.home_town_tile, "home town tile")?,
        power_available: required(snapshot.power_available, "available power")?,
        stock_by_type: resource_table(
            required(snapshot.stock_by_type, "city stock")?,
            "city stock",
        )?,
        production_orders: production_table(
            required(snapshot.production_orders, "production orders")?,
            "production orders",
        )?,
        production_accum: production_table(
            required(snapshot.production_accum, "production accumulation")?,
            "production accumulation",
        )?,
        production_flags: production_table(
            required(snapshot.production_flags, "production flags")?,
            "production flags",
        )?,
        production_current: production_table(
            required(snapshot.production_current, "current production")?,
            "current production",
        )?,
        production_progress: production_table(
            required(snapshot.production_progress, "production progress")?,
            "production progress",
        )?,
        population_growth_penalty_ticks: required(
            snapshot.population_growth_penalty_ticks,
            "population growth penalty",
        )?,
        unmet_resource_retries: resource_table(
            required(snapshot.unmet_resource_retries, "resource retry counts")?,
            "city resource retry counts",
        )?,
        consumed_production_input_by_type: resource_table(
            required(
                snapshot.consumed_production_input_by_type,
                "consumed production inputs",
            )?,
            "city consumed production inputs",
        )?,
        population: PopulationState::try_from(required(snapshot.population, "population state")?)?,
    }))
}

impl TryFrom<SnapshotPopulation> for PopulationState {
    type Error = SnapshotValidationError;

    fn try_from(snapshot: SnapshotPopulation) -> Result<Self, Self::Error> {
        Ok(Self {
            count: snapshot.count,
            count_float_bits: snapshot.count_float_bits,
            strength: snapshot.strength,
            extra: snapshot.extra,
            phase_value: snapshot.phase_value,
            baseline_labor: snapshot.baseline_labor.map(LaborPool::from),
            production_labor: snapshot.production_labor.map(LaborPool::from),
            pending_labor_delta: snapshot.pending_labor_delta.map(LaborPool::from),
            predicted_need_by_resource: resource_table(
                snapshot.predicted_need_by_resource,
                "population predicted needs",
            )?,
        })
    }
}

fn resource_table(
    values: Vec<i16>,
    field: &'static str,
) -> Result<ResourceTable<i16>, SnapshotValidationError> {
    let actual = values.len();
    let values: [i16; ResourceKind::LENGTH] = values.try_into().map_err(|_| {
        SnapshotValidationError::Shape(format!(
            "{field} has {actual} entries, expected {}",
            ResourceKind::LENGTH
        ))
    })?;
    Ok(ResourceTable::from_array(values))
}

fn nation_table<T>(
    values: Vec<T>,
    field: &'static str,
) -> Result<NationTable<T>, SnapshotValidationError> {
    let actual = values.len();
    let values: [T; NATION_COUNT] = values.try_into().map_err(|_| {
        SnapshotValidationError::Shape(format!(
            "{field} has {actual} entries, expected {NATION_COUNT}"
        ))
    })?;
    Ok(NationTable::from_array(values))
}

fn production_table<T>(
    values: Vec<T>,
    field: &'static str,
) -> Result<ProductionTable<T>, SnapshotValidationError> {
    let actual = values.len();
    let values: [T; ProductionSlot::COUNT] = values.try_into().map_err(|_| {
        SnapshotValidationError::Shape(format!(
            "{field} has {actual} entries, expected {}",
            ProductionSlot::COUNT
        ))
    })?;
    Ok(ProductionTable::from_array(values))
}

fn major_nation_table<T>(
    values: Vec<T>,
    field: &'static str,
) -> Result<MajorNationTable<T>, SnapshotValidationError> {
    let actual = values.len();
    let values: [T; MAJOR_NATION_COUNT] = values.try_into().map_err(|_| {
        SnapshotValidationError::Shape(format!(
            "{field} has {actual} entries, expected {MAJOR_NATION_COUNT}"
        ))
    })?;
    Ok(MajorNationTable::from_array(values))
}

fn pending_action_table<T>(
    values: Vec<T>,
    field: &'static str,
) -> Result<PendingActionTable<T>, SnapshotValidationError> {
    let actual = values.len();
    let values: [T; PENDING_ACTION_COUNT] = values.try_into().map_err(|_| {
        SnapshotValidationError::Shape(format!(
            "{field} has {actual} entries, expected {PENDING_ACTION_COUNT}"
        ))
    })?;
    Ok(PendingActionTable::from_array(values))
}

fn required<T>(value: Option<T>, label: &str) -> Result<T, SnapshotValidationError> {
    value.ok_or_else(|| SnapshotValidationError::Shape(format!("missing {label}")))
}

fn military_unit_state(
    snapshot: SnapshotMilitaryUnit,
) -> Result<MilitaryUnitState, SnapshotValidationError> {
    let persistent_id = u32::try_from(snapshot.persistent_id).map_err(|_| {
        SnapshotValidationError::Shape(format!(
            "invalid military unit id {}",
            snapshot.persistent_id
        ))
    })?;
    Ok(MilitaryUnitState {
        id: MilitaryUnitId::new(persistent_id),
        nation: NationId::new(snapshot.nation),
        roster_index: snapshot.roster_index,
        unit_type: snapshot.unit_type,
        stationed_province: snapshot.stationed_province,
        order: snapshot.order,
        order_target: snapshot.order_target,
        owner_nation: snapshot.owner_nation,
        roster_id: snapshot.roster_id,
        registered: snapshot.registered != 0,
        order_target_tiles: snapshot.order_target_tiles,
        order_target_mirrors: snapshot.order_target_mirrors,
        name: snapshot.name,
        strength: snapshot.strength,
        era: snapshot.era,
        experience: snapshot.experience,
        battle_flags: snapshot.battle_flags,
    })
}

fn civilian_unit_state(
    snapshot: SnapshotCivilianUnit,
) -> Result<CivilianUnitState, SnapshotValidationError> {
    let persistent_id = u32::try_from(snapshot.persistent_id).map_err(|_| {
        SnapshotValidationError::Shape(format!(
            "invalid civilian unit id {}",
            snapshot.persistent_id
        ))
    })?;
    let tile = if snapshot.tile < 0 {
        None
    } else {
        Some(TileId::new(u16::try_from(snapshot.tile).map_err(|_| {
            SnapshotValidationError::Shape(format!("invalid civilian tile {}", snapshot.tile))
        })?))
    };
    Ok(CivilianUnitState {
        id: CivilianUnitId::new(persistent_id),
        nation: NationId::new(snapshot.nation),
        roster_index: snapshot.roster_index,
        unit_type: snapshot.unit_type,
        tile,
        order: snapshot.order,
        order_target: snapshot.order_target,
        owner_nation: snapshot.owner_nation,
        roster_id: snapshot.roster_id,
        registered: snapshot.registered != 0,
        remaining_turns: snapshot.remaining_turns,
    })
}

fn ship_state(snapshot: SnapshotShip) -> Result<ShipState, SnapshotValidationError> {
    Ok(ShipState {
        id: ShipId::new(snapshot.index),
        ship_type: snapshot.r#type,
        location: snapshot.location,
        task_force: optional_id(snapshot.task_force, TaskForceId::new, "task force")?,
        aggression: snapshot.aggression,
        nation: snapshot.nation,
        name: snapshot.name,
        strength: snapshot.strength,
        experience: snapshot.experience,
        selection: snapshot.selection,
    })
}

fn task_force_state(
    snapshot: SnapshotTaskForce,
) -> Result<TaskForceState, SnapshotValidationError> {
    let target = if snapshot.target < 0 {
        TaskForceTarget::None
    } else if snapshot.target_kind == 1 {
        TaskForceTarget::Province(snapshot.target)
    } else {
        TaskForceTarget::Zone(snapshot.target)
    };
    let ships = snapshot
        .ships
        .into_iter()
        .map(|child| {
            let id = u32::try_from(child[0]).map_err(|_| {
                SnapshotValidationError::Shape(format!("invalid ship id {}", child[0]))
            })?;
            Ok((ShipId::new(id), child[1] != 0))
        })
        .collect::<Result<_, _>>()?;
    Ok(TaskForceState {
        id: TaskForceId::new(snapshot.index),
        aggression: snapshot.aggression,
        order: snapshot.order,
        target,
        location: snapshot.location,
        nation: snapshot.nation,
        ship_counts: snapshot.ship_counts,
        ingot_tile: snapshot.ingot_tile,
        flagship: optional_id(snapshot.flagship, ShipId::new, "flagship")?,
        ships,
    })
}

fn mission_state(snapshot: SnapshotMission) -> Result<MissionState, SnapshotValidationError> {
    let kind = match snapshot.class.as_str() {
        "TAttackProvinceMission" => MissionKind::AttackProvince,
        "TInvadeMission" => MissionKind::Invade,
        "TDefendProvinceMission" => MissionKind::DefendProvince,
        "TControlSeaZoneMission" => MissionKind::ControlSeaZone,
        "TEscortMission" => MissionKind::Escort,
        "TScatteredShipsMission" => MissionKind::ScatteredShips,
        "TBlockadePortMission" => MissionKind::BlockadePort,
        "TBeachheadMission" => MissionKind::Beachhead,
        class => {
            return Err(SnapshotValidationError::Shape(format!(
                "unsupported mission class {class}"
            )));
        }
    };
    let (target_province, amassing_province) = snapshot
        .attack
        .map(|attack| (Some(attack.target_province), Some(attack.amassing_province)))
        .unwrap_or((None, None));
    Ok(MissionState {
        id: MissionId::new(snapshot.index),
        nation: NationId::new(snapshot.nation),
        queue_index: snapshot.queue_index,
        kind,
        source_nation: snapshot.source_nation,
        path_marker: snapshot.path_marker,
        state: snapshot.state,
        importance_bits: snapshot.importance_bits,
        marker: snapshot.marker,
        army: snapshot.army.map(army_mission_state).transpose()?,
        navy: snapshot.navy.map(navy_mission_state).transpose()?,
        target_province,
        amassing_province,
        beachhead: snapshot.beachhead.map(navy_mission_state).transpose()?,
        blockade_port_zone: snapshot.blockade_port_zone,
    })
}

fn army_mission_state(
    snapshot: SnapshotArmyMission,
) -> Result<ArmyMissionState, SnapshotValidationError> {
    Ok(ArmyMissionState {
        present_location: snapshot.present_location,
        required_equipage_bits: snapshot.required_equipage_bits,
        units: snapshot
            .units
            .into_iter()
            .map(|id| {
                u32::try_from(id).map(MilitaryUnitId::new).map_err(|_| {
                    SnapshotValidationError::Shape(format!("invalid military unit id {id}"))
                })
            })
            .collect::<Result<_, _>>()?,
    })
}

fn navy_mission_state(
    snapshot: SnapshotNavyMission,
) -> Result<NavyMissionState, SnapshotValidationError> {
    Ok(NavyMissionState {
        target_zone: snapshot.target_zone,
        resolved_port_zone: snapshot.resolved_port_zone,
        selected_ship: optional_id(snapshot.selected_ship, ShipId::new, "mission ship")?,
        task_force: optional_id(snapshot.task_force, TaskForceId::new, "mission task force")?,
        state: snapshot.state,
        required_equipage_bits: snapshot.required_equipage_bits,
        ships: snapshot
            .ships
            .into_iter()
            .map(|child| {
                u32::try_from(child[0])
                    .map(|id| (ShipId::new(id), child[1] != 0))
                    .map_err(|_| {
                        SnapshotValidationError::Shape(format!(
                            "invalid mission ship id {}",
                            child[0]
                        ))
                    })
            })
            .collect::<Result<_, _>>()?,
    })
}

fn optional_id<T>(
    value: i32,
    construct: impl FnOnce(u32) -> T,
    label: &str,
) -> Result<Option<T>, SnapshotValidationError> {
    if value < 0 {
        return Ok(None);
    }
    let value = u32::try_from(value)
        .map_err(|_| SnapshotValidationError::Shape(format!("invalid {label} id {value}")))?;
    Ok(Some(construct(value)))
}

impl From<TileSnapshot> for TileState {
    fn from(snapshot: TileSnapshot) -> Self {
        let fields = snapshot.0;
        Self {
            terrain_kind: fields[0],
            owner_nation: fields[1],
            former_owner_nation: fields[2],
            city_or_province_index: fields[3],
            development_classes: fields[4],
            edge_resources: [fields[5], fields[6]],
            rail_flags: fields[7],
            action_state: fields[8],
            active_flags: fields[9],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_tables_accept_only_their_canonical_wire_lengths() {
        assert!(resource_table(vec![0; ResourceKind::LENGTH], "resources").is_ok());
        assert!(resource_table(vec![0; ResourceKind::LENGTH - 1], "resources").is_err());

        assert!(nation_table(vec![0; NATION_COUNT], "nations").is_ok());
        assert!(nation_table(vec![0; NATION_COUNT - 1], "nations").is_err());

        assert!(production_table(vec![0; ProductionSlot::COUNT], "production").is_ok());
        assert!(production_table(vec![0; ProductionSlot::COUNT - 1], "production").is_err());

        assert!(major_nation_table(vec![0; MAJOR_NATION_COUNT], "major nations").is_ok());
        assert!(major_nation_table(vec![0; MAJOR_NATION_COUNT - 1], "major nations").is_err());

        assert!(pending_action_table(vec![0; PENDING_ACTION_COUNT], "actions").is_ok());
        assert!(pending_action_table(vec![0; PENDING_ACTION_COUNT - 1], "actions").is_err());
    }

    #[test]
    fn resource_table_preserves_canonical_retail_order() {
        let values: Vec<i16> = (0..ResourceKind::LENGTH as i16).collect();
        let table = resource_table(values.clone(), "resources").unwrap();
        let round_trip: Vec<i16> = crate::all_resources()
            .map(|resource| table[resource])
            .collect();
        assert_eq!(round_trip, values);
    }
}
