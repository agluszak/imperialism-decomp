use crate::{
    GameSnapshotV1, MilitaryUnitId, MissionId, NationId, ShipId, SnapshotArmyMission, SnapshotCity,
    SnapshotMajorNation, SnapshotMilitaryUnit, SnapshotMission, SnapshotNation,
    SnapshotNavyMission, SnapshotPopulation, SnapshotShip, SnapshotTaskForce,
    SnapshotValidationError, TaskForceId, TileSnapshot,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GameState {
    pub turn: TurnState,
    pub world: WorldState,
    pub rng: RngState,
    pub nations: Vec<Option<NationState>>,
    pub cities: Vec<Option<CityState>>,
    pub military_units: Vec<MilitaryUnitState>,
    pub ships: Vec<ShipState>,
    pub task_forces: Vec<TaskForceState>,
    pub missions: Vec<MissionState>,
    pub pending: PendingWorkState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TurnState {
    pub scenario_map_index_plus_one: i32,
    pub economic_turn: i32,
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
    pub need_level_by_nation: Vec<i16>,
    pub major: Option<MajorNationState>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MajorNationState {
    pub diplomacy_eligible: bool,
    pub capacities: [i16; 4],
    pub grant_total_cost: i32,
    pub unfilled_trade_offer_count: i16,
    pub diplomacy_policy_by_nation: Vec<i16>,
    pub diplomacy_grant_by_nation: Vec<i16>,
    pub need_current_by_type: Vec<i16>,
    pub need_target_by_type: Vec<i16>,
    pub relation_delta_current: Vec<i16>,
    pub purchased_items_by_resource: Vec<i16>,
    pub item_potentials: Vec<i16>,
    pub unfilled_trade_turns_by_resource: Vec<i16>,
    pub transported_items_by_resource: Vec<i16>,
    pub remembered_trade_offers_by_resource: Vec<i16>,
    pub aid_allocation_matrix: Vec<i32>,
    pub budget_pool_base: i32,
    pub budget_pool_delta: i32,
    pub candidate_nation_flags: Vec<u8>,
    pub scenario_initialized: bool,
    pub pending_action_status: Vec<i8>,
    pub pending_action_payload_by_action: Vec<i16>,
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
    pub reserved_by_type: Vec<i16>,
    pub home_town_tile: i16,
    pub power_available: i16,
    pub stock_by_type: Vec<i16>,
    pub production_orders: Vec<i16>,
    pub production_accum: Vec<i16>,
    pub production_flags: Vec<u8>,
    pub production_current: Vec<i16>,
    pub production_progress: Vec<i16>,
    pub population_growth_penalty_ticks: i16,
    pub unmet_resource_retries: Vec<i16>,
    pub consumed_production_input_by_type: Vec<i16>,
    pub population: PopulationState,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PopulationState {
    pub count: i16,
    pub count_float_bits: u32,
    pub strength: i16,
    pub extra: i16,
    pub phase_value: i16,
    pub baseline_labor: Option<[i16; 3]>,
    pub production_labor: Option<[i16; 3]>,
    pub pending_labor_delta: Option<[i16; 3]>,
    pub predicted_need_by_resource: Vec<i16>,
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
    pub defeated: bool,
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
    pub nations: Vec<NationPendingWork>,
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
pub enum GameCommand {}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum GameEvent {}

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
                economic_turn: snapshot.metadata.economic_turn,
                phase_code: snapshot.metadata.turn_state,
                difficulty: snapshot.metadata.difficulty,
                active_nation: snapshot.metadata.active_nation,
                selected_nation: snapshot.metadata.selected_nation,
            },
            world: WorldState {
                width: snapshot.world.width,
                height: snapshot.world.height,
                wraps_horizontally: snapshot.world.wrap != 0,
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
                nations: snapshot
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
        need_level_by_nation: required(snapshot.need_level_by_nation, "nation need levels")?,
        major: snapshot.major.map(MajorNationState::from),
    }))
}

impl From<SnapshotMajorNation> for MajorNationState {
    fn from(snapshot: SnapshotMajorNation) -> Self {
        Self {
            diplomacy_eligible: snapshot.diplomacy_eligible != 0,
            capacities: snapshot.capacities,
            grant_total_cost: snapshot.grant_total_cost,
            unfilled_trade_offer_count: snapshot.unfilled_trade_offer_count,
            diplomacy_policy_by_nation: snapshot.diplomacy_policy_by_nation,
            diplomacy_grant_by_nation: snapshot.diplomacy_grant_by_nation,
            need_current_by_type: snapshot.need_current_by_type,
            need_target_by_type: snapshot.need_target_by_type,
            relation_delta_current: snapshot.relation_delta_current,
            purchased_items_by_resource: snapshot.purchased_items_by_resource,
            item_potentials: snapshot.item_potentials,
            unfilled_trade_turns_by_resource: snapshot.unfilled_trade_turns_by_resource,
            transported_items_by_resource: snapshot.transported_items_by_resource,
            remembered_trade_offers_by_resource: snapshot.remembered_trade_offers_by_resource,
            aid_allocation_matrix: snapshot.aid_allocation_matrix,
            budget_pool_base: snapshot.budget_pool_base,
            budget_pool_delta: snapshot.budget_pool_delta,
            candidate_nation_flags: snapshot.candidate_nation_flags,
            scenario_initialized: snapshot.scenario_initialized != 0,
            pending_action_status: snapshot.pending_action_status,
            pending_action_payload_by_action: snapshot.pending_action_payload_by_action,
            diplomacy_budget_base: snapshot.diplomacy_budget_base,
            escalation_counter: snapshot.escalation_counter,
            pending_commitment_cost: snapshot.pending_commitment_cost,
            pressure_counter: snapshot.pressure_counter,
            aid_allocation_total: snapshot.aid_allocation_total,
            colony_boycott_flags: snapshot.colony_boycott_flags,
            military_expenses: snapshot.military_expenses,
        }
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
        reserved_by_type: required(snapshot.reserved_by_type, "city reservations")?,
        home_town_tile: required(snapshot.home_town_tile, "home town tile")?,
        power_available: required(snapshot.power_available, "available power")?,
        stock_by_type: required(snapshot.stock_by_type, "city stock")?,
        production_orders: required(snapshot.production_orders, "production orders")?,
        production_accum: required(snapshot.production_accum, "production accumulation")?,
        production_flags: required(snapshot.production_flags, "production flags")?,
        production_current: required(snapshot.production_current, "current production")?,
        production_progress: required(snapshot.production_progress, "production progress")?,
        population_growth_penalty_ticks: required(
            snapshot.population_growth_penalty_ticks,
            "population growth penalty",
        )?,
        unmet_resource_retries: required(snapshot.unmet_resource_retries, "resource retry counts")?,
        consumed_production_input_by_type: required(
            snapshot.consumed_production_input_by_type,
            "consumed production inputs",
        )?,
        population: PopulationState::from(required(snapshot.population, "population state")?),
    }))
}

impl From<SnapshotPopulation> for PopulationState {
    fn from(snapshot: SnapshotPopulation) -> Self {
        Self {
            count: snapshot.count,
            count_float_bits: snapshot.count_float_bits,
            strength: snapshot.strength,
            extra: snapshot.extra,
            phase_value: snapshot.phase_value,
            baseline_labor: snapshot.baseline_labor,
            production_labor: snapshot.production_labor,
            pending_labor_delta: snapshot.pending_labor_delta,
            predicted_need_by_resource: snapshot.predicted_need_by_resource,
        }
    }
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
        defeated: snapshot.defeated != 0,
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
