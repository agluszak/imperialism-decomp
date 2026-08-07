use super::{
    GameSnapshotV1, SnapshotArmyMission, SnapshotCity, SnapshotCivilianUnit, SnapshotMajorNation,
    SnapshotMilitaryUnit, SnapshotMission, SnapshotNation, SnapshotNavyMission, SnapshotPopulation,
    SnapshotShip, SnapshotTaskForce, SnapshotValidationError, TileSnapshot,
};
use imperialism_core::{
    ArmyMissionState, AttackMissionState, CityState, CivilianUnitId, CivilianUnitState, GameState,
    LaborPool, MAJOR_NATION_COUNT, MajorNationState, MajorNationTable, MilitaryUnitId,
    MilitaryUnitState, MissionData, MissionId, MissionState, NATION_COUNT, NationCommonState,
    NationData, NationId, NationPendingWork, NationState, NationTable, NavyMissionState,
    PENDING_ACTION_COUNT, PendingActionTable, PendingWorkState, PopulationState, ProductionSlot,
    ProductionTable, ResourceTable, RngState, ShipId, ShipState, TaskForceId, TaskForceState,
    TaskForceTarget, TileId, TileState, TurnStartEventState, TurnState, WorldState, all_resources,
};

pub fn game_state_from_snapshot(
    snapshot: GameSnapshotV1,
) -> Result<GameState, SnapshotValidationError> {
    snapshot.verify_hashes()?;
    Ok(GameState {
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
            tiles: snapshot.world.tiles.into_iter().map(tile_state).collect(),
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

fn nation_state(snapshot: SnapshotNation) -> Result<Option<NationState>, SnapshotValidationError> {
    if !snapshot.present {
        return Ok(None);
    }
    let slot = snapshot.slot;
    let data = match (snapshot.kind.as_str(), snapshot.major) {
        ("major", Some(major)) => NationData::Major(major_nation_state(major)?),
        ("minor", None) => NationData::Minor,
        ("major", None) => {
            return Err(SnapshotValidationError::Shape(format!(
                "present major nation {slot} has no major state"
            )));
        }
        ("minor", Some(_)) => {
            return Err(SnapshotValidationError::Shape(format!(
                "minor nation {slot} contains major state"
            )));
        }
        (kind, _) => {
            return Err(SnapshotValidationError::Shape(format!(
                "unsupported nation kind {kind}"
            )));
        }
    };
    Ok(Some(NationState {
        id: NationId::new(slot),
        common: NationCommonState {
            encoded_nation_slot: required(snapshot.encoded_nation_slot, "encoded nation slot")?,
            owner_nation: required(snapshot.owner_nation, "owner nation")?,
            treasury: required(snapshot.treasury, "treasury")?,
            home_tile: required(snapshot.home_tile, "home tile")?,
            need_level_by_nation: nation_table(
                required(snapshot.need_level_by_nation, "nation need levels")?,
                "nation need levels",
            )?,
        },
        data,
    }))
}

fn major_nation_state(
    snapshot: SnapshotMajorNation,
) -> Result<MajorNationState, SnapshotValidationError> {
    Ok(MajorNationState {
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
        item_potentials: resource_table(snapshot.item_potentials, "major nation item potentials")?,
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
        population: population_state(required(snapshot.population, "population state")?)?,
    }))
}

fn population_state(
    snapshot: SnapshotPopulation,
) -> Result<PopulationState, SnapshotValidationError> {
    Ok(PopulationState {
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

fn resource_table(
    values: Vec<i16>,
    field: &'static str,
) -> Result<ResourceTable<i16>, SnapshotValidationError> {
    let actual = values.len();
    let expected = all_resources().count();
    let values = values.try_into().map_err(|_: Vec<i16>| {
        SnapshotValidationError::Shape(format!("{field} has {actual} entries, expected {expected}"))
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
    let class = snapshot.class;
    let data = match (
        class.as_str(),
        snapshot.army,
        snapshot.navy,
        snapshot.attack,
        snapshot.beachhead,
        snapshot.blockade_port_zone,
    ) {
        ("TDefendProvinceMission", Some(army), None, None, None, None) => {
            MissionData::DefendProvince(army_mission_state(army)?)
        }
        ("TAttackProvinceMission", Some(army), None, Some(attack), None, None) => {
            MissionData::AttackProvince(AttackMissionState {
                army: army_mission_state(army)?,
                target_province: attack.target_province,
                amassing_province: attack.amassing_province,
            })
        }
        ("TInvadeMission", Some(army), None, Some(attack), beachhead, None) => {
            MissionData::Invade {
                attack: AttackMissionState {
                    army: army_mission_state(army)?,
                    target_province: attack.target_province,
                    amassing_province: attack.amassing_province,
                },
                beachhead: beachhead.map(navy_mission_state).transpose()?,
            }
        }
        ("TControlSeaZoneMission", None, Some(navy), None, None, None) => {
            MissionData::ControlSeaZone(navy_mission_state(navy)?)
        }
        ("TEscortMission", None, Some(navy), None, None, None) => {
            MissionData::Escort(navy_mission_state(navy)?)
        }
        ("TScatteredShipsMission", None, Some(navy), None, None, None) => {
            MissionData::ScatteredShips(navy_mission_state(navy)?)
        }
        ("TBlockadePortMission", None, Some(navy), None, None, Some(port_zone)) => {
            MissionData::BlockadePort {
                navy: navy_mission_state(navy)?,
                port_zone,
            }
        }
        ("TBeachheadMission", None, Some(navy), None, None, None) => {
            MissionData::Beachhead(navy_mission_state(navy)?)
        }
        (
            "TAttackProvinceMission"
            | "TInvadeMission"
            | "TDefendProvinceMission"
            | "TControlSeaZoneMission"
            | "TEscortMission"
            | "TScatteredShipsMission"
            | "TBlockadePortMission"
            | "TBeachheadMission",
            _,
            _,
            _,
            _,
            _,
        ) => {
            return Err(SnapshotValidationError::Shape(format!(
                "mission class {class} has incompatible payloads"
            )));
        }
        _ => {
            return Err(SnapshotValidationError::Shape(format!(
                "unsupported mission class {class}"
            )));
        }
    };
    Ok(MissionState {
        id: MissionId::new(snapshot.index),
        nation: NationId::new(snapshot.nation),
        queue_index: snapshot.queue_index,
        data,
        source_nation: snapshot.source_nation,
        path_marker: snapshot.path_marker,
        state: snapshot.state,
        importance_bits: snapshot.importance_bits,
        marker: snapshot.marker,
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

fn tile_state(snapshot: TileSnapshot) -> TileState {
    let fields = snapshot.0;
    TileState {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_tables_accept_only_their_canonical_wire_lengths() {
        let resource_count = all_resources().count();
        assert!(resource_table(vec![0; resource_count], "resources").is_ok());
        assert!(resource_table(vec![0; resource_count - 1], "resources").is_err());

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
        let values: Vec<i16> = (0..all_resources().count() as i16).collect();
        let table = resource_table(values.clone(), "resources").unwrap();
        let round_trip: Vec<i16> = all_resources().map(|resource| table[resource]).collect();
        assert_eq!(round_trip, values);
    }
}
