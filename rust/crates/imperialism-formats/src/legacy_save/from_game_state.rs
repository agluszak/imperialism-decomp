use super::conversions::*;
use super::model::*;
use super::*;
use enum_map::Enum;
use imperialism_core::*;

impl LegacySaveV62 {
    pub fn from_game_state(state: &GameState, label: &str, session_slot: i32) -> Self {
        let turn = state.turn();
        let loaded_unit_count =
            (state.military_units().len() + state.civilian_units().len()) as i32;
        let mut nation_availability = [0_u8; NATION_COUNT];
        let mut nation_control_modes = [0_i16; MAJOR_NATION_COUNT];
        let mut foreign_minister_policy_ids = [0_i16; MAJOR_NATION_COUNT];
        let mut nation_names = vec![String::new(); NATION_COUNT];
        let mut major_nations = IndexMap::new();
        let mut minor_nations = IndexMap::new();

        for slot in 0..MAJOR_NATION_COUNT {
            let major_id = MajorNationId::new(slot as u8);
            let Some(nation) = state
                .nations()
                .major_is_present(major_id)
                .then(|| state.nations().major(major_id))
            else {
                continue;
            };
            nation_availability[slot] = 1;
            nation_names[slot] = nation.common.display_name.clone();
            nation_control_modes[slot] = if nation.auto.is_some() { 2 } else { 0 };
            foreign_minister_policy_ids[slot] =
                foreign_minister_personality_to_retail(nation.economy.foreign_minister_personality);
            let military = state
                .military_units()
                .filter(|(_, unit)| unit.nation() == major_id.nation())
                .map(|(id, unit)| (id, unit.clone()))
                .collect::<Vec<_>>();
            let civilians = state
                .civilian_units()
                .filter(|(_, unit)| unit.nation() == major_id.nation())
                .map(|(id, unit)| (id, unit.clone()))
                .collect::<Vec<_>>();
            let missions = state
                .missions()
                .filter(|(_, mission)| mission.nation == major_id.nation())
                .map(|(_, mission)| mission.clone())
                .collect::<Vec<_>>();
            let pending = &state.pending().nations[major_id];
            major_nations.insert(
                major_id,
                major_nation_dto(
                    nation,
                    major_id,
                    &military,
                    &civilians,
                    &missions,
                    pending,
                    state.map().topology,
                ),
            );
        }

        for index in 0..MINOR_NATION_COUNT {
            let minor_id = MinorNationId::new(MajorNationId::COUNT + index as u8);
            let Some(minor) = state.nations().minor(minor_id) else {
                continue;
            };
            let slot = usize::from(minor_id.get());
            nation_availability[slot] = 1;
            nation_names[slot] = minor.common.display_name.clone();
            let military = state
                .military_units()
                .filter(|(_, unit)| unit.nation() == minor_id.nation())
                .map(|(id, unit)| (id, unit.clone()))
                .collect::<Vec<_>>();
            minor_nations.insert(minor_id, minor_nation_dto(minor, minor_id, &military));
        }

        let active_name = state
            .nations()
            .display_name(turn.active_nation)
            .unwrap_or("")
            .to_owned();
        let header = LegacySaveHeader {
            format_version: super::slots::SAVE_FORMAT_VERSION,
            saved_session_slot: session_slot,
            save_label: super::slots::normalize_save_label(label),
            preview_owner_nation_by_tile: state
                .map()
                .tiles
                .iter()
                .map(|tile| option_i8(tile.owner_nation.map(TileOwnerTag::get)))
                .collect(),
            preview_economic_year_offset: turn.economic_turn as i16,
            preview_difficulty: turn.difficulty.retail(),
            preview_active_nation: turn.active_nation.get(),
            preview_active_nation_name: active_name,
        };

        let mut phase_state_by_decade = [0_u8; 12];
        for (destination, &enabled) in phase_state_by_decade
            .iter_mut()
            .zip(turn.quarter_gate_by_decade.values())
        {
            *destination = u8::from(enabled);
        }

        let simulation = LegacySimulationPrefix {
            language_code: 0,
            economic_turn: turn.economic_turn as i16,
            active_nation: i16::from(turn.active_nation.get()),
            turn_state_code: turn.phase().retail() as i16,
            mode: 0,
            previous_turn_state_code: 0,
            previous_mode: 0,
            nation_count: state
                .nations()
                .majors()
                .filter(|major| matches!(major.common.status(), CountryStatus::Independent))
                .count() as i32,
            minor_nation_count: MINOR_NATION_COUNT as i32,
            turn_flow_status_flags: turn.turn_flow_status_flags,
            difficulty: turn.difficulty.retail(),
            game_setup: LegacyGameSetup {
                multiplayer_game_active: 0,
                nation_control_modes,
                city_minister_policy_ids: [0; MAJOR_NATION_COUNT],
                foreign_minister_policy_ids,
                defense_minister_policy_ids: [0; MAJOR_NATION_COUNT],
                reload_political_map_state: 0,
                scenario_map_index_plus_one: turn
                    .scenario_map
                    .map(|id| id.index() as i16 + 1)
                    .unwrap_or(0),
            },
            persistent_unit_id_counter: state.unit_ids().current() - loaded_unit_count,
            nation_availability,
            saved_multiplayer_role: 0,
            preference_slot_10: 0,
            selected_asset_set: 0,
            diplomacy_year_term_raw: turn.diplomacy_year_term_raw,
            phase_state_by_decade,
            nation_names,
        };

        Self {
            header,
            simulation,
            animator_idle_frequency: 0,
            market: market_dto(state.market()),
            diplomacy: diplomacy_dto(state.diplomacy()),
            technology: technology_dto(state.technology()),
            map: map_dto(state.map(), state.map_view_origin()),
            ocean: ocean_dto(state.ocean()),
            navy: navy_dto(state),
            army_reports: army_reports_from_state(state),
            major_nations,
            minor_nations,
            help: LegacyHelpState {
                index_records: empty_records(),
                civilian_completion_counters: [0; 5],
                help_index_ready: 0,
            },
        }
    }
}

fn major_nation_dto(
    nation: &MajorNation,
    major_id: MajorNationId,
    military: &[(MilitaryUnitId, MilitaryUnitState)],
    civilians: &[(CivilianUnitId, CivilianUnitState)],
    missions: &[MissionState],
    pending: &NationPendingWork,
    topology: MapTopology,
) -> LegacyMajorNationState {
    let power = LegacyGreatPowerState {
        country: country_dto(
            &nation.common,
            military,
            nation.common.display_name.clone(),
            i16::from(major_id.get()),
        ),
        prefix: great_power_prefix_dto(&nation.economy, pending),
        ministers: ministers_dto(&nation.economy),
        city: Some(city_dto(&nation.city)),
        post_city: post_city_dto(&nation.economy, &nation.towns, civilians, topology),
    };
    match &nation.auto {
        None => LegacyMajorNationState::Other(Box::new(power)),
        Some(auto) => LegacyMajorNationState::Auto(Box::new(LegacyAutoGreatPowerState {
            great_power: power,
            auto_prefix: auto_prefix_dto(auto),
            missions: missions
                .iter()
                .map(|mission| mission_dto(mission, military))
                .collect(),
        })),
    }
}

fn minor_nation_dto(
    nation: &MinorNation,
    minor_id: MinorNationId,
    military: &[(MilitaryUnitId, MilitaryUnitState)],
) -> LegacyMinorState {
    LegacyMinorState {
        country: country_dto(
            &nation.common,
            military,
            nation.common.display_name.clone(),
            i16::from(minor_id.get()),
        ),
        need_current_by_type: resource_i16(&nation.trade.current_supply),
        trade_offers_by_resource: resource_i16(&nation.trade.offers),
        grant_amounts_by_resource: resource_i16(&nation.trade.grant_deltas),
        diplomacy_thresholds: [
            nation.trade.thresholds.primary_manufactured_price,
            nation.trade.thresholds.secondary_manufactured_price,
            nation.trade.thresholds.general_offer_price,
            nation.trade.thresholds.random_offer_price,
            nation.trade.thresholds.coal_offer_price,
            nation.trade.thresholds.iron_offer_price,
            nation.trade.thresholds.oil_offer_price,
        ],
        diplomacy_policy_fields: [
            optional_commodity_i16(nation.trade.primary_manufactured_request),
            optional_commodity_i16(nation.trade.secondary_manufactured_request),
            nation.trade.primary_request_fulfilled,
            nation.trade.secondary_request_fulfilled,
        ],
        diplomacy_save_fields: nation.consortium_members.map(|id| i16::from(id.get())),
        diplomacy_save_extension: resource_i16(&nation.trade.independent_resource_counts),
    }
}

fn country_dto(
    common: &NationCommonState,
    military: &[(MilitaryUnitId, MilitaryUnitState)],
    identity: String,
    nation_slot: i16,
) -> LegacyCountryBase {
    LegacyCountryBase {
        identity: identity.clone(),
        alternate_identity: identity,
        nation_slot,
        encoded_country_status: country_status_to_retail(common.status()),
        unit_name_ordinal_by_type: common.unit_name_ordinal_by_type.into_array(),
        unit_name_counter: common.unit_name_counter,
        treasury: common.treasury,
        home_tile: option_i32(common.home_tile.map(TileId::get)),
        overlay_anchor_tile: -1,
        need_level_by_nation: nation_i16_table(&common.trade_policy_by_nation, |score| {
            score.get() as i16
        }),
        military_units: military
            .iter()
            .map(|(id, unit)| military_unit_dto(*id, unit))
            .collect(),
        owned_regions: common
            .owned_regions()
            .iter()
            .map(|province| i32::from(province.get()))
            .collect(),
    }
}

fn military_unit_dto(id: MilitaryUnitId, unit: &MilitaryUnitState) -> LegacyMilitaryUnit {
    LegacyMilitaryUnit {
        unit_type: i16::from(unit.unit_type().retail()),
        stationed_province: option_i16(unit.stationed_province().map(ProvinceId::get)),
        order_target: option_i16(unit.order().target().map(ProvinceId::get)),
        owner_nation: i16::from(unit.owner_nation().get()),
        roster_id: unit.roster_id(),
        registered: u8::from(unit.registered()),
        order: unit.order().code().get(),
        persistent_id: id.get(),
        name: unit.name().to_owned(),
        order_target_tiles: unit
            .order()
            .targets()
            .map(|province| option_i16(province.map(ProvinceId::get))),
        order_target_mirrors: unit
            .order()
            .target_mirrors()
            .map(|province| option_i16(province.map(ProvinceId::get))),
        strength: unit.strength(),
        era: unit.era().retail(),
        experience: unit.experience(),
        battle_flags: unit.battle_flags(),
    }
}

fn great_power_prefix_dto(
    economy: &GreatPowerState,
    pending: &NationPendingWork,
) -> LegacyGreatPowerPrefix {
    LegacyGreatPowerPrefix {
        diplomacy_eligible: u8::from(economy.diplomacy_eligible),
        capacities: [
            economy.capacities.available_merchant,
            economy.capacities.trade_offer,
            economy.capacities.transport,
            economy.capacities.reserved_transport,
        ],
        grant_total_cost: economy.grant_total_cost,
        unfilled_trade_offer_count: economy.unfilled_trade_offer_count,
        diplomacy_policy_by_nation: nation_i16_table(
            &economy.diplomacy_policy_by_nation,
            |policy| policy.map(DiplomacyPolicy::retail).unwrap_or(-1),
        ),
        diplomacy_grant_by_nation: nation_i16_table(&economy.diplomacy_grants_by_nation, |grant| {
            grant.map(grant_to_retail).unwrap_or(-1)
        }),
        need_current_by_type: resource_i16(&economy.need_current_by_type),
        need_target_by_type: resource_i16(&economy.need_target_by_type),
        relation_delta_current: resource_i16(&economy.relation_delta_current),
        purchased_items_by_resource: resource_i16(&economy.purchased_items_by_resource),
        item_potentials: resource_i16(&economy.item_potentials),
        unfilled_trade_turns_by_resource: resource_i16(&economy.unfilled_trade_turns_by_resource),
        transported_items_by_resource: resource_i16(&economy.transported_items_by_resource),
        remembered_trade_offers_by_resource: resource_i16(
            &economy.remembered_trade_offers_by_resource,
        ),
        budget_pool_base: economy.budget_pool_base,
        budget_pool_delta: economy.budget_pool_delta,
        aid_allocation_by_minor_nation: std::array::from_fn(|index| {
            let id = MinorNationId::new(MajorNationId::COUNT + index as u8);
            resource_i32(&economy.aid_allocation_by_minor_nation[id])
        }),
        pending_action_status: std::array::from_fn(|index| {
            economy.pending_actions[PendingActionKind::from_usize(index)]
                .status()
                .retail()
        }),
        pending_action_payload_by_action: std::array::from_fn(|index| {
            economy.pending_actions[PendingActionKind::from_usize(index)]
                .payload()
                .unwrap_or(-1)
        }),
        turn_event_queue: notices_to_records(&pending.turn_events),
        proposal_queue: proposals_to_records(&pending.proposals),
        diplomacy_tracked_slots: std::array::from_fn(|index| {
            deal_book_records(&economy.deal_book[TradeCommodity::from_usize(index)])
        }),
    }
}

fn ministers_dto(economy: &GreatPowerState) -> LegacyGreatPowerMinisters {
    let trade = &economy.foreign_trade;
    let interior = economy.interior_civilian.as_ref();
    let mut scalar_fields = [0_i16; 7];
    match trade.interior_bid {
        Some(bid) => {
            scalar_fields[0] = trade_commodity_i16(bid.commodity);
            scalar_fields[1] = bid.amount;
        }
        None => scalar_fields[0] = -10,
    }
    scalar_fields[2] = trade.capability_flag_14;
    scalar_fields[3] = trade.capability_flag_16;
    scalar_fields[4] = trade.phase_counter;
    scalar_fields[5] = trade.refresh_interval;
    scalar_fields[6] = match trade.requested_ship {
        ShipType::Trader => 1,
        _ => 2,
    };
    let mut order_scalars = [0_i16; 8];
    order_scalars[1] = match economy.pending_ship {
        None => 0,
        Some(ShipType::Trader) => 1,
        Some(ShipType::Indiaman) => 2,
        _ => 0,
    };
    order_scalars[3] = match interior.pending_recruitment() {
        None => -1,
        Some(kind) => kind.into_usize() as i16,
    };
    order_scalars[6] = option_i16(interior.railhead_target().map(TileId::get));
    let mut order_metrics = [0_i16; 61];
    let resources = resource_i16(interior.resource_order_metrics());
    order_metrics[..RESOURCE_KIND_COUNT].copy_from_slice(&resources);
    let demand = interior.city_order_demand();
    for (index, value) in demand.training().values().copied().enumerate() {
        order_metrics[23 + index] = value;
    }
    for (index, value) in demand.military_recruitment().values().copied().enumerate() {
        order_metrics[25 + index] = value;
    }
    for (index, value) in demand.civilian_recruitment().values().copied().enumerate() {
        order_metrics[34 + index] = value;
    }
    for (index, value) in demand.ships().values().copied().enumerate() {
        order_metrics[43 + index] = value;
    }
    order_metrics[51] = demand.transport_capacity();
    order_metrics[53..60].copy_from_slice(demand.expansions().as_array());
    order_metrics[60] = demand.population_growth();
    let pending_development = interior
        .pending_development_actions()
        .iter()
        .map(|action| match *action {
            PendingDevelopmentAction::LandUnit { unit_type } => unit_type.into_usize() as i32,
            PendingDevelopmentAction::Industry { slot } => i32::from(slot as u8) + 30,
        })
        .collect();
    LegacyGreatPowerMinisters {
        foreign: Some(LegacyForeignMinisterState {
            skill_index: economy.foreign_minister_skill_index,
            scalar_fields,
            purchase_priority_by_resource: enum_i16(&trade.purchase_priority),
            preferred_resource_slots: trade.preferred_resources.map(optional_commodity_i16),
            status_flag: 0,
            trade_partner_enabled: trade.trade_partner_enabled.into_array().map(u8::from),
            development_grant_by_nation: *economy.development_grant_by_nation.as_array(),
            bill_order_flag: matches!(
                economy.foreign_minister_personality,
                ForeignMinisterPersonality::Bill
            )
            .then_some(0),
        }),
        interior: Some(LegacyInteriorMinisterState {
            skill_index: 0,
            scalar_prefix: [0; 4],
            trailing_table: [0; 7],
            order_scalars,
            order_metrics,
            deferred_labor_shortfall: interior.deferred_labor_shortfall(),
            order_short_table: *interior.production_deficit_by_slot().as_array(),
            order_type_tables: [
                resource_i16(interior.railhead_priority_by_resource()),
                resource_i16(interior.exterior_need_by_resource()),
                resource_i16(interior.historical_need_by_resource()),
            ],
            temporarily_reserved_ship_arms: interior.temporarily_reserved_ship_arms(),
            integer_lists: [Vec::new(), Vec::new(), pending_development],
            civilian_order_demand_by_resource: resource_i16(
                interior.civilian_order_demand_by_resource(),
            ),
        }),
        defense: Some(LegacyDefenseMinisterState {
            skill_index: economy.defense_minister_skill_index,
            scalar_fields: [0; 2],
            recruit_order_count_by_type: [0; 30],
            order_weight_by_type: [0; 30],
            thresholds: [0; 4],
        }),
    }
}

fn city_dto(city: &CityState) -> LegacyCityState {
    let orders = &city.orders;
    let (production_flags, production_current, production_progress) =
        city_windows_to_retail(&city.building_windows);
    LegacyCityState {
        power_plant_upgrade_queued: u8::from(city.power_plant_upgrade_queued),
        low_production: u8::from(city.low_production),
        low_stock: u8::from(city.low_stock),
        production_flags,
        food_substitution_count: city.food_substitution_count,
        starvation_population_loss: city.starvation_population_loss,
        serialized_state: city.serialized_state,
        phase_counter: city.phase_counter,
        power_available: city.power_available,
        military_recruit_count_by_kind: enum_i16(&city.military_recruit_count_by_kind),
        civilian_recruit_count_by_kind: enum_i16(&city.civilian_recruit_count_by_kind),
        order_count_by_type: enum_i16(&city.ship_order_count_by_type),
        stockpile: resource_i16_from_stockpile(&city.stockpile),
        production_orders: *city.production_orders.as_array(),
        production_accum: *city.production_accum.as_array(),
        unmet_resource_retries: resource_i16(&city.unmet_resource_retries),
        reserved_by_type: resource_i16(&city.reserved_by_type),
        production_current,
        production_progress,
        consumed_production_input_by_type: resource_i16(&city.consumed_production_input_by_type),
        rolling_item_production_score: city.rolling_item_production_score,
        population: LegacyPopulationState {
            count: city.population.count(),
            strength: city.population.strength(),
            extra: city.population.extra(),
            phase_value: city.population.strike_phase().retail(),
            predicted_need_by_resource: resource_i16(city.population.predicted_need_by_resource()),
            count_float_bits: city.population.accumulator().to_bits(),
            baseline_labor: city.population.baseline_labor().into(),
            production_labor: city.population.production_labor().into(),
            pending_labor_delta: city.population.pending_labor_delta().into(),
        },
        orders: city_orders_dto(orders),
        tasks: Vec::new(),
        transport_requests: empty_records(),
    }
}

fn city_orders_dto(orders: &CityOrders) -> LegacyCityOrders {
    LegacyCityOrders {
        food_processing: production_from_progress(&orders.food_processing, 0),
        items: std::array::from_fn(|index| {
            let item = ManufacturedItem::from_usize(index);
            item_from_requested(&orders.items[item], i16::from(item.resource().retail()))
        }),
        training: std::array::from_fn(|index| {
            production_from_progress(&orders.training[TrainingLevel::from_usize(index)], 0)
        }),
        military_recruitment: std::array::from_fn(|index| {
            let order =
                &orders.military_recruitment[MilitaryRecruitmentCategory::from_usize(index)];
            unit_from_progress(&order.progress, i16::from(order.unit_kind.retail()))
        }),
        civilian_recruitment: std::array::from_fn(|index| {
            unit_from_progress(
                &orders.civilian_recruitment[CivilianUnitKind::from_usize(index)],
                i16::from(CivilianUnitKind::from_usize(index).retail()),
            )
        }),
        ships: std::array::from_fn(|index| {
            production_from_ship(&orders.ships[ShipOrderSlot::from_usize(index)])
        }),
        transport_capacity: item_from_requested(&orders.transport_capacity, 0),
        power_plant: LegacyPowerPlantOrder {
            order: production_from_progress(&orders.power_plant.progress, 0),
            desired_quantity: orders.power_plant.desired_quantity,
        },
        expansions: std::array::from_fn(|index| {
            item_from_requested(&orders.expansions[ExpandableFacility::from_usize(index)], 0)
        }),
        population_growth: production_from_progress(&orders.population_growth, 0),
    }
}

fn post_city_dto(
    economy: &GreatPowerState,
    towns: &indexmap::IndexMap<TileId, TownState>,
    civilians: &[(CivilianUnitId, CivilianUnitState)],
    topology: MapTopology,
) -> LegacyGreatPowerPostCity {
    LegacyGreatPowerPostCity {
        towns: towns
            .iter()
            .map(|(tile, town)| town_dto(*tile, town))
            .collect(),
        civilian_units: civilians
            .iter()
            .map(|(id, unit)| civilian_unit_dto(*id, unit, topology))
            .collect(),
        candidate_nation_flags: *economy.candidate_nation_flags.as_array(),
        diplomacy_budget_base: economy.diplomacy_budget_base,
        escalation_counter: economy.escalation_counter as i8,
        pending_commitment_cost: economy.pending_commitment_cost,
        pressure_counter: economy.pressure_counter as i8,
        army_movement_budget: economy.army_movement_budget,
        turn_finished_flag: u8::from(economy.turn_finished),
        special_resource_trade_balance: economy.special_resource_trade_balance,
        aid_allocation_total: economy.aid_allocation_total,
        colony_boycott_flags: *economy.colony_boycott_flags.as_array(),
        military_expenses: economy.military_expenses,
    }
}

fn town_dto(tile: TileId, town: &TownState) -> LegacyTown {
    LegacyTown {
        name: town.name.clone(),
        tile_index: tile.get() as i16,
        opaque_fields: [0; 2],
        created_turn: town.created_turn,
        owner_nation: i16::from(town.owner_nation.get()),
        resource_yield_by_type: resource_i16(&town.resource_yield_by_type),
        transport_linked: u8::from(town.transport_linked),
        enabled: town.enabled,
        has_adjacent_city: town.has_adjacent_city,
        active: u8::from(town.active),
    }
}

fn civilian_unit_dto(
    id: CivilianUnitId,
    unit: &CivilianUnitState,
    topology: MapTopology,
) -> LegacyCivilianUnit {
    let tile = option_i16(unit.location().tile().map(TileId::get));
    let (order, target, remaining) = match unit.order() {
        CivilianWorkOrder::Idle => (0, -1, 0),
        CivilianWorkOrder::Redeploy { destination, turns } => {
            (1, destination.get() as i16, turns.get())
        }
        CivilianWorkOrder::Sleep => (2, -1, 0),
        CivilianWorkOrder::LayRail { segment, turns } => {
            let _ = topology;
            (5, segment.origin().get() as i16, turns.get())
        }
        CivilianWorkOrder::BuildDepot { turns } => (6, -1, turns.get()),
        CivilianWorkOrder::BuildPort { turns } => (7, -1, turns.get()),
        CivilianWorkOrder::Prospect { turns } => (8, -1, turns.get()),
        CivilianWorkOrder::DevelopResource { turns } => (10, -1, turns.get()),
        CivilianWorkOrder::BuildFort { turns } => (12, -1, turns.get()),
        CivilianWorkOrder::PurchaseLand { turns } => (13, -1, turns.get()),
    };
    LegacyCivilianUnit {
        unit_type: i16::from(unit.unit_type().retail()),
        tile_index: tile,
        order_target: target,
        owner_nation: i16::from(unit.owner_nation().get()),
        roster_id: unit.roster_id(),
        registered: u8::from(unit.registered()),
        order,
        persistent_id: id.get(),
        remaining_turns: remaining,
    }
}

fn auto_prefix_dto(auto: &AutoGreatPowerState) -> LegacyAutoGreatPowerPrefix {
    let mut map_node_state_flags = [0_u8; super::PROVINCE_COUNT];
    for (index, flag) in map_node_state_flags.iter_mut().enumerate() {
        *flag = ai_target_to_retail(auto.province_targets[ProvinceId::new(index as u16)]);
    }
    let mut port_zone_state_flags = [0_u8; AI_ZONE_TARGET_CAPACITY];
    for (index, target) in auto.zone_targets.iter().enumerate() {
        if index < AI_ZONE_TARGET_CAPACITY {
            port_zone_state_flags[index] = ai_target_to_retail(*target);
        }
    }
    LegacyAutoGreatPowerPrefix {
        action_metric_by_quarter: enum_i16(&auto.trade.temporary_processed_stock),
        map_node_state_flags,
        port_zone_state_flags,
    }
}

fn mission_dto(
    mission: &MissionState,
    military: &[(MilitaryUnitId, MilitaryUnitState)],
) -> LegacyMission {
    let common = LegacyMissionCommon {
        source_nation: i16::from(mission.nation.get()),
        state: mission.state,
        importance_bits: mission.importance_bits,
        flag: u8::from(mission.held),
        path_marker: option_i16(mission.path_nation.map(|id| u16::from(id.get()))),
        marker: mission.marker,
    };
    match &mission.data {
        MissionData::DefendProvince { province, army } => LegacyMission::DefendProvince {
            common,
            army: army_dto(army, Some(*province), military),
        },
        MissionData::AttackProvince(attack) => LegacyMission::AttackProvince {
            common,
            army: army_dto(&attack.army, attack.present_province, military),
            target_province: attack.target_province.get() as i16,
            amassing_province: option_i16(attack.amassing_province.map(ProvinceId::get)),
        },
        MissionData::Invade { attack, beachhead } => LegacyMission::Invade {
            common,
            army: army_dto(&attack.army, attack.present_province, military),
            target_province: attack.target_province.get() as i16,
            amassing_province: option_i16(attack.amassing_province.map(ProvinceId::get)),
            beachhead: beachhead
                .as_ref()
                .map(navy_mission_dto)
                .unwrap_or_else(empty_navy_mission),
        },
        MissionData::ControlSeaZone(navy) => LegacyMission::ControlSeaZone {
            common,
            navy: navy_mission_dto(navy),
        },
        MissionData::Escort(navy) => LegacyMission::Escort {
            common,
            navy: navy_mission_dto(navy),
        },
        MissionData::ScatteredShips(navy) => LegacyMission::ScatteredShips {
            common,
            navy: navy_mission_dto(navy),
        },
        MissionData::Beachhead(navy) => LegacyMission::Beachhead {
            common,
            navy: navy_mission_dto(navy),
        },
        MissionData::BlockadePort { navy, port_zone } => LegacyMission::BlockadePort {
            common,
            navy: navy_mission_dto(navy),
            blockade_port_zone: port_zone.get() as i16,
        },
    }
}

fn army_dto(
    army: &ArmyMissionState,
    present: Option<ProvinceId>,
    military: &[(MilitaryUnitId, MilitaryUnitState)],
) -> LegacyArmyMission {
    let unit_ordinals = army
        .units
        .iter()
        .rev()
        .map(|id| {
            let index = military
                .iter()
                .position(|(unit_id, _)| *unit_id == *id)
                .expect("mission unit belongs to the owning nation");
            (index + 1) as i16
        })
        .collect();
    LegacyArmyMission {
        present_location: option_i16(present.map(ProvinceId::get)),
        required_equipage_bits: army.required_equipage_bits,
        unit_ordinals,
    }
}

fn navy_dto(state: &GameState) -> LegacyNavyState {
    let ships: Vec<LegacyShip> = state
        .ships_in_retail_order()
        .map(|(_, ship)| LegacyShip {
            ship_type: i16::from(ship.ship_type.retail()),
            aggression: ship.aggression.retail(),
            nation: i16::from(ship.nation.get()),
            name: ship.name.clone(),
            strength: ship.strength,
            selection: ship.selection.retail(),
            experience: ship.experience,
            zone_ordinal: i16::try_from(ship.location.get())
                .expect("ship zone ordinal fits a save short"),
        })
        .collect();
    let ship_count = i16::try_from(ships.len()).expect("ship count fits a save short");
    let ship_ordinals: std::collections::HashMap<ShipId, i16> = state
        .ships_in_retail_order()
        .enumerate()
        .map(|(ordinal, (id, _))| {
            (
                id,
                i16::try_from(ordinal).expect("ship ordinal fits a save short"),
            )
        })
        .collect();
    let admirals = state
        .admirals_in_retail_order()
        .map(|(_, admiral)| LegacyAdmiral {
            nation: i16::from(admiral.nation.get()),
            name: admiral.name.clone(),
            experience: admiral.experience,
            ship_index: admiral
                .ship
                .map(|id| {
                    *ship_ordinals
                        .get(&id)
                        .expect("admiral ship is present in the retail ship list")
                })
                .unwrap_or(ship_count),
        })
        .collect();
    LegacyNavyState {
        ships,
        admirals,
        task_forces: Vec::new(),
    }
}

fn navy_mission_dto(navy: &NavyMissionState) -> LegacyNavyMission {
    LegacyNavyMission {
        target_zone: option_i16(navy.target_zone.map(OceanZoneId::get)),
        resolved_port_zone: option_i16(navy.resolved_port_zone.map(OceanZoneId::get)),
        required_equipage_bits: navy.required_equipage_bits,
        ship_ordinals: Vec::new(),
        state: navy.state.retail(),
    }
}

fn empty_navy_mission() -> LegacyNavyMission {
    LegacyNavyMission {
        target_zone: -1,
        resolved_port_zone: -1,
        required_equipage_bits: [0; 4],
        ship_ordinals: Vec::new(),
        state: 0,
    }
}

fn market_dto(market: &TradeMarketState) -> LegacyTradeMarketState {
    LegacyTradeMarketState {
        rows: std::array::from_fn(|index| {
            let row = &market.rows[TradeCommodity::from_usize(index)];
            LegacyTradeMarketRow {
                previous_price: row.previous_price as i16,
                price: row.price as i16,
                request_count: row.request_count as i16,
                offer_count: row.offer_count as i16,
                adjusted_offer_count: row.adjusted_offer_count,
                amount_offered: row.amount_offered as i16,
                base_price: row.base_price as i16,
                current_offer_by_nation: *row.current_offer_by_nation.as_array(),
                accumulated_offer_by_nation: *row.accumulated_offer_by_nation.as_array(),
                maximum_offer_by_nation: *row.maximum_offer_by_nation.as_array(),
            }
        }),
        history: std::array::from_fn(|_| empty_records()),
    }
}

fn diplomacy_dto(diplomacy: &DiplomacyState) -> LegacyDiplomacyState {
    LegacyDiplomacyState {
        relation_standing_scores: flatten_nation_pairs(&diplomacy.standings, |value| value),
        relation_propagation_matrix: flatten_nation_pairs(&diplomacy.relationships, |value| {
            value.retail()
        }),
        relation_turn_stamp_matrix: flatten_nation_pairs(&diplomacy.relationship_turns, |value| {
            value.unwrap_or(-1)
        }),
        relation_code_matrix: *diplomacy.influence_thresholds.as_array(),
        pending_policy_code_matrix: diplomacy
            .influence_sides
            .as_array()
            .map(|side| option_i8(side.map(MajorNationId::get))),
        last_diplomatic_effort_turn: diplomacy.last_diplomatic_effort_turn,
        relation_side_effect_matrix: flatten_nation_pairs(&diplomacy.mission_levels, |value| {
            value.retail()
        }),
        congress_leadership: [
            option_i16(diplomacy.congress.chairman.map(|id| u16::from(id.get()))),
            option_i16(diplomacy.congress.counterpart.map(|id| u16::from(id.get()))),
        ],
        congress_support: [
            diplomacy.congress.chairman_support,
            diplomacy.congress.counterpart_support,
            diplomacy.congress.neutral_support,
        ],
        special_relation_source_slots: diplomacy
            .special_relation_sources
            .as_array()
            .map(|id| option_i16(id.map(|major| u16::from(major.get())))),
        special_relation_target_slots: diplomacy
            .special_relation_targets
            .as_array()
            .map(|id| option_i16(id.map(|major| u16::from(major.get())))),
    }
}

fn technology_dto(technology: &TechnologyState) -> LegacyTechnologyState {
    let mut research_status_by_nation = [[0_u8; Technology::LENGTH]; MAJOR_NATION_COUNT];
    let mut ability_active_by_nation = [[0_u8; 30]; MAJOR_NATION_COUNT];
    let mut university_recruitment_availability = [[0_u8; 9]; MAJOR_NATION_COUNT];
    let mut capability_value_by_nation_and_resource =
        [[0_i16; RESOURCE_KIND_COUNT]; MAJOR_NATION_COUNT];
    for slot in 0..MAJOR_NATION_COUNT {
        let nation = MajorNationId::new(slot as u8);
        research_status_by_nation[slot] = (*technology.research_status_by_nation[nation]
            .as_array())
        .map(technology_research_status_to_retail);
        ability_active_by_nation[slot] =
            enum_u8(&technology.military_unit_ability_active_by_nation[nation]);
        let capabilities = &technology.city_capabilities_by_nation[nation];
        university_recruitment_availability[slot] = enum_u8(&capabilities.university.available);
        capability_value_by_nation_and_resource[slot] = std::array::from_fn(|index| {
            i16::from(
                capabilities.university.requirement_levels
                    [ResourceKind::from_index(index as u8).expect("resource index")]
                .retail(),
            )
        });
    }
    LegacyTechnologyState {
        priority_slots: *technology.scheduled_unlock_turn_by_technology.as_array(),
        initial_capability_value_by_nation_and_resource: [[0; RESOURCE_KIND_COUNT];
            MAJOR_NATION_COUNT],
        tech_selector: 0,
        active_zone_index: i16::from(technology.navy_growth_ship_type.retail()),
        per_technology_unlock_flags: (*technology.global_unlocks_by_technology.as_array())
            .map(u8::from),
        resource_type_enabled: std::array::from_fn(|index| {
            let slot = IndustryCapabilitySlot::ALL[index];
            u8::from(technology.industry_enabled_by_slot[slot])
        }),
        init_flags_1ab: [0; 30],
        init_flags_1c9: [0; 9],
        active_prerequisite_pair: [0; 2],
        nation_capability_slots: std::array::from_fn(|slot| {
            technology.selected_capability_slots[MajorNationId::new(slot as u8)]
                .as_array()
                .map(|kind| i16::from(kind.retail()))
        }),
        research_status_by_nation,
        selected_resource_type_by_nation: [[0; 14]; MAJOR_NATION_COUNT],
        ability_active_by_nation,
        university_recruitment_availability,
        completion_year_offsets: std::array::from_fn(|slot| {
            *technology.completion_year_by_nation[MajorNationId::new(slot as u8)].as_array()
        }),
        capability_value_by_nation_and_resource,
        marker: technology.latest_global_unlock as i16,
    }
}

fn map_dto(map: &MapMgr, view_origin: TileId) -> LegacyMapState {
    LegacyMapState {
        view_origin_tile: view_origin.get() as i16,
        map_data_ready: u8::from(map.map_data_ready),
        recruit_search_active: u8::from(map.recruit_search_active),
        city_score_total: map.city_score_total,
        scenario_tag: map.scenario_tag.clone(),
        no_horizontal_wrap: u8::from(!map.topology.wraps_horizontally()),
        tiles: map.tiles.iter().map(tile_dto).collect(),
        provinces: map.provinces.as_array().iter().map(province_dto).collect(),
        pending_river_mouth_tile: option_i16(map.pending_river_mouth_tile.map(TileId::get)),
    }
}

fn tile_dto(tile: &TileState) -> LegacyTerrainTile {
    let mut visibility = 0_u8;
    for slot in 0..MAJOR_NATION_COUNT {
        if tile.development.resource_visible_to_majors[MajorNationId::new(slot as u8)] {
            visibility |= 1 << slot;
        }
    }
    LegacyTerrainTile {
        terrain_kind: tile.terrain.retail(),
        sprite_variant: tile.rendering.sprite_variant,
        river_sprite: tile
            .rendering
            .river_sprite
            .map(RiverSprite::retail)
            .unwrap_or(0),
        owner_nation: option_i8(tile.owner_nation.map(TileOwnerTag::get)),
        former_owner_nation: option_i8(tile.former_owner_nation.map(TileOwnerTag::get)),
        secondary_owner_nation: option_i8(tile.secondary_owner_nation.map(MajorNationId::get)),
        owner_border_mask: tile.owner_border_mask,
        city_border_mask: tile.city_border_mask,
        water_adjacency_mask: tile.water_adjacency_mask,
        region: option_i8(tile.region.map(RegionId::get)),
        adjacency_bits: tile.transport_links.bits(),
        adjacency_mask_a: tile.rendering.transition_mask,
        adjacency_mask_b: tile.rendering.coast_or_secondary_mask,
        city_record_index: option_i16(tile.province.map(ProvinceId::get)),
        development_classes: (tile.development.surface.get()
            | (tile.development.extractive.get() << 4)) as i8,
        pending_development_visibility: visibility,
        recruit_search_visited: tile.recruit_search_visited,
        per_tile_visited: tile.per_tile_visited,
        marker_slot_index: tile.marker_slot_index,
        edge_resources: tile
            .edge_resources
            .map(|resource| option_i8(resource.map(|kind| kind.retail()))),
        gate: tile.gate,
        rail_flags: tile.pending_rail_links.bits(),
        action_state: tile
            .action
            .map(|action| action.retail() as i8)
            .unwrap_or(-1),
        tile_action_ordinal: tile.tile_action_ordinal,
        active_flags: tile.flags.bits(),
    }
}

fn province_dto(province: &ProvinceState) -> LegacyProvince {
    let mut adjacent_region_ids = [-1_i16; 12];
    let mut adjacent_region_anchor_tiles = [-1_i16; 12];
    for (index, (id, tile)) in province
        .adjacency()
        .iter()
        .zip(province.adjacency_anchor_tiles.iter())
        .enumerate()
    {
        adjacent_region_ids[index] = id.get() as i16;
        adjacent_region_anchor_tiles[index] = tile.get() as i16;
    }
    let mut linked_tile_indices = [-1_i16; 32];
    for (index, tile) in province.linked_tiles.iter().enumerate() {
        linked_tile_indices[index] = tile.get() as i16;
    }
    let resource_development_by_type = std::array::from_fn(|offset| {
        let resource = ResourceKind::from_index(
            ResourceKind::Food.retail()
                + u8::try_from(offset).expect("province resource-development index fits u8"),
        )
        .expect("province resource-development table spans food through arms");
        province.resource_development_by_type()[resource]
    });
    let mut explored_by_nation_mask = 0_u8;
    for slot in 0..MAJOR_NATION_COUNT {
        if province.explored_by_majors()[MajorNationId::new(slot as u8)] {
            explored_by_nation_mask |= 1 << slot;
        }
    }
    LegacyProvince {
        owner_nation: option_i8(province.owner().map(NationId::get)),
        former_owner_nation: option_i8(province.former_owner().map(NationId::get)),
        development_stage: province.development_stage().retail(),
        fort_level: province.fort_level().retail(),
        city_tile: option_i16(province.city_tile().map(TileId::get)),
        last_turn_tick: province.last_turn_tick,
        adjacent_region_count: province.adjacency().len() as i8,
        adjacent_region_ids,
        adjacent_region_anchor_tiles,
        linked_region_count: province.linked_tiles.len() as i8,
        secondary_neighbor_tile: option_i16(province.secondary_neighbor_tile.map(TileId::get)),
        primary_neighbor_tile: option_i16(province.primary_neighbor_tile.map(TileId::get)),
        linked_tile_indices,
        resource_development_by_type,
        city_score: province.city_score(),
        navy_order_reachable: u8::from(province.navy_order_reachable),
        explored_by_nation_mask,
        resource_presence_mask: province.resource_presence_mask,
        region_class: option_i8(province.region_class),
        name: province.name.clone(),
    }
}

fn ocean_dto(ocean: &Ocean) -> LegacyOceanState {
    let mut zones = Vec::new();
    let mut port_zones = Vec::new();
    for (ordinal, zone) in ocean.zones.iter().enumerate() {
        match zone {
            ZoneKind::Zone(zone) => zones.push(zone_dto(zone, ordinal as i16)),
            ZoneKind::PortZone(port) => port_zones.push(LegacyPortZone {
                zone: zone_dto(&port.zone, ordinal as i16),
                port_tile_index: port.port_tile.get() as i16,
            }),
        }
    }
    LegacyOceanState {
        zones,
        port_zones,
        route_segments: ocean
            .routes
            .iter()
            .map(|route| {
                [
                    route.start_row,
                    route.start_column,
                    route.end_row,
                    route.end_column,
                ]
            })
            .collect(),
    }
}

fn zone_dto(zone: &Zone, ordinal: i16) -> LegacyZone {
    LegacyZone {
        display_name: zone.display_name.clone(),
        status_code: zone.status_code.unwrap_or(-1),
        tile_or_terrain_id: option_i32(zone.target_tile.map(TileId::get)),
        seed_nation_id: option_i16(zone.seed_owner.map(|tag| u16::from(tag.get()))),
        active_tile_index: option_i16(zone.active_tile.map(TileId::get)),
        context_ordinal: ordinal,
    }
}

fn production_from_progress(
    progress: &ProductionProgress,
    resource_type_index: i16,
) -> LegacyProductionOrder {
    production_order(progress, resource_type_index, [0; RESOURCE_KIND_COUNT], 0)
}

fn production_from_ship(order: &ShipOrderState) -> LegacyProductionOrder {
    let mut tracking_slots = [0_i16; RESOURCE_KIND_COUNT];
    for (kind, amount) in order.materials.iter() {
        tracking_slots[usize::from(kind.retail())] = amount;
    }
    production_order(
        &order.progress,
        i16::from(order.ship_type.retail()),
        tracking_slots,
        0,
    )
}

fn production_order(
    progress: &ProductionProgress,
    resource_type_index: i16,
    tracking_slots: [i16; RESOURCE_KIND_COUNT],
    accumulated_value: i32,
) -> LegacyProductionOrder {
    LegacyProductionOrder {
        resource_type_index,
        quantity: progress.quantity,
        limiting_constraint: production_constraint_to_retail(progress.limiting_constraint),
        tracking_slots,
        accumulated_value,
    }
}

fn item_from_requested(
    order: &RequestedCityOrderState,
    resource_type_index: i16,
) -> LegacyItemOrder {
    LegacyItemOrder {
        order: production_order(
            &order.progress,
            resource_type_index,
            resource_i16(&order.tracking_by_resource),
            order.accumulated_value,
        ),
        requested_quantity: order.requested_quantity,
        primary_input_resource_id: 0,
        secondary_input_resource_id: 0,
        production_slot: 0,
    }
}

fn unit_from_progress(progress: &ProductionProgress, resource_type_index: i16) -> LegacyUnitOrder {
    LegacyUnitOrder {
        order: production_from_progress(progress, resource_type_index),
        primary_input_resource_id: 0,
        secondary_input_resource_id: 0,
        primary_input_per_unit: 0,
        secondary_input_per_unit: 0,
        cash_cost_per_unit: 0,
        workforce_mode: 0,
        specialist_mode: 0,
    }
}

fn notices_to_records(notices: &[DiplomacyNotice]) -> LegacyFixedRecordList {
    let mut records = notices
        .iter()
        .map(|notice| {
            let mut record = vec![0_u8; 4];
            record[..2].copy_from_slice(&notice.code.to_le_bytes());
            record[2..4].copy_from_slice(&i16::from(notice.source.get()).to_le_bytes());
            record
        })
        .collect::<Vec<_>>();
    records.sort_by_key(|record| i16::from_le_bytes([record[2], record[3]]));
    LegacyFixedRecordList {
        record_size: 4,
        records,
    }
}

fn proposals_to_records(proposals: &[DiplomacyProposal]) -> LegacyFixedRecordList {
    let mut records = proposals
        .iter()
        .map(|proposal| {
            let mut record = vec![0_u8; 4];
            record[..2].copy_from_slice(&proposal.policy.retail().to_le_bytes());
            record[2..4].copy_from_slice(&i16::from(proposal.source.get()).to_le_bytes());
            record
        })
        .collect::<Vec<_>>();
    records.sort_by_key(|record| i16::from_le_bytes([record[2], record[3]]));
    LegacyFixedRecordList {
        record_size: 4,
        records,
    }
}

fn deal_book_records(entries: &[TradeDealBookEntry]) -> LegacyFixedRecordList {
    let mut records = entries
        .iter()
        .map(|entry| {
            let mut record = vec![0_u8; 12];
            let kind = deal_book_entry_kind_to_retail(entry.kind);
            record[..2].copy_from_slice(&kind.to_le_bytes());
            record[2..4].copy_from_slice(&i16::from(entry.nation.get()).to_le_bytes());
            record[4..6].copy_from_slice(&entry.amount.to_le_bytes());
            record[8..12].copy_from_slice(&entry.unit_price.to_le_bytes());
            record
        })
        .collect::<Vec<_>>();
    records.sort_by_key(|record| i16::from_le_bytes([record[2], record[3]]));
    LegacyFixedRecordList {
        record_size: 12,
        records,
    }
}

fn empty_records() -> LegacyFixedRecordList {
    LegacyFixedRecordList {
        record_size: 0,
        records: Vec::new(),
    }
}

fn grant_to_retail(grant: DiplomacyGrant) -> i16 {
    let amount = (grant.amount as i16) & 0x3fff;
    if grant.recurring {
        amount | 0x4000
    } else {
        amount
    }
}

fn resource_i16<T: Copy + Into<i16>>(table: &ResourceTable<T>) -> [i16; RESOURCE_KIND_COUNT] {
    std::array::from_fn(|index| {
        table[ResourceKind::from_index(index as u8).expect("resource index")].into()
    })
}

fn resource_i16_from_stockpile(stockpile: &Stockpile) -> [i16; RESOURCE_KIND_COUNT] {
    std::array::from_fn(|index| {
        stockpile[ResourceKind::from_index(index as u8).expect("resource index")]
    })
}

fn resource_i32(table: &ResourceTable<i32>) -> [i32; RESOURCE_KIND_COUNT] {
    std::array::from_fn(|index| {
        table[ResourceKind::from_index(index as u8).expect("resource index")]
    })
}

fn enum_i16<K: Enum + Copy, const N: usize>(table: &enum_map::EnumMap<K, i16>) -> [i16; N] {
    std::array::from_fn(|index| table[K::from_usize(index)])
}

fn enum_u8<K: Enum + Copy, const N: usize>(table: &enum_map::EnumMap<K, bool>) -> [u8; N] {
    std::array::from_fn(|index| u8::from(table[K::from_usize(index)]))
}

fn nation_i16_table<T: Copy>(
    table: &NationTable<T>,
    map: impl Fn(T) -> i16,
) -> [i16; NATION_COUNT] {
    std::array::from_fn(|index| map(table.as_array()[index]))
}

fn flatten_nation_pairs<T: Copy, U: Copy>(
    table: &NationTable<NationTable<T>>,
    map: impl Fn(T) -> U,
) -> [U; NATION_COUNT * NATION_COUNT] {
    std::array::from_fn(|index| {
        let source = NationId::new((index / NATION_COUNT) as u8);
        let target = NationId::new((index % NATION_COUNT) as u8);
        map(table[source][target])
    })
}

fn trade_commodity_i16(commodity: TradeCommodity) -> i16 {
    i16::from(commodity.resource().retail())
}

fn optional_commodity_i16(commodity: Option<TradeCommodity>) -> i16 {
    commodity.map(trade_commodity_i16).unwrap_or(-10)
}

fn army_reports_from_state(state: &GameState) -> Vec<LegacyBattleReport> {
    state
        .battle_reports()
        .iter()
        .map(|report| LegacyBattleReport {
            participant_index: report.participant.retail(),
            displayed_participant: report.displayed_participant.retail(),
            kind: report.kind.retail(),
            node_id: match report.location {
                BattleReportLocation::Province(province) => province.get() as i16,
                BattleReportLocation::Zone(zone) => zone.get() as i16,
            },
            sides: [
                &report.sides[BattleReportSideSlot::Left],
                &report.sides[BattleReportSideSlot::Right],
            ]
            .map(|side| LegacyBattleReportSide {
                nation: side.nation.get(),
                name: side.name.clone(),
                overlay: side.overlay.clone(),
                children: side
                    .children
                    .iter()
                    .map(|child| LegacyBattleReportChild {
                        resource_type: match child.kind {
                            BattleReportUnitKind::Military(kind) => i16::from(kind.retail()),
                            BattleReportUnitKind::Ship(kind) => i16::from(kind.retail()),
                            BattleReportUnitKind::Resource(kind) => i16::from(kind.retail()),
                        },
                        stock_or_required: child.stock_or_required,
                        name: child.name.clone(),
                        strength_bucket: child.strength_bucket,
                        detail_identity: child.detail_identity,
                    })
                    .collect(),
            }),
        })
        .collect()
}
