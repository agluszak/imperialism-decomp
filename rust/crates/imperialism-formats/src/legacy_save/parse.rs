use super::model::*;
use super::*;
use crate::legacy_stream::LegacyStream;
use imperialism_core::*;

impl LegacySaveV62 {
    pub fn parse(bytes: &[u8]) -> Self {
        let mut stream = LegacyStream::new(bytes);

        // The caller has selected the retail v62 reader. These fields remain in the
        // raw DTO, but do not need a second format-dispatch check here.
        stream.skip(4);
        let header = LegacySaveHeader {
            format_version: stream.read_le_u32(),
            saved_session_slot: stream.read_le_i32(),
            save_label: fixed_text(stream.read_bytes(SAVE_LABEL_LENGTH)),
            preview_owner_nation_by_tile: (0..STRATEGIC_TILE_COUNT)
                .map(|_| stream.read_i8())
                .collect(),
            preview_economic_year_offset: stream.read_le_i16(),
            preview_difficulty: stream.read_u8(),
            preview_active_nation: stream.read_u8(),
            preview_active_nation_name: fixed_text(stream.read_bytes(ACTIVE_NATION_NAME_LENGTH)),
        };

        let language_code = stream.read_le_u32();
        let economic_turn = stream.read_le_i16();
        let active_nation = stream.read_le_i16();
        let turn_state_code = stream.read_le_i16();
        let mode = stream.read_le_i16();
        let previous_turn_state_code = stream.read_le_i16();
        let previous_mode = stream.read_le_i16();
        stream.skip(1);
        let nation_count = stream.read_le_i32();
        let minor_nation_count = stream.read_le_i32();
        let turn_flow_status_flags = stream.read_le_u32();
        let difficulty = stream.read_u8();
        let game_setup = read_game_setup(&mut stream);
        let persistent_unit_id_counter = stream.read_le_i32();
        let nation_availability = stream.read_bytes(NATION_COUNT).try_into().unwrap();
        let saved_multiplayer_role = stream.read_le_i32();
        let preference_slot_10 = stream.read_le_i16();
        let selected_asset_set = stream.read_le_i16();
        let diplomacy_year_term_raw = stream.read_le_i16();
        let phase_state_by_decade = stream.read_bytes(12).try_into().unwrap();
        let nation_names = (0..NATION_COUNT)
            .map(|_| lossy_text(&stream.read_mfc_string()))
            .collect();
        let simulation = LegacySimulationPrefix {
            language_code,
            economic_turn,
            active_nation,
            turn_state_code,
            mode,
            previous_turn_state_code,
            previous_mode,
            nation_count,
            minor_nation_count,
            turn_flow_status_flags,
            difficulty,
            game_setup,
            persistent_unit_id_counter,
            nation_availability,
            saved_multiplayer_role,
            preference_slot_10,
            selected_asset_set,
            diplomacy_year_term_raw,
            phase_state_by_decade,
            nation_names,
        };

        let animator_idle_frequency = stream.read_le_i32();
        let market = read_trade_market(&mut stream);
        let diplomacy = read_diplomacy_state(&mut stream);
        let technology = read_technology_state(&mut stream);
        let map = read_map(&mut stream);
        let ocean = read_ocean(&mut stream);
        let navy = read_navy(&mut stream);
        let army_report_count = skip_army_reports(&mut stream);

        let mut archive = LegacyMfcArchiveState::default();
        let mut major_nations = Vec::new();
        for nation in 0..MAJOR_NATION_COUNT {
            if simulation.nation_availability[nation] == 0 {
                continue;
            }
            let foreign_policy_id = simulation.game_setup.foreign_minister_policy_ids[nation];
            if simulation.game_setup.nation_control_modes[nation] == 2 {
                major_nations.push(LegacyMajorNationState::Auto(Box::new(
                    read_auto_great_power_record(&mut stream, foreign_policy_id, &mut archive),
                )));
            } else {
                major_nations.push(LegacyMajorNationState::Other(Box::new(
                    read_great_power_record(&mut stream, foreign_policy_id),
                )));
            }
        }

        let mut minor_nations = Vec::new();
        for nation in MAJOR_NATION_COUNT..NATION_COUNT {
            if simulation.nation_availability[nation] != 0 {
                minor_nations.push(read_minor_record(&mut stream));
            }
        }

        // TViewMgr, TMacViewMgr, and TNewsMgr persist no fields beyond TObject.
        let help = read_help_manager(&mut stream);
        Self {
            header,
            simulation,
            animator_idle_frequency,
            market,
            diplomacy,
            technology,
            map,
            ocean,
            navy,
            army_report_count,
            major_nations,
            minor_nations,
            help,
        }
    }
}

fn read_great_power_record(
    stream: &mut LegacyStream<'_>,
    foreign_policy_id: i16,
) -> LegacyGreatPowerState {
    let country = read_country_base(stream);
    let prefix = read_great_power_prefix(stream);
    let ministers =
        read_great_power_ministers(stream, prefix.minister_presence_mask, foreign_policy_id);
    let city = (prefix.minister_presence_mask & 8 != 0).then(|| read_city(stream));
    let post_city = read_great_power_post_city(stream);
    LegacyGreatPowerState {
        country,
        prefix,
        ministers,
        city,
        post_city,
    }
}

fn read_auto_great_power_record(
    stream: &mut LegacyStream<'_>,
    foreign_policy_id: i16,
    archive: &mut LegacyMfcArchiveState,
) -> LegacyAutoGreatPowerState {
    let great_power = read_great_power_record(stream, foreign_policy_id);
    let auto_prefix = read_auto_great_power_prefix(stream);
    let missions = (0..auto_prefix.mission_count)
        .map(|_| read_mfc_mission(stream, archive))
        .collect();
    LegacyAutoGreatPowerState {
        great_power,
        auto_prefix,
        missions,
    }
}

fn read_minor_record(stream: &mut LegacyStream<'_>) -> LegacyMinorState {
    LegacyMinorState {
        country: read_country_base(stream),
        need_current_by_type: read_be_short_array(stream),
        trade_offers_by_resource: read_be_short_array(stream),
        grant_amounts_by_resource: read_be_short_array(stream),
        diplomacy_thresholds: read_short_array(stream),
        diplomacy_policy_fields: read_short_array(stream),
        diplomacy_save_fields: read_be_short_array(stream),
        diplomacy_save_extension: read_be_short_array(stream),
    }
}

fn read_help_manager(stream: &mut LegacyStream<'_>) -> LegacyHelpState {
    LegacyHelpState {
        index_records: read_fixed_record_list(stream),
        civilian_completion_counters: read_be_short_array(stream),
        help_index_ready: stream.read_le_i16(),
    }
}

pub(super) fn read_trade_market(stream: &mut LegacyStream<'_>) -> LegacyTradeMarketState {
    LegacyTradeMarketState {
        rows: std::array::from_fn(|_| read_trade_market_row(stream)),
        history: std::array::from_fn(|_| read_fixed_record_list(stream)),
    }
}

pub(super) fn read_trade_market_row(stream: &mut LegacyStream<'_>) -> LegacyTradeMarketRow {
    LegacyTradeMarketRow {
        previous_price: stream.read_le_i16(),
        price: stream.read_le_i16(),
        request_count: stream.read_le_i16(),
        offer_count: stream.read_le_i16(),
        adjusted_offer_count: f64::from_le_bytes(stream.read_bytes(8).try_into().unwrap()),
        amount_offered: stream.read_le_i16(),
        base_price: stream.read_le_i16(),
        current_offer_by_nation: read_be_short_array(stream),
        accumulated_offer_by_nation: read_be_short_array(stream),
        maximum_offer_by_nation: read_be_short_array(stream),
    }
}

pub(super) fn read_diplomacy_state(stream: &mut LegacyStream<'_>) -> LegacyDiplomacyState {
    LegacyDiplomacyState {
        relation_standing_scores: read_be_short_array(stream),
        relation_propagation_matrix: read_be_short_array(stream),
        relation_turn_stamp_matrix: read_be_short_array(stream),
        relation_code_matrix: read_be_short_array(stream),
        pending_policy_code_matrix: std::array::from_fn(|_| stream.read_i8()),
        last_diplomatic_effort_turn: stream.read_le_i16(),
        relation_side_effect_matrix: read_be_short_array(stream),
        congress_leadership: read_be_short_array(stream),
        congress_support: read_be_short_array(stream),
        special_relation_source_slots: read_be_short_array(stream),
        special_relation_target_slots: read_be_short_array(stream),
    }
}

pub(super) fn read_technology_state(stream: &mut LegacyStream<'_>) -> LegacyTechnologyState {
    LegacyTechnologyState {
        priority_slots: read_be_short_array(stream),
        initial_capability_value_by_nation_and_resource: std::array::from_fn(|_| {
            read_be_short_array(stream)
        }),
        tech_selector: stream.read_le_i16(),
        active_zone_index: stream.read_le_i16(),
        per_technology_unlock_flags: stream.read_bytes(TECHNOLOGY_COUNT).try_into().unwrap(),
        resource_type_enabled: stream.read_bytes(14).try_into().unwrap(),
        init_flags_1ab: stream.read_bytes(30).try_into().unwrap(),
        init_flags_1c9: stream.read_bytes(9).try_into().unwrap(),
        active_prerequisite_pair: read_short_array(stream),
        nation_capability_slots: std::array::from_fn(|_| read_be_short_array(stream)),
        research_status_by_nation: std::array::from_fn(|_| {
            stream.read_bytes(TECHNOLOGY_COUNT).try_into().unwrap()
        }),
        selected_resource_type_by_nation: std::array::from_fn(|_| {
            stream.read_bytes(14).try_into().unwrap()
        }),
        ability_active_by_nation: std::array::from_fn(|_| {
            stream.read_bytes(30).try_into().unwrap()
        }),
        university_recruitment_availability: std::array::from_fn(|_| {
            stream.read_bytes(9).try_into().unwrap()
        }),
        completion_year_offsets: std::array::from_fn(|_| read_be_short_array(stream)),
        capability_value_by_nation_and_resource: std::array::from_fn(|_| {
            read_be_short_array(stream)
        }),
        marker: stream.read_le_i16(),
    }
}

pub(super) fn read_map(stream: &mut LegacyStream<'_>) -> LegacyMapState {
    let view_origin_tile = stream.read_le_i16();
    let map_data_ready = stream.read_u8();
    let recruit_search_active = stream.read_u8();
    let city_score_total = stream.read_le_i32();
    let scenario_tag = lossy_text(&stream.read_mfc_string());
    let no_horizontal_wrap = stream.read_u8();
    let tiles = (0..STRATEGIC_TILE_COUNT)
        .map(|_| read_terrain_tile(stream))
        .collect();
    let provinces = (0..super::PROVINCE_COUNT)
        .map(|_| read_province(stream))
        .collect();
    let pending_river_mouth_tile = stream.read_le_i16();
    LegacyMapState {
        view_origin_tile,
        map_data_ready,
        recruit_search_active,
        city_score_total,
        scenario_tag,
        no_horizontal_wrap,
        tiles,
        provinces,
        pending_river_mouth_tile,
    }
}

pub(super) fn read_ocean(stream: &mut LegacyStream<'_>) -> LegacyOceanState {
    let zone_count = stream.read_le_u16();
    let zones = (0..zone_count).map(|_| read_zone(stream)).collect();
    let port_zone_count = stream.read_le_u16();
    let port_zones = (0..port_zone_count)
        .map(|_| LegacyPortZone {
            zone: read_zone(stream),
            port_tile_index: stream.read_le_i16(),
        })
        .collect();
    let route_count = stream.read_le_u16();
    let route_segments = (0..route_count)
        .map(|_| {
            [
                stream.read_le_i32(),
                stream.read_le_i32(),
                stream.read_le_i32(),
                stream.read_le_i32(),
            ]
        })
        .collect();
    LegacyOceanState {
        zones,
        port_zones,
        route_segments,
    }
}

pub(super) fn read_zone(stream: &mut LegacyStream<'_>) -> LegacyZone {
    LegacyZone {
        display_name: lossy_text(&stream.read_mfc_string()),
        status_code: stream.read_le_i16(),
        tile_or_terrain_id: stream.read_le_i32(),
        seed_nation_id: stream.read_le_i16(),
        active_tile_index: stream.read_le_i16(),
        context_ordinal: stream.read_le_i16(),
    }
}

pub(super) fn read_navy(stream: &mut LegacyStream<'_>) -> LegacyNavyState {
    let ship_count = stream.read_le_u16();
    let mut ships: Vec<_> = (0..ship_count).map(|_| read_ship(stream)).collect();
    // TSortedList inserts each deserialized ship at the head.
    ships.reverse();
    let admiral_count = stream.read_le_u16();
    let admirals = (0..admiral_count).map(|_| read_admiral(stream)).collect();
    let task_force_count = stream.read_le_u16();
    let task_forces = (0..task_force_count)
        .map(|_| read_task_force(stream))
        .collect();
    LegacyNavyState {
        ships,
        admirals,
        task_forces,
    }
}

fn read_ship(stream: &mut LegacyStream<'_>) -> LegacyShip {
    LegacyShip {
        ship_type: stream.read_le_i16(),
        aggression: stream.read_le_i32(),
        nation: stream.read_le_i16(),
        name: lossy_text(&stream.read_mfc_string()),
        strength: stream.read_le_i16(),
        selection: stream.read_le_i32(),
        experience: stream.read_le_i16(),
        zone_ordinal: stream.read_le_i16(),
    }
}

fn read_admiral(stream: &mut LegacyStream<'_>) -> LegacyAdmiral {
    LegacyAdmiral {
        nation: stream.read_le_i16(),
        name: lossy_text(&stream.read_mfc_string()),
        experience: stream.read_le_i16(),
        ship_index: stream.read_le_i16(),
    }
}

fn read_task_force(stream: &mut LegacyStream<'_>) -> LegacyTaskForce {
    let aggression = stream.read_le_i32();
    let order = stream.read_le_i32();
    let target_ordinal = stream.read_le_i16();
    let location_ordinal = stream.read_le_i16();
    let nation = stream.read_le_i16();
    let defeated = stream.read_u8();
    let ingot_tile = stream.read_le_i16();
    let child_count = stream.read_le_u16();
    let ships = (0..child_count)
        .map(|_| [stream.read_le_i16(), stream.read_le_i16()])
        .collect();
    LegacyTaskForce {
        aggression,
        order,
        target_ordinal,
        location_ordinal,
        nation,
        defeated,
        ingot_tile,
        ships,
    }
}

fn skip_army_reports(stream: &mut LegacyStream<'_>) -> u16 {
    let report_count = stream.read_le_u16();
    for _ in 0..report_count {
        stream.skip(8);
        for _ in 0..2 {
            stream.skip(1 + 0x20 + 0xff);
            let child_count = stream.read_le_u16() as usize;
            stream.skip(child_count * 42);
        }
    }
    report_count
}

pub(super) fn read_country_base(stream: &mut LegacyStream<'_>) -> LegacyCountryBase {
    let identity = lossy_text(&stream.read_mfc_string());
    let alternate_identity = lossy_text(&stream.read_mfc_string());
    let nation_slot = stream.read_le_i16();
    let encoded_country_status = stream.read_le_i16();
    let unit_name_ordinal_by_type = read_be_short_array(stream);
    let unit_name_counter = stream.read_le_i16();
    let treasury = stream.read_le_i32();
    let home_tile = stream.read_le_i32();
    let overlay_anchor_tile = stream.read_le_i32();
    let need_level_by_nation = read_be_short_array(stream);

    // TSortedList::ReadFrom is a retail no-op; the count follows immediately.
    let military_unit_count = stream.read_le_u32();
    let military_units = (0..military_unit_count)
        .map(|_| read_military_unit(stream))
        .collect();

    // TLongintList::NoOpReadFrom is likewise a no-op.
    let owned_region_count = stream.read_le_u32();
    let owned_regions = (0..owned_region_count)
        .map(|_| stream.read_le_i32())
        .collect();

    LegacyCountryBase {
        identity,
        alternate_identity,
        nation_slot,
        encoded_country_status,
        unit_name_ordinal_by_type,
        unit_name_counter,
        treasury,
        home_tile,
        overlay_anchor_tile,
        need_level_by_nation,
        military_units,
        owned_regions,
    }
}

fn read_military_unit(stream: &mut LegacyStream<'_>) -> LegacyMilitaryUnit {
    LegacyMilitaryUnit {
        unit_type: stream.read_le_i16(),
        stationed_province: stream.read_le_i16(),
        order_target: stream.read_le_i16(),
        owner_nation: stream.read_le_i16(),
        roster_id: stream.read_le_i16(),
        registered: stream.read_u8(),
        order: stream.read_le_i32(),
        persistent_id: stream.read_le_i32(),
        name: lossy_text(&stream.read_mfc_string()),
        order_target_tiles: read_be_short_array(stream),
        order_target_mirrors: read_be_short_array(stream),
        strength: stream.read_le_i16(),
        era: stream.read_le_i16(),
        experience: stream.read_le_i16(),
        battle_flags: stream.read_le_i16(),
    }
}

pub(super) fn read_great_power_prefix(stream: &mut LegacyStream<'_>) -> LegacyGreatPowerPrefix {
    let diplomacy_eligible = stream.read_u8();
    let capacities = read_short_array(stream);
    let grant_total_cost = stream.read_le_i32();
    let unfilled_trade_offer_count = stream.read_le_i16();
    let diplomacy_policy_by_nation = read_be_short_array(stream);
    let diplomacy_grant_by_nation = read_be_short_array(stream);
    let need_current_by_type = read_be_short_array(stream);
    let need_target_by_type = read_be_short_array(stream);
    let relation_delta_current = read_be_short_array(stream);
    let purchased_items_by_resource = read_be_short_array(stream);
    let item_potentials = read_be_short_array(stream);
    let unfilled_trade_turns_by_resource = read_be_short_array(stream);
    let transported_items_by_resource = read_be_short_array(stream);
    let remembered_trade_offers_by_resource = read_be_short_array(stream);
    let budget_pool_base = stream.read_le_i32();
    let budget_pool_delta = stream.read_le_i32();
    let aid_allocation_by_minor_nation =
        std::array::from_fn(|_| std::array::from_fn(|_| stream.read_be_i32()));
    let pending_action_status = std::array::from_fn(|_| stream.read_i8());
    let pending_action_payload_by_action = read_be_short_array(stream);
    let relationship_lists = (0..19).map(|_| read_fixed_record_list(stream)).collect();
    let minister_presence_mask = stream.read_u8();

    LegacyGreatPowerPrefix {
        diplomacy_eligible,
        capacities,
        grant_total_cost,
        unfilled_trade_offer_count,
        diplomacy_policy_by_nation,
        diplomacy_grant_by_nation,
        need_current_by_type,
        need_target_by_type,
        relation_delta_current,
        purchased_items_by_resource,
        item_potentials,
        unfilled_trade_turns_by_resource,
        transported_items_by_resource,
        remembered_trade_offers_by_resource,
        budget_pool_base,
        budget_pool_delta,
        aid_allocation_by_minor_nation,
        pending_action_status,
        pending_action_payload_by_action,
        relationship_lists,
        minister_presence_mask,
    }
}

fn read_fixed_record_list(stream: &mut LegacyStream<'_>) -> LegacyFixedRecordList {
    let record_size = stream.read_le_u16();
    let record_count = stream.read_le_u32();
    let records = (0..record_count)
        .map(|_| stream.read_bytes(usize::from(record_size)).to_vec())
        .collect();
    LegacyFixedRecordList {
        record_size,
        records,
    }
}

fn read_great_power_ministers(
    stream: &mut LegacyStream<'_>,
    presence_mask: u8,
    foreign_policy_id: i16,
) -> LegacyGreatPowerMinisters {
    LegacyGreatPowerMinisters {
        foreign: (presence_mask & 1 != 0).then(|| read_foreign_minister(stream, foreign_policy_id)),
        interior: (presence_mask & 2 != 0).then(|| read_interior_minister(stream)),
        defense: (presence_mask & 4 != 0).then(|| read_defense_minister(stream)),
    }
}

fn read_foreign_minister(
    stream: &mut LegacyStream<'_>,
    foreign_policy_id: i16,
) -> LegacyForeignMinisterState {
    LegacyForeignMinisterState {
        skill_index: stream.read_le_i16(),
        scalar_fields: read_short_array(stream),
        purchase_priority_by_resource: read_be_short_array(stream),
        preferred_resource_slots: read_be_short_array(stream),
        status_flag: stream.read_u8(),
        trade_partner_enabled: stream.read_bytes(7).try_into().unwrap(),
        development_grant_by_nation: read_be_short_array(stream),
        bill_order_flag: (foreign_policy_id == 4).then(|| stream.read_u8()),
    }
}

fn read_interior_minister(stream: &mut LegacyStream<'_>) -> LegacyInteriorMinisterState {
    LegacyInteriorMinisterState {
        skill_index: stream.read_le_i16(),
        scalar_prefix: read_short_array(stream),
        trailing_table: read_be_short_array(stream),
        order_scalars: read_short_array(stream),
        order_metrics: read_be_short_array(stream),
        deferred_labor_shortfall: stream.read_le_i16(),
        order_short_table: read_be_short_array(stream),
        order_type_tables: std::array::from_fn(|_| read_be_short_array(stream)),
        temporarily_reserved_ship_arms: stream.read_le_i16(),
        integer_lists: std::array::from_fn(|_| read_longint_list(stream)),
        civilian_order_demand_by_resource: read_be_short_array(stream),
    }
}

fn read_defense_minister(stream: &mut LegacyStream<'_>) -> LegacyDefenseMinisterState {
    LegacyDefenseMinisterState {
        skill_index: stream.read_le_i16(),
        scalar_fields: read_short_array(stream),
        recruit_order_count_by_type: read_be_short_array(stream),
        order_weight_by_type: read_be_short_array(stream),
        thresholds: read_short_array(stream),
    }
}

fn read_longint_list(stream: &mut LegacyStream<'_>) -> Vec<i32> {
    let count = stream.read_le_u32();
    (0..count).map(|_| stream.read_le_i32()).collect()
}

pub(super) fn read_city(stream: &mut LegacyStream<'_>) -> LegacyCityState {
    let power_plant_upgrade_queued = stream.read_u8();
    let low_production = stream.read_u8();
    let low_stock = stream.read_u8();
    let production_flags = stream
        .read_bytes(CITY_PRODUCTION_SLOT_COUNT)
        .try_into()
        .unwrap();
    let food_substitution_count = stream.read_le_i16();
    let starvation_population_loss = stream.read_le_i16();
    let serialized_state = stream.read_le_i16();
    let phase_counter = stream.read_le_i16();
    let power_available = stream.read_le_i16();
    let military_recruit_count_by_kind = read_be_short_array(stream);
    let civilian_recruit_count_by_kind = read_be_short_array(stream);
    let order_count_by_type = read_be_short_array(stream);
    let stockpile = read_be_short_array(stream);
    let production_orders = read_be_short_array(stream);
    let production_accum = read_be_short_array(stream);
    let unmet_resource_retries = read_be_short_array(stream);
    let reserved_by_type = read_be_short_array(stream);
    let production_current = read_be_short_array(stream);
    let production_progress = read_be_short_array(stream);
    let consumed_production_input_by_type = read_be_short_array(stream);
    let rolling_item_production_score = stream.read_le_i32();
    let population = read_population(stream);
    let orders = read_city_orders(stream);

    // TTaskList's inherited TSortedList stream hook is a no-op.
    let task_count = stream.read_le_u32();
    let tasks = (0..task_count)
        .map(|_| {
            let kind = stream.read_u8();
            let payload_size = if kind == 1 { 8 } else { 12 };
            LegacyCityTask {
                kind,
                payload: stream.read_bytes(payload_size).to_vec(),
            }
        })
        .collect();
    let transport_requests = read_fixed_record_list(stream);

    LegacyCityState {
        power_plant_upgrade_queued,
        low_production,
        low_stock,
        production_flags,
        food_substitution_count,
        starvation_population_loss,
        serialized_state,
        phase_counter,
        power_available,
        military_recruit_count_by_kind,
        civilian_recruit_count_by_kind,
        order_count_by_type,
        stockpile,
        production_orders,
        production_accum,
        unmet_resource_retries,
        reserved_by_type,
        production_current,
        production_progress,
        consumed_production_input_by_type,
        rolling_item_production_score,
        population,
        orders,
        tasks,
        transport_requests,
    }
}

pub(super) fn read_city_orders(stream: &mut LegacyStream<'_>) -> LegacyCityOrders {
    // ICity constructs these 47 concrete orders in this exact pointer-list order.
    LegacyCityOrders {
        food_processing: read_production_order(stream),
        items: std::array::from_fn(|_| read_item_order(stream)),
        training: std::array::from_fn(|_| read_production_order(stream)),
        military_recruitment: std::array::from_fn(|_| read_unit_order(stream)),
        civilian_recruitment: std::array::from_fn(|_| read_unit_order(stream)),
        ships: std::array::from_fn(|_| read_production_order(stream)),
        transport_capacity: read_item_order(stream),
        power_plant: read_power_plant_order(stream),
        expansions: std::array::from_fn(|_| read_item_order(stream)),
        population_growth: read_production_order(stream),
    }
}

pub(super) fn read_production_order(stream: &mut LegacyStream<'_>) -> LegacyProductionOrder {
    // TProductionOrder::ReadFrom reads the saved constructor value and then
    // overwrites the same field with the authoritative serialized value below.
    stream.skip(2);
    let quantity = stream.read_le_i16();
    let limiting_constraint = stream.read_le_i16();
    let resource_type_index = stream.read_le_i16();
    let tracking_slots = read_short_array(stream);
    let accumulated_value = stream.read_le_i32();
    LegacyProductionOrder {
        resource_type_index,
        quantity,
        limiting_constraint,
        tracking_slots,
        accumulated_value,
    }
}

pub(super) fn read_item_order(stream: &mut LegacyStream<'_>) -> LegacyItemOrder {
    LegacyItemOrder {
        order: read_production_order(stream),
        requested_quantity: stream.read_le_i16(),
        primary_input_resource_id: stream.read_le_i16(),
        secondary_input_resource_id: stream.read_le_i16(),
        production_slot: stream.read_le_i16(),
    }
}

fn read_unit_order(stream: &mut LegacyStream<'_>) -> LegacyUnitOrder {
    LegacyUnitOrder {
        order: read_production_order(stream),
        primary_input_resource_id: stream.read_le_i16(),
        secondary_input_resource_id: stream.read_le_i16(),
        primary_input_per_unit: stream.read_le_i16(),
        secondary_input_per_unit: stream.read_le_i16(),
        cash_cost_per_unit: stream.read_le_i16(),
        workforce_mode: stream.read_le_i16(),
        specialist_mode: stream.read_u8(),
    }
}

fn read_power_plant_order(stream: &mut LegacyStream<'_>) -> LegacyPowerPlantOrder {
    LegacyPowerPlantOrder {
        order: read_production_order(stream),
        desired_quantity: stream.read_le_i16(),
    }
}

fn read_population(stream: &mut LegacyStream<'_>) -> LegacyPopulationState {
    LegacyPopulationState {
        count: stream.read_le_i16(),
        strength: stream.read_le_i16(),
        extra: stream.read_le_i16(),
        phase_value: stream.read_le_i16(),
        // TPopulationMgr persists this block raw, unlike TCity's swapped arrays.
        predicted_need_by_resource: read_short_array(stream),
        count_float_bits: stream.read_le_u32(),
        baseline_labor: read_short_array(stream),
        production_labor: read_short_array(stream),
        pending_labor_delta: read_short_array(stream),
    }
}

fn read_great_power_post_city(stream: &mut LegacyStream<'_>) -> LegacyGreatPowerPostCity {
    let town_count = stream.read_le_u32();
    let towns = (0..town_count).map(|_| read_town(stream)).collect();
    let civilian_count = stream.read_le_u32();
    let civilian_units = (0..civilian_count)
        .map(|_| read_civilian_unit(stream))
        .collect();
    let candidate_nation_flags = stream.read_bytes(NATION_COUNT).try_into().unwrap();
    let diplomacy_budget_base = stream.read_le_i32();
    let escalation_counter = stream.read_i8();
    let pending_commitment_cost = stream.read_le_i32();
    let pressure_counter = stream.read_i8();
    let army_movement_budget = stream.read_le_i32();
    let turn_finished_flag = stream.read_u8();

    // No supported fixture has a polymorphic turn-start queue, whose object
    // payloads need their concrete runtime classes to locate the following data.
    assert_eq!(stream.read_le_u32(), 0, "unsupported turn-start queue");

    let special_resource_trade_balance = stream.read_le_i32();
    let aid_allocation_total = stream.read_le_i32();
    let colony_boycott_flags = stream.read_bytes(NATION_COUNT).try_into().unwrap();
    let military_expenses = stream.read_le_i32();
    LegacyGreatPowerPostCity {
        towns,
        civilian_units,
        candidate_nation_flags,
        diplomacy_budget_base,
        escalation_counter,
        pending_commitment_cost,
        pressure_counter,
        army_movement_budget,
        turn_finished_flag,
        special_resource_trade_balance,
        aid_allocation_total,
        colony_boycott_flags,
        military_expenses,
    }
}

fn read_town(stream: &mut LegacyStream<'_>) -> LegacyTown {
    LegacyTown {
        name: fixed_text(stream.read_bytes(0x10)),
        tile_index: stream.read_le_i16(),
        opaque_fields: read_short_array(stream),
        created_turn: stream.read_le_i16(),
        owner_nation: stream.read_le_i16(),
        resource_yield_by_type: read_be_short_array(stream),
        transport_linked: stream.read_u8(),
        enabled: stream.read_u8(),
        has_adjacent_city: stream.read_u8(),
        active: stream.read_u8(),
    }
}

fn read_civilian_unit(stream: &mut LegacyStream<'_>) -> LegacyCivilianUnit {
    LegacyCivilianUnit {
        unit_type: stream.read_le_i16(),
        tile_index: stream.read_le_i16(),
        order_target: stream.read_le_i16(),
        owner_nation: stream.read_le_i16(),
        roster_id: stream.read_le_i16(),
        registered: stream.read_u8(),
        order: stream.read_le_i32(),
        persistent_id: stream.read_le_i32(),
        remaining_turns: stream.read_le_i16(),
    }
}

fn read_auto_great_power_prefix(stream: &mut LegacyStream<'_>) -> LegacyAutoGreatPowerPrefix {
    LegacyAutoGreatPowerPrefix {
        action_metric_by_quarter: read_be_short_array(stream),
        map_node_state_flags: stream.read_bytes(0x180).try_into().unwrap(),
        port_zone_state_flags: stream.read_bytes(0x70).try_into().unwrap(),
        mission_count: stream.read_le_u32(),
    }
}

fn read_mfc_mission(
    stream: &mut LegacyStream<'_>,
    archive: &mut LegacyMfcArchiveState,
) -> LegacyMission {
    const NEW_CLASS_TAG: u16 = 0xffff;
    const CLASS_TAG: u16 = 0x8000;
    const BIG_TAG: u16 = 0x7fff;
    const BIG_CLASS_TAG: u32 = 0x8000_0000;

    let word_tag = stream.read_le_u16();
    let object_tag = if word_tag == BIG_TAG {
        stream.read_le_u32()
    } else {
        (u32::from(word_tag & CLASS_TAG) << 16) | u32::from(word_tag & !CLASS_TAG)
    };
    let class = if word_tag == NEW_CLASS_TAG {
        stream.skip(2);
        let name_length = usize::from(stream.read_le_u16());
        let name = lossy_text(stream.read_bytes(name_length));
        archive.entries.push(Some(name.clone()));
        name
    } else {
        let class_index = (object_tag & !BIG_CLASS_TAG) as usize;
        archive.entries[class_index].clone().unwrap()
    };

    // ReadObject reserves the object index before invoking Serialize, allowing cycles.
    archive.entries.push(None);
    read_mission_payload(stream, &class)
}

fn read_mission_payload(stream: &mut LegacyStream<'_>, class: &str) -> LegacyMission {
    let common = LegacyMissionCommon {
        source_nation: stream.read_le_i16(),
        state: stream.read_u8(),
        importance_bits: stream.read_le_u32(),
        flag: stream.read_u8(),
        path_marker: stream.read_le_i16(),
        marker: stream.read_u8(),
    };

    match class {
        "TDefendProvinceMission" => LegacyMission::DefendProvince {
            common,
            army: read_army_mission(stream),
        },
        "TAttackProvinceMission" => {
            let army = read_army_mission(stream);
            let target_province = stream.read_le_i16();
            let amassing_province = stream.read_le_i16();
            LegacyMission::AttackProvince {
                common,
                army,
                target_province,
                amassing_province,
            }
        }
        "TInvadeMission" => {
            let army = read_army_mission(stream);
            let target_province = stream.read_le_i16();
            let amassing_province = stream.read_le_i16();
            let beachhead = read_navy_mission(stream);
            LegacyMission::Invade {
                common,
                army,
                target_province,
                amassing_province,
                beachhead,
            }
        }
        "TControlSeaZoneMission" => LegacyMission::ControlSeaZone {
            common,
            navy: read_navy_mission(stream),
        },
        "TEscortMission" => LegacyMission::Escort {
            common,
            navy: read_navy_mission(stream),
        },
        "TScatteredShipsMission" => LegacyMission::ScatteredShips {
            common,
            navy: read_navy_mission(stream),
        },
        "TBeachheadMission" => LegacyMission::Beachhead {
            common,
            navy: read_navy_mission(stream),
        },
        "TBlockadePortMission" => LegacyMission::BlockadePort {
            common,
            navy: read_navy_mission(stream),
            blockade_port_zone: stream.read_le_i16(),
        },
        _ => panic!("unsupported mission runtime class {class}"),
    }
}

fn read_army_mission(stream: &mut LegacyStream<'_>) -> LegacyArmyMission {
    let present_location = stream.read_le_i16();
    let required_equipage_bits = read_be_u32_array(stream);
    let count = stream.read_le_i16() as usize;
    let unit_ordinals = (0..count).map(|_| stream.read_le_i16()).collect();
    LegacyArmyMission {
        present_location,
        required_equipage_bits,
        unit_ordinals,
    }
}

fn read_navy_mission(stream: &mut LegacyStream<'_>) -> LegacyNavyMission {
    let target_zone = stream.read_le_i16();
    let resolved_port_zone = stream.read_le_i16();
    let required_equipage_bits = read_be_u32_array(stream);
    let mut ship_ordinals = Vec::new();
    loop {
        let ordinal = stream.read_le_i16();
        if ordinal < 0 {
            break;
        }
        ship_ordinals.push(ordinal);
    }
    let state = stream.read_le_i32();
    LegacyNavyMission {
        target_zone,
        resolved_port_zone,
        required_equipage_bits,
        ship_ordinals,
        state,
    }
}

fn read_terrain_tile(stream: &mut LegacyStream<'_>) -> LegacyTerrainTile {
    let bytes = stream.read_bytes(TERRAIN_TILE_SERIALIZED_SIZE);
    LegacyTerrainTile {
        terrain_kind: bytes[0] as i8,
        sprite_variant: bytes[1],
        river_sprite: bytes[2],
        former_owner_nation: bytes[3] as i8,
        owner_nation: bytes[4] as i8,
        secondary_owner_nation: bytes[0x18] as i8,
        owner_border_mask: bytes[7],
        city_border_mask: bytes[8],
        water_adjacency_mask: bytes[9],
        region: bytes[5] as i8,
        adjacency_bits: bytes[6],
        adjacency_mask_a: bytes[0x0a],
        adjacency_mask_b: bytes[0x0b],
        development_classes: bytes[0x0c] as i8,
        pending_development_visibility: bytes[0x0d],
        recruit_search_visited: bytes[0x0e],
        per_tile_visited: bytes[0x0f] as i8,
        marker_slot_index: bytes[0x10] as i8,
        edge_resources: [bytes[0x11] as i8, bytes[0x12] as i8],
        gate: bytes[0x13] as i8,
        city_record_index: i16::from_le_bytes(bytes[0x14..0x16].try_into().unwrap()),
        action_state: bytes[0x16] as i8,
        rail_flags: bytes[0x17],
        tile_action_ordinal: i16::from_le_bytes(bytes[0x1a..0x1c].try_into().unwrap()),
        active_flags: u16::from_le_bytes(bytes[0x1c..0x1e].try_into().unwrap()),
    }
}

fn read_province(stream: &mut LegacyStream<'_>) -> LegacyProvince {
    let bytes = stream.read_bytes(PROVINCE_FIXED_SERIALIZED_SIZE);
    let name = lossy_text(&stream.read_mfc_string());
    LegacyProvince {
        owner_nation: bytes[0] as i8,
        former_owner_nation: bytes[1] as i8,
        development_stage: bytes[2] as i8,
        fort_level: bytes[3] as i8,
        city_tile: i16::from_le_bytes(bytes[4..6].try_into().unwrap()),
        last_turn_tick: i16::from_le_bytes(bytes[6..8].try_into().unwrap()),
        adjacent_region_count: bytes[8] as i8,
        adjacent_region_ids: std::array::from_fn(|index| {
            let offset = 0x0a + index * 2;
            i16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
        }),
        adjacent_region_anchor_tiles: std::array::from_fn(|index| {
            let offset = 0x22 + index * 2;
            i16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
        }),
        linked_region_count: bytes[0x3a] as i8,
        secondary_neighbor_tile: i16::from_le_bytes(bytes[0x3e..0x40].try_into().unwrap()),
        primary_neighbor_tile: i16::from_le_bytes(bytes[0x40..0x42].try_into().unwrap()),
        linked_tile_indices: std::array::from_fn(|index| {
            let offset = 0x42 + index * 2;
            i16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
        }),
        resource_development_by_type: std::array::from_fn(|index| {
            let offset = 0x82 + index * 2;
            i16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
        }),
        city_score: i32::from_le_bytes(bytes[0x9c..0xa0].try_into().unwrap()),
        navy_order_reachable: bytes[0xa0],
        explored_by_nation_mask: bytes[0xa1],
        resource_presence_mask: bytes[0xa2] as i8,
        region_class: bytes[0xa3] as i8,
        name,
    }
}

pub(super) fn read_game_setup(stream: &mut LegacyStream<'_>) -> LegacyGameSetup {
    let multiplayer_game_active = stream.read_u8();
    stream.skip(1);
    let nation_control_modes = read_short_array(stream);
    let city_minister_policy_ids = read_short_array(stream);
    let foreign_minister_policy_ids = read_short_array(stream);
    let defense_minister_policy_ids = read_short_array(stream);
    let reload_political_map_state = stream.read_u8();
    stream.skip(1);
    let scenario_map_index_plus_one = stream.read_le_i16();
    LegacyGameSetup {
        multiplayer_game_active,
        nation_control_modes,
        city_minister_policy_ids,
        foreign_minister_policy_ids,
        defense_minister_policy_ids,
        reload_political_map_state,
        scenario_map_index_plus_one,
    }
}

fn read_short_array<const N: usize>(stream: &mut LegacyStream<'_>) -> [i16; N] {
    std::array::from_fn(|_| stream.read_le_i16())
}

fn read_be_short_array<const N: usize>(stream: &mut LegacyStream<'_>) -> [i16; N] {
    std::array::from_fn(|_| stream.read_be_i16())
}

fn read_be_u32_array<const N: usize>(stream: &mut LegacyStream<'_>) -> [u32; N] {
    std::array::from_fn(|_| u32::from_be_bytes(stream.read_bytes(4).try_into().unwrap()))
}

fn fixed_text(bytes: &[u8]) -> String {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    lossy_text(&bytes[..length])
}

fn lossy_text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
