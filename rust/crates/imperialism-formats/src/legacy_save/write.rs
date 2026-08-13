use super::model::*;
use super::*;
use crate::legacy_stream::LegacyWriter;
use imperialism_core::*;

impl LegacySaveV62 {
    pub(super) fn has_task_forces(&self) -> bool {
        !self.navy.task_forces.is_empty()
    }

    pub(super) fn has_city_tasks(&self) -> bool {
        self.major_nations.iter().any(|nation| {
            nation
                .great_power()
                .city
                .as_ref()
                .is_some_and(|city| !city.tasks.is_empty())
        })
    }

    pub(super) fn has_transport_requests(&self) -> bool {
        self.major_nations.iter().any(|nation| {
            nation
                .great_power()
                .city
                .as_ref()
                .is_some_and(|city| !city.transport_requests.records.is_empty())
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut writer = LegacyWriter::new();
        writer.write_le_u32(super::slots::SAVE_MAGIC);
        writer.write_le_u32(self.header.format_version);
        writer.write_le_i32(self.header.saved_session_slot);
        writer.write_fixed_text(&self.header.save_label, SAVE_LABEL_LENGTH);
        assert_eq!(
            self.header.preview_owner_nation_by_tile.len(),
            STRATEGIC_TILE_COUNT
        );
        for tag in &self.header.preview_owner_nation_by_tile {
            writer.write_i8(*tag);
        }
        writer.write_le_i16(self.header.preview_economic_year_offset);
        writer.write_u8(self.header.preview_difficulty);
        writer.write_u8(self.header.preview_active_nation);
        writer.write_fixed_text(
            &self.header.preview_active_nation_name,
            ACTIVE_NATION_NAME_LENGTH,
        );

        writer.write_le_u32(self.simulation.language_code);
        writer.write_le_i16(self.simulation.economic_turn);
        writer.write_le_i16(self.simulation.active_nation);
        writer.write_le_i16(self.simulation.turn_state_code);
        writer.write_le_i16(self.simulation.mode);
        writer.write_le_i16(self.simulation.previous_turn_state_code);
        writer.write_le_i16(self.simulation.previous_mode);
        writer.write_u8(0);
        writer.write_le_i32(self.simulation.nation_count);
        writer.write_le_i32(self.simulation.minor_nation_count);
        writer.write_le_u32(self.simulation.turn_flow_status_flags);
        writer.write_u8(self.simulation.difficulty);
        write_game_setup(&mut writer, &self.simulation.game_setup);
        writer.write_le_i32(self.simulation.persistent_unit_id_counter);
        writer.write_bytes(&self.simulation.nation_availability);
        writer.write_le_i32(self.simulation.saved_multiplayer_role);
        writer.write_le_i16(self.simulation.preference_slot_10);
        writer.write_le_i16(self.simulation.selected_asset_set);
        writer.write_le_i16(self.simulation.diplomacy_year_term_raw);
        writer.write_bytes(&self.simulation.phase_state_by_decade);
        for name in &self.simulation.nation_names {
            writer.write_mfc_string(name);
        }

        writer.write_le_i32(self.animator_idle_frequency);
        write_trade_market(&mut writer, &self.market);
        write_diplomacy_state(&mut writer, &self.diplomacy);
        write_technology_state(&mut writer, &self.technology);
        write_map(&mut writer, &self.map);
        write_ocean(&mut writer, &self.ocean);
        write_navy(&mut writer, &self.navy);
        write_army_reports(&mut writer, self.army_report_count);

        let mut archive = vec![None];
        for nation in &self.major_nations {
            match nation {
                LegacyMajorNationState::Auto(auto) => {
                    write_great_power(&mut writer, &auto.great_power);
                    write_auto_great_power_prefix(
                        &mut writer,
                        &auto.auto_prefix,
                        auto.missions.len() as u32,
                    );
                    for mission in &auto.missions {
                        write_mfc_mission(&mut writer, mission, &mut archive);
                    }
                }
                LegacyMajorNationState::Other(power) => write_great_power(&mut writer, power),
            }
        }
        for nation in &self.minor_nations {
            write_minor(&mut writer, nation);
        }
        write_help(&mut writer, &self.help);
        writer.into_bytes()
    }
}

fn write_game_setup(writer: &mut LegacyWriter, setup: &LegacyGameSetup) {
    writer.write_u8(setup.multiplayer_game_active);
    writer.write_u8(0);
    write_le_short_array(writer, &setup.nation_control_modes);
    write_le_short_array(writer, &setup.city_minister_policy_ids);
    write_le_short_array(writer, &setup.foreign_minister_policy_ids);
    write_le_short_array(writer, &setup.defense_minister_policy_ids);
    writer.write_u8(setup.reload_political_map_state);
    writer.write_u8(0);
    writer.write_le_i16(setup.scenario_map_index_plus_one);
}

fn write_trade_market(writer: &mut LegacyWriter, market: &LegacyTradeMarketState) {
    for row in &market.rows {
        writer.write_le_i16(row.previous_price);
        writer.write_le_i16(row.price);
        writer.write_le_i16(row.request_count);
        writer.write_le_i16(row.offer_count);
        writer.write_f64_le(row.adjusted_offer_count);
        writer.write_le_i16(row.amount_offered);
        writer.write_le_i16(row.base_price);
        write_be_short_array(writer, &row.current_offer_by_nation);
        write_be_short_array(writer, &row.accumulated_offer_by_nation);
        write_be_short_array(writer, &row.maximum_offer_by_nation);
    }
    for history in &market.history {
        write_fixed_record_list(writer, history);
    }
}

fn write_diplomacy_state(writer: &mut LegacyWriter, diplomacy: &LegacyDiplomacyState) {
    write_be_short_array(writer, &diplomacy.relation_standing_scores);
    write_be_short_array(writer, &diplomacy.relation_propagation_matrix);
    write_be_short_array(writer, &diplomacy.relation_turn_stamp_matrix);
    write_be_short_array(writer, &diplomacy.relation_code_matrix);
    for value in diplomacy.pending_policy_code_matrix {
        writer.write_i8(value);
    }
    writer.write_le_i16(diplomacy.last_diplomatic_effort_turn);
    write_be_short_array(writer, &diplomacy.relation_side_effect_matrix);
    write_be_short_array(writer, &diplomacy.congress_leadership);
    write_be_short_array(writer, &diplomacy.congress_support);
    write_be_short_array(writer, &diplomacy.special_relation_source_slots);
    write_be_short_array(writer, &diplomacy.special_relation_target_slots);
}

fn write_technology_state(writer: &mut LegacyWriter, technology: &LegacyTechnologyState) {
    write_be_short_array(writer, &technology.priority_slots);
    for row in &technology.initial_capability_value_by_nation_and_resource {
        write_be_short_array(writer, row);
    }
    writer.write_le_i16(technology.tech_selector);
    writer.write_le_i16(technology.active_zone_index);
    writer.write_bytes(&technology.per_technology_unlock_flags);
    writer.write_bytes(&technology.resource_type_enabled);
    writer.write_bytes(&technology.init_flags_1ab);
    writer.write_bytes(&technology.init_flags_1c9);
    write_le_short_array(writer, &technology.active_prerequisite_pair);
    for row in &technology.nation_capability_slots {
        write_be_short_array(writer, row);
    }
    for row in &technology.research_status_by_nation {
        writer.write_bytes(row);
    }
    for row in &technology.selected_resource_type_by_nation {
        writer.write_bytes(row);
    }
    for row in &technology.ability_active_by_nation {
        writer.write_bytes(row);
    }
    for row in &technology.university_recruitment_availability {
        writer.write_bytes(row);
    }
    for row in &technology.completion_year_offsets {
        write_be_short_array(writer, row);
    }
    for row in &technology.capability_value_by_nation_and_resource {
        write_be_short_array(writer, row);
    }
    writer.write_le_i16(technology.marker);
}

fn write_map(writer: &mut LegacyWriter, map: &LegacyMapState) {
    writer.write_le_i16(map.view_origin_tile);
    writer.write_u8(map.map_data_ready);
    writer.write_u8(map.recruit_search_active);
    writer.write_le_i32(map.city_score_total);
    writer.write_mfc_string(&map.scenario_tag);
    writer.write_u8(map.no_horizontal_wrap);
    for tile in &map.tiles {
        write_terrain_tile(writer, tile);
    }
    for province in &map.provinces {
        write_province(writer, province);
    }
    writer.write_le_i16(map.pending_river_mouth_tile);
}

fn write_terrain_tile(writer: &mut LegacyWriter, tile: &LegacyTerrainTile) {
    let mut bytes = [0_u8; TERRAIN_TILE_SERIALIZED_SIZE];
    bytes[0] = tile.terrain_kind as u8;
    bytes[1] = tile.sprite_variant;
    bytes[2] = tile.river_sprite;
    bytes[3] = tile.former_owner_nation as u8;
    bytes[4] = tile.owner_nation as u8;
    bytes[5] = tile.region as u8;
    bytes[6] = tile.adjacency_bits;
    bytes[7] = tile.owner_border_mask;
    bytes[8] = tile.city_border_mask;
    bytes[9] = tile.water_adjacency_mask;
    bytes[0x0a] = tile.adjacency_mask_a;
    bytes[0x0b] = tile.adjacency_mask_b;
    bytes[0x0c] = tile.development_classes as u8;
    bytes[0x0d] = tile.pending_development_visibility;
    bytes[0x0e] = tile.recruit_search_visited;
    bytes[0x0f] = tile.per_tile_visited as u8;
    bytes[0x10] = tile.marker_slot_index as u8;
    bytes[0x11] = tile.edge_resources[0] as u8;
    bytes[0x12] = tile.edge_resources[1] as u8;
    bytes[0x13] = tile.gate as u8;
    bytes[0x14..0x16].copy_from_slice(&tile.city_record_index.to_le_bytes());
    bytes[0x16] = tile.action_state as u8;
    bytes[0x17] = tile.rail_flags;
    bytes[0x18] = tile.secondary_owner_nation as u8;
    bytes[0x1a..0x1c].copy_from_slice(&tile.tile_action_ordinal.to_le_bytes());
    bytes[0x1c..0x1e].copy_from_slice(&tile.active_flags.to_le_bytes());
    writer.write_bytes(&bytes);
}

fn write_province(writer: &mut LegacyWriter, province: &LegacyProvince) {
    let mut bytes = [0_u8; PROVINCE_FIXED_SERIALIZED_SIZE];
    bytes[0] = province.owner_nation as u8;
    bytes[1] = province.former_owner_nation as u8;
    bytes[2] = province.development_stage as u8;
    bytes[3] = province.fort_level as u8;
    bytes[4..6].copy_from_slice(&province.city_tile.to_le_bytes());
    bytes[6..8].copy_from_slice(&province.last_turn_tick.to_le_bytes());
    bytes[8] = province.adjacent_region_count as u8;
    for (index, value) in province.adjacent_region_ids.iter().enumerate() {
        let offset = 0x0a + index * 2;
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (index, value) in province.adjacent_region_anchor_tiles.iter().enumerate() {
        let offset = 0x22 + index * 2;
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes[0x3a] = province.linked_region_count as u8;
    bytes[0x3e..0x40].copy_from_slice(&province.secondary_neighbor_tile.to_le_bytes());
    bytes[0x40..0x42].copy_from_slice(&province.primary_neighbor_tile.to_le_bytes());
    for (index, value) in province.linked_tile_indices.iter().enumerate() {
        let offset = 0x42 + index * 2;
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    for (index, value) in province.resource_development_by_type.iter().enumerate() {
        let offset = 0x82 + index * 2;
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    bytes[0x9c..0xa0].copy_from_slice(&province.city_score.to_le_bytes());
    bytes[0xa0] = province.navy_order_reachable;
    bytes[0xa1] = province.explored_by_nation_mask;
    bytes[0xa2] = province.resource_presence_mask as u8;
    bytes[0xa3] = province.region_class as u8;
    writer.write_bytes(&bytes);
    writer.write_mfc_string(&province.name);
}

fn write_ocean(writer: &mut LegacyWriter, ocean: &LegacyOceanState) {
    writer.write_le_u16(ocean.zones.len() as u16);
    for zone in &ocean.zones {
        write_zone(writer, zone);
    }
    writer.write_le_u16(ocean.port_zones.len() as u16);
    for port in &ocean.port_zones {
        write_zone(writer, &port.zone);
        writer.write_le_i16(port.port_tile_index);
    }
    writer.write_le_u16(ocean.route_segments.len() as u16);
    for segment in &ocean.route_segments {
        for value in segment {
            writer.write_le_i32(*value);
        }
    }
}

fn write_zone(writer: &mut LegacyWriter, zone: &LegacyZone) {
    writer.write_mfc_string(&zone.display_name);
    writer.write_le_i16(zone.status_code);
    writer.write_le_i32(zone.tile_or_terrain_id);
    writer.write_le_i16(zone.seed_nation_id);
    writer.write_le_i16(zone.active_tile_index);
    writer.write_le_i16(zone.context_ordinal);
}

fn write_navy(writer: &mut LegacyWriter, navy: &LegacyNavyState) {
    writer.write_le_u16(navy.ships.len() as u16);
    for ship in navy.ships.iter().rev() {
        writer.write_le_i16(ship.ship_type);
        writer.write_le_i32(ship.aggression);
        writer.write_le_i16(ship.nation);
        writer.write_mfc_string(&ship.name);
        writer.write_le_i16(ship.strength);
        writer.write_le_i32(ship.selection);
        writer.write_le_i16(ship.experience);
        writer.write_le_i16(ship.zone_ordinal);
    }
    writer.write_le_u16(navy.admirals.len() as u16);
    for admiral in &navy.admirals {
        writer.write_le_i16(admiral.nation);
        writer.write_mfc_string(&admiral.name);
        writer.write_le_i16(admiral.experience);
        writer.write_le_i16(admiral.ship_index);
    }
    writer.write_le_u16(navy.task_forces.len() as u16);
    for force in &navy.task_forces {
        writer.write_le_i32(force.aggression);
        writer.write_le_i32(force.order);
        writer.write_le_i16(force.target_ordinal);
        writer.write_le_i16(force.location_ordinal);
        writer.write_le_i16(force.nation);
        writer.write_u8(force.defeated);
        writer.write_le_i16(force.ingot_tile);
        writer.write_le_u16(force.ships.len() as u16);
        for pair in &force.ships {
            writer.write_le_i16(pair[0]);
            writer.write_le_i16(pair[1]);
        }
    }
}

fn write_army_reports(writer: &mut LegacyWriter, report_count: u16) {
    writer.write_le_u16(report_count);
    for _ in 0..report_count {
        writer.write_zeros(8);
        for _ in 0..2 {
            writer.write_zeros(1 + 0x20 + 0xff);
            writer.write_le_u16(0);
        }
    }
}

fn write_great_power(writer: &mut LegacyWriter, power: &LegacyGreatPowerState) {
    write_country_base(writer, &power.country);
    write_great_power_prefix(
        writer,
        &power.prefix,
        minister_presence_mask(&power.ministers, power.city.is_some()),
    );
    write_great_power_ministers(writer, &power.ministers);
    if let Some(city) = &power.city {
        write_city(writer, city);
    }
    write_great_power_post_city(writer, &power.post_city);
}

fn minister_presence_mask(ministers: &LegacyGreatPowerMinisters, has_city: bool) -> u8 {
    let mut mask = 0;
    if ministers.foreign.is_some() {
        mask |= 1;
    }
    if ministers.interior.is_some() {
        mask |= 2;
    }
    if ministers.defense.is_some() {
        mask |= 4;
    }
    if has_city {
        mask |= 8;
    }
    mask
}

fn write_country_base(writer: &mut LegacyWriter, country: &LegacyCountryBase) {
    writer.write_mfc_string(&country.identity);
    writer.write_mfc_string(&country.alternate_identity);
    writer.write_le_i16(country.nation_slot);
    writer.write_le_i16(country.encoded_country_status);
    write_be_short_array(writer, &country.unit_name_ordinal_by_type);
    writer.write_le_i16(country.unit_name_counter);
    writer.write_le_i32(country.treasury);
    writer.write_le_i32(country.home_tile);
    writer.write_le_i32(country.overlay_anchor_tile);
    write_be_short_array(writer, &country.need_level_by_nation);
    writer.write_le_u32(country.military_units.len() as u32);
    for unit in &country.military_units {
        write_military_unit(writer, unit);
    }
    writer.write_le_u32(country.owned_regions.len() as u32);
    for region in &country.owned_regions {
        writer.write_le_i32(*region);
    }
}

fn write_military_unit(writer: &mut LegacyWriter, unit: &LegacyMilitaryUnit) {
    writer.write_le_i16(unit.unit_type);
    writer.write_le_i16(unit.stationed_province);
    writer.write_le_i16(unit.order_target);
    writer.write_le_i16(unit.owner_nation);
    writer.write_le_i16(unit.roster_id);
    writer.write_u8(unit.registered);
    writer.write_le_i32(unit.order);
    writer.write_le_i32(unit.persistent_id);
    writer.write_mfc_string(&unit.name);
    write_be_short_array(writer, &unit.order_target_tiles);
    write_be_short_array(writer, &unit.order_target_mirrors);
    writer.write_le_i16(unit.strength);
    writer.write_le_i16(unit.era);
    writer.write_le_i16(unit.experience);
    writer.write_le_i16(unit.battle_flags);
}

fn write_great_power_prefix(writer: &mut LegacyWriter, prefix: &LegacyGreatPowerPrefix, mask: u8) {
    writer.write_u8(prefix.diplomacy_eligible);
    write_le_short_array(writer, &prefix.capacities);
    writer.write_le_i32(prefix.grant_total_cost);
    writer.write_le_i16(prefix.unfilled_trade_offer_count);
    write_be_short_array(writer, &prefix.diplomacy_policy_by_nation);
    write_be_short_array(writer, &prefix.diplomacy_grant_by_nation);
    write_be_short_array(writer, &prefix.need_current_by_type);
    write_be_short_array(writer, &prefix.need_target_by_type);
    write_be_short_array(writer, &prefix.relation_delta_current);
    write_be_short_array(writer, &prefix.purchased_items_by_resource);
    write_be_short_array(writer, &prefix.item_potentials);
    write_be_short_array(writer, &prefix.unfilled_trade_turns_by_resource);
    write_be_short_array(writer, &prefix.transported_items_by_resource);
    write_be_short_array(writer, &prefix.remembered_trade_offers_by_resource);
    writer.write_le_i32(prefix.budget_pool_base);
    writer.write_le_i32(prefix.budget_pool_delta);
    for row in &prefix.aid_allocation_by_minor_nation {
        for value in row {
            writer.write_be_i32(*value);
        }
    }
    for status in prefix.pending_action_status {
        writer.write_i8(status);
    }
    write_be_short_array(writer, &prefix.pending_action_payload_by_action);
    write_fixed_record_list(writer, &prefix.turn_event_queue);
    write_fixed_record_list(writer, &prefix.proposal_queue);
    for list in &prefix.diplomacy_tracked_slots {
        write_fixed_record_list(writer, list);
    }
    writer.write_u8(mask);
}

fn write_great_power_ministers(writer: &mut LegacyWriter, ministers: &LegacyGreatPowerMinisters) {
    if let Some(foreign) = &ministers.foreign {
        writer.write_le_i16(foreign.skill_index);
        write_le_short_array(writer, &foreign.scalar_fields);
        write_be_short_array(writer, &foreign.purchase_priority_by_resource);
        write_be_short_array(writer, &foreign.preferred_resource_slots);
        writer.write_u8(foreign.status_flag);
        writer.write_bytes(&foreign.trade_partner_enabled);
        write_be_short_array(writer, &foreign.development_grant_by_nation);
        if let Some(flag) = foreign.bill_order_flag {
            writer.write_u8(flag);
        }
    }
    if let Some(interior) = &ministers.interior {
        writer.write_le_i16(interior.skill_index);
        write_le_short_array(writer, &interior.scalar_prefix);
        write_be_short_array(writer, &interior.trailing_table);
        write_le_short_array(writer, &interior.order_scalars);
        write_be_short_array(writer, &interior.order_metrics);
        writer.write_le_i16(interior.deferred_labor_shortfall);
        write_be_short_array(writer, &interior.order_short_table);
        for table in &interior.order_type_tables {
            write_be_short_array(writer, table);
        }
        writer.write_le_i16(interior.temporarily_reserved_ship_arms);
        for list in &interior.integer_lists {
            writer.write_le_u32(list.len() as u32);
            for value in list {
                writer.write_le_i32(*value);
            }
        }
        write_be_short_array(writer, &interior.civilian_order_demand_by_resource);
    }
    if let Some(defense) = &ministers.defense {
        writer.write_le_i16(defense.skill_index);
        write_le_short_array(writer, &defense.scalar_fields);
        write_be_short_array(writer, &defense.recruit_order_count_by_type);
        write_be_short_array(writer, &defense.order_weight_by_type);
        write_le_short_array(writer, &defense.thresholds);
    }
}

fn write_city(writer: &mut LegacyWriter, city: &LegacyCityState) {
    writer.write_u8(city.power_plant_upgrade_queued);
    writer.write_u8(city.low_production);
    writer.write_u8(city.low_stock);
    writer.write_bytes(&city.production_flags);
    writer.write_le_i16(city.food_substitution_count);
    writer.write_le_i16(city.starvation_population_loss);
    writer.write_le_i16(city.serialized_state);
    writer.write_le_i16(city.phase_counter);
    writer.write_le_i16(city.power_available);
    write_be_short_array(writer, &city.military_recruit_count_by_kind);
    write_be_short_array(writer, &city.civilian_recruit_count_by_kind);
    write_be_short_array(writer, &city.order_count_by_type);
    write_be_short_array(writer, &city.stockpile);
    write_be_short_array(writer, &city.production_orders);
    write_be_short_array(writer, &city.production_accum);
    write_be_short_array(writer, &city.unmet_resource_retries);
    write_be_short_array(writer, &city.reserved_by_type);
    write_be_short_array(writer, &city.production_current);
    write_be_short_array(writer, &city.production_progress);
    write_be_short_array(writer, &city.consumed_production_input_by_type);
    writer.write_le_i32(city.rolling_item_production_score);
    write_population(writer, &city.population);
    write_city_orders(writer, &city.orders);
    writer.write_le_u32(city.tasks.len() as u32);
    for task in &city.tasks {
        writer.write_u8(task.kind);
        writer.write_bytes(&task.payload);
    }
    write_fixed_record_list(writer, &city.transport_requests);
}

fn write_population(writer: &mut LegacyWriter, population: &LegacyPopulationState) {
    writer.write_le_i16(population.count);
    writer.write_le_i16(population.strength);
    writer.write_le_i16(population.extra);
    writer.write_le_i16(population.phase_value);
    write_le_short_array(writer, &population.predicted_need_by_resource);
    writer.write_le_u32(population.count_float_bits);
    write_le_short_array(writer, &population.baseline_labor);
    write_le_short_array(writer, &population.production_labor);
    write_le_short_array(writer, &population.pending_labor_delta);
}

fn write_city_orders(writer: &mut LegacyWriter, orders: &LegacyCityOrders) {
    write_production_order(writer, &orders.food_processing);
    for order in &orders.items {
        write_item_order(writer, order);
    }
    for order in &orders.training {
        write_production_order(writer, order);
    }
    for order in &orders.military_recruitment {
        write_unit_order(writer, order);
    }
    for order in &orders.civilian_recruitment {
        write_unit_order(writer, order);
    }
    for order in &orders.ships {
        write_production_order(writer, order);
    }
    write_item_order(writer, &orders.transport_capacity);
    write_production_order(writer, &orders.power_plant.order);
    writer.write_le_i16(orders.power_plant.desired_quantity);
    for order in &orders.expansions {
        write_item_order(writer, order);
    }
    write_production_order(writer, &orders.population_growth);
}

fn write_production_order(writer: &mut LegacyWriter, order: &LegacyProductionOrder) {
    writer.write_le_i16(order.quantity);
    writer.write_le_i16(order.quantity);
    writer.write_le_i16(order.limiting_constraint);
    writer.write_le_i16(order.resource_type_index);
    write_le_short_array(writer, &order.tracking_slots);
    writer.write_le_i32(order.accumulated_value);
}

fn write_item_order(writer: &mut LegacyWriter, order: &LegacyItemOrder) {
    write_production_order(writer, &order.order);
    writer.write_le_i16(order.requested_quantity);
    writer.write_le_i16(order.primary_input_resource_id);
    writer.write_le_i16(order.secondary_input_resource_id);
    writer.write_le_i16(order.production_slot);
}

fn write_unit_order(writer: &mut LegacyWriter, order: &LegacyUnitOrder) {
    write_production_order(writer, &order.order);
    writer.write_le_i16(order.primary_input_resource_id);
    writer.write_le_i16(order.secondary_input_resource_id);
    writer.write_le_i16(order.primary_input_per_unit);
    writer.write_le_i16(order.secondary_input_per_unit);
    writer.write_le_i16(order.cash_cost_per_unit);
    writer.write_le_i16(order.workforce_mode);
    writer.write_u8(order.specialist_mode);
}

fn write_great_power_post_city(writer: &mut LegacyWriter, post: &LegacyGreatPowerPostCity) {
    writer.write_le_u32(post.towns.len() as u32);
    for town in &post.towns {
        writer.write_fixed_text(&town.name, 0x10);
        writer.write_le_i16(town.tile_index);
        write_le_short_array(writer, &town.opaque_fields);
        writer.write_le_i16(town.created_turn);
        writer.write_le_i16(town.owner_nation);
        write_be_short_array(writer, &town.resource_yield_by_type);
        writer.write_u8(town.transport_linked);
        writer.write_u8(town.enabled);
        writer.write_u8(town.has_adjacent_city);
        writer.write_u8(town.active);
    }
    writer.write_le_u32(post.civilian_units.len() as u32);
    for unit in &post.civilian_units {
        writer.write_le_i16(unit.unit_type);
        writer.write_le_i16(unit.tile_index);
        writer.write_le_i16(unit.order_target);
        writer.write_le_i16(unit.owner_nation);
        writer.write_le_i16(unit.roster_id);
        writer.write_u8(unit.registered);
        writer.write_le_i32(unit.order);
        writer.write_le_i32(unit.persistent_id);
        writer.write_le_i16(unit.remaining_turns);
    }
    writer.write_bytes(&post.candidate_nation_flags);
    writer.write_le_i32(post.diplomacy_budget_base);
    writer.write_i8(post.escalation_counter);
    writer.write_le_i32(post.pending_commitment_cost);
    writer.write_i8(post.pressure_counter);
    writer.write_le_i32(post.army_movement_budget);
    writer.write_u8(post.turn_finished_flag);
    writer.write_le_u32(0);
    writer.write_le_i32(post.special_resource_trade_balance);
    writer.write_le_i32(post.aid_allocation_total);
    writer.write_bytes(&post.colony_boycott_flags);
    writer.write_le_i32(post.military_expenses);
}

fn write_auto_great_power_prefix(
    writer: &mut LegacyWriter,
    prefix: &LegacyAutoGreatPowerPrefix,
    mission_count: u32,
) {
    write_be_short_array(writer, &prefix.action_metric_by_quarter);
    writer.write_bytes(&prefix.map_node_state_flags);
    writer.write_bytes(&prefix.port_zone_state_flags);
    writer.write_le_u32(mission_count);
}

fn write_minor(writer: &mut LegacyWriter, nation: &LegacyMinorState) {
    write_country_base(writer, &nation.country);
    write_be_short_array(writer, &nation.need_current_by_type);
    write_be_short_array(writer, &nation.trade_offers_by_resource);
    write_be_short_array(writer, &nation.grant_amounts_by_resource);
    write_le_short_array(writer, &nation.diplomacy_thresholds);
    write_le_short_array(writer, &nation.diplomacy_policy_fields);
    write_be_short_array(writer, &nation.diplomacy_save_fields);
    write_be_short_array(writer, &nation.diplomacy_save_extension);
}

fn write_help(writer: &mut LegacyWriter, help: &LegacyHelpState) {
    write_fixed_record_list(writer, &help.index_records);
    write_be_short_array(writer, &help.civilian_completion_counters);
    writer.write_le_i16(help.help_index_ready);
}

fn write_fixed_record_list(writer: &mut LegacyWriter, list: &LegacyFixedRecordList) {
    writer.write_le_u16(list.record_size);
    writer.write_le_u32(list.records.len() as u32);
    for record in &list.records {
        assert_eq!(record.len(), usize::from(list.record_size));
        writer.write_bytes(record);
    }
}

fn write_mfc_mission(
    writer: &mut LegacyWriter,
    mission: &LegacyMission,
    archive: &mut Vec<Option<String>>,
) {
    const NEW_CLASS_TAG: u16 = 0xffff;
    const CLASS_TAG: u16 = 0x8000;
    let class = mission_class_name(mission);
    if let Some(index) = archive
        .iter()
        .enumerate()
        .find_map(|(index, name)| (name.as_deref() == Some(class)).then_some(index))
    {
        writer.write_le_u16(CLASS_TAG | index as u16);
    } else {
        writer.write_le_u16(NEW_CLASS_TAG);
        writer.write_le_i16(0);
        writer.write_le_u16(class.len() as u16);
        writer.write_bytes(class.as_bytes());
        archive.push(Some(class.to_owned()));
    }
    archive.push(None);
    write_mission_payload(writer, mission);
}

fn mission_class_name(mission: &LegacyMission) -> &'static str {
    match mission {
        LegacyMission::DefendProvince { .. } => "TDefendProvinceMission",
        LegacyMission::AttackProvince { .. } => "TAttackProvinceMission",
        LegacyMission::Invade { .. } => "TInvadeMission",
        LegacyMission::ControlSeaZone { .. } => "TControlSeaZoneMission",
        LegacyMission::Escort { .. } => "TEscortMission",
        LegacyMission::ScatteredShips { .. } => "TScatteredShipsMission",
        LegacyMission::Beachhead { .. } => "TBeachheadMission",
        LegacyMission::BlockadePort { .. } => "TBlockadePortMission",
    }
}

fn write_mission_payload(writer: &mut LegacyWriter, mission: &LegacyMission) {
    let common = mission_common(mission);
    writer.write_le_i16(common.source_nation);
    writer.write_u8(common.state);
    writer.write_le_u32(common.importance_bits);
    writer.write_u8(common.flag);
    writer.write_le_i16(common.path_marker);
    writer.write_u8(common.marker);
    match mission {
        LegacyMission::DefendProvince { army, .. } => write_army_mission(writer, army),
        LegacyMission::AttackProvince {
            army,
            target_province,
            amassing_province,
            ..
        } => {
            write_army_mission(writer, army);
            writer.write_le_i16(*target_province);
            writer.write_le_i16(*amassing_province);
        }
        LegacyMission::Invade {
            army,
            target_province,
            amassing_province,
            beachhead,
            ..
        } => {
            write_army_mission(writer, army);
            writer.write_le_i16(*target_province);
            writer.write_le_i16(*amassing_province);
            write_navy_mission(writer, beachhead);
        }
        LegacyMission::ControlSeaZone { navy, .. }
        | LegacyMission::Escort { navy, .. }
        | LegacyMission::ScatteredShips { navy, .. }
        | LegacyMission::Beachhead { navy, .. } => write_navy_mission(writer, navy),
        LegacyMission::BlockadePort {
            navy,
            blockade_port_zone,
            ..
        } => {
            write_navy_mission(writer, navy);
            writer.write_le_i16(*blockade_port_zone);
        }
    }
}

fn mission_common(mission: &LegacyMission) -> &LegacyMissionCommon {
    match mission {
        LegacyMission::DefendProvince { common, .. }
        | LegacyMission::AttackProvince { common, .. }
        | LegacyMission::Invade { common, .. }
        | LegacyMission::ControlSeaZone { common, .. }
        | LegacyMission::Escort { common, .. }
        | LegacyMission::ScatteredShips { common, .. }
        | LegacyMission::Beachhead { common, .. }
        | LegacyMission::BlockadePort { common, .. } => common,
    }
}

fn write_army_mission(writer: &mut LegacyWriter, army: &LegacyArmyMission) {
    writer.write_le_i16(army.present_location);
    for value in army.required_equipage_bits {
        writer.write_be_u32(value);
    }
    writer.write_le_i16(army.unit_ordinals.len() as i16);
    for ordinal in &army.unit_ordinals {
        writer.write_le_i16(*ordinal);
    }
}

fn write_navy_mission(writer: &mut LegacyWriter, navy: &LegacyNavyMission) {
    writer.write_le_i16(navy.target_zone);
    writer.write_le_i16(navy.resolved_port_zone);
    for value in navy.required_equipage_bits {
        writer.write_be_u32(value);
    }
    for ordinal in &navy.ship_ordinals {
        writer.write_le_i16(*ordinal);
    }
    writer.write_le_i16(-1);
    writer.write_le_i32(navy.state);
}

fn write_le_short_array<const N: usize>(writer: &mut LegacyWriter, values: &[i16; N]) {
    for value in values {
        writer.write_le_i16(*value);
    }
}

fn write_be_short_array<const N: usize>(writer: &mut LegacyWriter, values: &[i16; N]) {
    for value in values {
        writer.write_be_i16(*value);
    }
}
