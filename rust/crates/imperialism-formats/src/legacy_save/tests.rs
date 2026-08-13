use super::PROVINCE_COUNT;
use super::model::*;
use super::parse::*;
use super::project::*;
use super::*;
use crate::legacy_stream::LegacyStream;
use imperialism_core::*;

const RETAIL_FIXTURE: &[u8] =
    include_bytes!("../../../../../fixtures/retail/beginning_of_game.imp");
const DIPLOMACY_YEAR_TERM_ABSOLUTE_OFFSET_V62: usize = 0x1a1f;
const MARKET_ABSOLUTE_OFFSET_V62: usize = 0x1ac1;
const MARKET_ROW_SERIALIZED_SIZE_V62: usize = 0x9e;
const MARKET_MAXIMUM_OFFER_OFFSET_V62: usize = 0x70;
const TECH_ABSOLUTE_OFFSET_V62: usize = 0x3af9;
const DIPLOMACY_SERIALIZED_SIZE_V62: usize = 5_460;
const TECH_SERIALIZED_SIZE_V62: usize = 1_914;
const TECH_GLOBAL_UNLOCK_FLAGS_OFFSET_V62: usize = 0x180;
const TECH_INDUSTRY_ENABLED_OFFSET_V62: usize = 0x19d;
const TECH_ADVANCED_IRON_WORKING_OFFSET_V62: usize = 0x1a5;
const TECH_MARINE_ENGINEERING_OFFSET_V62: usize = 0x1a8;
const TECH_ORDER_CAP_ROWS_OFFSET_V62: usize = 0x262;
const TECH_ORDER_CAP_ROW_SIZE: usize = 0x1d;
const TECH_ABILITY_ACTIVE_ROWS_OFFSET_V62: usize = 0x38f;
const TECH_ABILITY_ACTIVE_ROW_SIZE: usize = 30;
const TECH_ADVANCED_IRON_WORKING_ID: usize = 0x0f;
const TECH_OIL_DRILLING_ID: usize = 0x13;
const TECH_UNIVERSITY_AVAILABILITY_OFFSET_V62: usize = 0x461;
const TECH_UNIVERSITY_AVAILABILITY_ROW_SIZE: usize = 9;
const TECH_FINAL_REQUIREMENT_LEVELS_OFFSET_V62: usize = 0x636;
const TECH_REQUIREMENT_LEVELS_ROW_SIZE: usize = RESOURCE_KIND_COUNT * std::mem::size_of::<i16>();

fn game_context() -> LegacyGameStateContext {
    LegacyGameStateContext {
        crt_rand_state: 1,
        map_generation_lcg: 0,
        zone_status_lcg: 3_916_827_792,
        selected_nation: NationId::new(6),
    }
}

fn push_be_i16(bytes: &mut Vec<u8>, value: i16) {
    bytes.extend_from_slice(&value.to_be_bytes());
}

fn nonzero_steel_order_payload() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(66);
    // Retail overwrites this first constructor product with the second
    // product word, so keep them deliberately different.
    for value in [99_i16, 3, 2, 11] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    for resource in 0..RESOURCE_KIND_COUNT {
        let tracked =
            if resource == ResourceKind::Coal as usize || resource == ResourceKind::Iron as usize {
                3_i16
            } else {
                0_i16
            };
        bytes.extend_from_slice(&tracked.to_le_bytes());
    }
    bytes.extend_from_slice(&27_i32.to_le_bytes());
    for value in [5_i16, 4, 3, 2] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[test]
fn decodes_nonzero_item_order_field_sequence() {
    let bytes = nonzero_steel_order_payload();
    let mut stream = LegacyStream::new(&bytes);

    let state = read_item_order(&mut stream);

    assert_eq!(stream.position(), 66);
    assert_eq!(state.order.resource_type_index, 11);
    assert_eq!(state.order.quantity, 3);
    assert_eq!(state.order.limiting_constraint, 2);
    assert_eq!(state.order.tracking_slots[ResourceKind::Coal as usize], 3);
    assert_eq!(state.order.tracking_slots[ResourceKind::Iron as usize], 3);
    assert_eq!(state.order.accumulated_value, 27);
    assert_eq!(state.requested_quantity, 5);
}

fn valid_diplomacy_payload() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(DIPLOMACY_SERIALIZED_SIZE_V62);
    for index in 0..NATION_COUNT * NATION_COUNT {
        push_be_i16(&mut bytes, if index == 0 { 0x1234 } else { 90 });
    }
    for _ in 0..NATION_COUNT * NATION_COUNT {
        push_be_i16(&mut bytes, DiplomaticRelationship::Peace.retail());
    }
    for index in 0..NATION_COUNT * NATION_COUNT {
        push_be_i16(&mut bytes, if index == 0 { 7 } else { -1 });
    }
    for index in 0..PROVINCE_COUNT {
        push_be_i16(&mut bytes, if index == 0 { 0x2345 } else { 0 });
    }
    bytes.extend(std::iter::once(6).chain(std::iter::repeat_n(0xff, PROVINCE_COUNT - 1)));
    bytes.extend_from_slice(&0x3456_i16.to_le_bytes());
    for index in 0..NATION_COUNT * NATION_COUNT {
        push_be_i16(
            &mut bytes,
            if index == 1 {
                DiplomaticMissionLevel::Embassy.retail()
            } else {
                DiplomaticMissionLevel::None.retail()
            },
        );
    }
    push_be_i16(&mut bytes, 6);
    push_be_i16(&mut bytes, -1);
    push_be_i16(&mut bytes, 1);
    push_be_i16(&mut bytes, 2);
    push_be_i16(&mut bytes, 3);
    for index in 0..MINOR_NATION_COUNT {
        push_be_i16(&mut bytes, if index == 0 { 5 } else { -1 });
    }
    for _ in 0..MINOR_NATION_COUNT {
        push_be_i16(&mut bytes, -1);
    }
    assert_eq!(bytes.len(), DIPLOMACY_SERIALIZED_SIZE_V62);
    bytes
}

#[test]
fn reads_phase_six_inputs_from_their_exact_v62_offsets() {
    let mut bytes = RETAIL_FIXTURE.to_vec();
    bytes[DIPLOMACY_YEAR_TERM_ABSOLUTE_OFFSET_V62..DIPLOMACY_YEAR_TERM_ABSOLUTE_OFFSET_V62 + 2]
        .copy_from_slice(&(-1234_i16).to_le_bytes());
    let category = 6;
    let nation_slot = 22;
    let maximum_offset = MARKET_ABSOLUTE_OFFSET_V62
        + category * MARKET_ROW_SERIALIZED_SIZE_V62
        + MARKET_MAXIMUM_OFFER_OFFSET_V62
        + nation_slot * std::mem::size_of::<i16>();
    assert_eq!(maximum_offset, 0x1f11);
    bytes[maximum_offset..maximum_offset + 2].copy_from_slice(&321_i16.to_be_bytes());
    bytes[TECH_ABSOLUTE_OFFSET_V62 + TECH_ADVANCED_IRON_WORKING_OFFSET_V62] = 1;
    bytes[TECH_ABSOLUTE_OFFSET_V62 + TECH_MARINE_ENGINEERING_OFFSET_V62] = 1;
    assert_eq!(
        TECH_ABSOLUTE_OFFSET_V62 + TECH_ADVANCED_IRON_WORKING_OFFSET_V62,
        0x3c9e
    );
    assert_eq!(
        TECH_ABSOLUTE_OFFSET_V62 + TECH_MARINE_ENGINEERING_OFFSET_V62,
        0x3ca1
    );

    let save = LegacySaveV62::parse(&bytes);
    let state = save.game_state(game_context());
    assert_eq!(state.turn().diplomacy_year_term_raw, -1234);
    assert!(state.technology().advanced_iron_working);
    assert!(state.technology().marine_engineering);
    assert_eq!(
        state.market().rows[TradeCommodity::Oil].maximum_offer_by_nation[NationId::new(22)],
        321
    );
}

#[test]
fn technology_decoder_reads_retail_resource_type_fields() {
    let mut bytes = [0_u8; TECH_SERIALIZED_SIZE_V62];
    bytes[TECH_ADVANCED_IRON_WORKING_OFFSET_V62] = 1;
    bytes[TECH_MARINE_ENGINEERING_OFFSET_V62] = 1;
    bytes[4 * std::mem::size_of::<i16>()..5 * std::mem::size_of::<i16>()]
        .copy_from_slice(&17_i16.to_be_bytes());
    bytes[TECH_GLOBAL_UNLOCK_FLAGS_OFFSET_V62 + TECH_OIL_DRILLING_ID] = 1;
    bytes[TECH_INDUSTRY_ENABLED_OFFSET_V62 + CityFacilitySlot::OilRefinery as usize] = 1;
    bytes[TECH_ABILITY_ACTIVE_ROWS_OFFSET_V62
        + 2 * TECH_ABILITY_ACTIVE_ROW_SIZE
        + MilitaryUnitKind::SiegeArtillery as usize] = 1;
    bytes[TECH_ORDER_CAP_ROWS_OFFSET_V62
        + 2 * TECH_ORDER_CAP_ROW_SIZE
        + TECH_ADVANCED_IRON_WORKING_ID] = 2;
    bytes[TECH_ORDER_CAP_ROWS_OFFSET_V62 + 3 * TECH_ORDER_CAP_ROW_SIZE + TECH_OIL_DRILLING_ID] = 2;
    bytes[TECH_ORDER_CAP_ROWS_OFFSET_V62 + 4 * TECH_ORDER_CAP_ROW_SIZE + 4] = 1;
    bytes[TECH_UNIVERSITY_AVAILABILITY_OFFSET_V62
        + TECH_UNIVERSITY_AVAILABILITY_ROW_SIZE
        + CivilianUnitKind::Driller as usize] = 1;
    let requirement_offset = TECH_FINAL_REQUIREMENT_LEVELS_OFFSET_V62
        + TECH_REQUIREMENT_LEVELS_ROW_SIZE
        + ResourceKind::Oil as usize * std::mem::size_of::<i16>();
    bytes[requirement_offset..requirement_offset + 2].copy_from_slice(&3_i16.to_be_bytes());
    let mut stream = LegacyStream::new(&bytes);
    let technology = read_technology_state(&mut stream);
    assert_eq!(technology.priority_slots[4], 17);
    assert_eq!(
        technology.per_technology_unlock_flags[TECH_OIL_DRILLING_ID],
        1
    );
    assert_eq!(
        technology.resource_type_enabled[CityFacilitySlot::OilRefinery as usize],
        1
    );
    assert_eq!(
        technology.ability_active_by_nation[2][MilitaryUnitKind::SiegeArtillery as usize],
        1
    );
    assert_eq!(
        technology.research_status_by_nation[2][TECH_ADVANCED_IRON_WORKING_ID],
        2
    );
    assert_eq!(
        technology.research_status_by_nation[3][TECH_OIL_DRILLING_ID],
        2
    );
    assert_eq!(technology.research_status_by_nation[4][4], 1);
    assert_eq!(
        technology.university_recruitment_availability[1][CivilianUnitKind::Driller as usize],
        1
    );
    assert_eq!(
        technology.capability_value_by_nation_and_resource[1][ResourceKind::Oil as usize],
        3
    );
    assert_eq!(stream.position(), TECH_SERIALIZED_SIZE_V62);
}

#[test]
fn trade_current_offer_decoder_keeps_signed_nation_slots() {
    const MARKET_CURRENT_OFFER_OFFSET_V62: usize = 0x14;
    let mut bytes = [0_u8; MARKET_ROW_SERIALIZED_SIZE_V62];
    bytes[MARKET_CURRENT_OFFER_OFFSET_V62..MARKET_CURRENT_OFFER_OFFSET_V62 + 2]
        .copy_from_slice(&(-3_i16).to_be_bytes());
    bytes[MARKET_CURRENT_OFFER_OFFSET_V62 + 22 * 2..MARKET_CURRENT_OFFER_OFFSET_V62 + 22 * 2 + 2]
        .copy_from_slice(&4_i16.to_be_bytes());

    let mut stream = LegacyStream::new(&bytes);
    let row = read_trade_market_row(&mut stream);
    assert_eq!(stream.position(), MARKET_ROW_SERIALIZED_SIZE_V62);
    assert_eq!(row.current_offer_by_nation[0], -3);
    assert_eq!(row.current_offer_by_nation[22], 4);
}

#[test]
fn trade_maximum_decoder_keeps_all_nation_slots() {
    let mut bytes = [0_u8; MARKET_ROW_SERIALIZED_SIZE_V62];
    let nation_zero_offset = MARKET_MAXIMUM_OFFER_OFFSET_V62;
    let nation_twenty_two_offset = MARKET_MAXIMUM_OFFER_OFFSET_V62 + 22 * 2;
    assert_eq!(nation_zero_offset, 0x70);
    assert_eq!(nation_twenty_two_offset, 0x9c);
    bytes[nation_zero_offset..nation_zero_offset + 2].copy_from_slice(&17_i16.to_be_bytes());
    bytes[nation_twenty_two_offset..nation_twenty_two_offset + 2]
        .copy_from_slice(&222_i16.to_be_bytes());

    let mut stream = LegacyStream::new(&bytes);
    let row = read_trade_market_row(&mut stream);
    assert_eq!(stream.position(), MARKET_ROW_SERIALIZED_SIZE_V62);
    assert_eq!(row.maximum_offer_by_nation[0], 17);
    assert_eq!(row.maximum_offer_by_nation[22], 222);
}

#[test]
fn reads_the_exact_v62_diplomacy_payload_and_endianness() {
    let bytes = valid_diplomacy_payload();
    let mut stream = LegacyStream::new(&bytes);
    let diplomacy = read_diplomacy_state(&mut stream);

    assert_eq!(stream.position(), DIPLOMACY_SERIALIZED_SIZE_V62);
    assert_eq!(diplomacy.relation_standing_scores[0], 0x1234);
    assert_eq!(diplomacy.relation_turn_stamp_matrix[0], 7);
    assert_eq!(diplomacy.relation_code_matrix[0], 0x2345);
    assert_eq!(diplomacy.pending_policy_code_matrix[0], 6);
    assert_eq!(diplomacy.last_diplomatic_effort_turn, 0x3456);
    assert_eq!(
        diplomacy.relation_side_effect_matrix[1],
        DiplomaticMissionLevel::Embassy.retail()
    );
    assert_eq!(diplomacy.congress_leadership, [6, -1]);
    assert_eq!(diplomacy.congress_support, [1, 2, 3]);
    assert_eq!(diplomacy.special_relation_source_slots[0], 5);
}

fn first_great_power_mut(save: &mut LegacySaveV62) -> &mut LegacyGreatPowerState {
    match &mut save.major_nations[0] {
        LegacyMajorNationState::Auto(nation) => &mut nation.great_power,
        LegacyMajorNationState::Other(nation) => nation,
    }
}

fn relationship_record(value: i16, source: i16) -> Vec<u8> {
    [value.to_le_bytes(), source.to_le_bytes()].concat()
}

#[test]
fn projects_typed_relationship_queues_in_retail_source_order_without_rng_draws() {
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE);
    let prefix = &mut first_great_power_mut(&mut save).prefix;
    prefix.turn_event_queue.records = vec![relationship_record(-7, 2), relationship_record(9, 0)];
    prefix.proposal_queue.records =
        vec![relationship_record(0x134, 5), relationship_record(0x12d, 1)];
    let mut context = game_context();
    context.crt_rand_state = 0x1234_5678;

    let state = save.game_state(context);
    let pending = &state.pending().nations[MajorNationId::new(0)];
    assert_eq!(
        pending.turn_events,
        vec![
            DiplomacyNotice {
                source: NationId::new(0),
                code: 9,
            },
            DiplomacyNotice {
                source: NationId::new(2),
                code: -7,
            },
        ]
    );
    assert_eq!(
        pending.proposals,
        vec![
            DiplomacyProposal {
                source: NationId::new(1),
                policy: DiplomacyPolicy::JoinEmpire,
            },
            DiplomacyProposal {
                source: NationId::new(5),
                policy: DiplomacyPolicy::BuildEmbassy,
            },
        ]
    );
    assert_eq!(state.rng().crt_rand.state(), 0x1234_5678);
}

#[test]
fn projects_exact_fixture_phase_ten_inputs_and_ocean() {
    let save = LegacySaveV62::parse(RETAIL_FIXTURE);
    assert_eq!(save.ocean.zones.len(), 60);
    assert_eq!(save.ocean.port_zones.len(), 23);
    let state = save.game_state(game_context());
    let expected_mission_queued = [[22, 66], [42, 65], [26, 64], [21, 63], [8, 62], [11, 61]];
    let expected_provinces = [
        [79, 80, 89, 90, 91, 100, 101, 111],
        [32, 43, 44, 45, 55, 56, 57, 58],
        [42, 53, 54, 66, 67, 68, 74, 75],
        [1, 2, 9, 10, 18, 19, 28, 29],
        [26, 27, 38, 39, 40, 41, 51, 52],
        [85, 86, 87, 97, 98, 107, 108, 109],
    ];
    for (slot, (expected_zones, expected_provinces)) in expected_mission_queued
        .into_iter()
        .zip(expected_provinces)
        .enumerate()
    {
        let major = state.nations().major(MajorNationId::new(slot as u8));
        let targets = major.economy.ai_zone_targets.as_ref().unwrap();
        assert_eq!(targets.len(), 83);
        let mut expected_targets = vec![AiTargetState::Unmarked; 83];
        for ordinal in expected_zones {
            expected_targets[ordinal] = AiTargetState::MissionQueued;
        }
        assert_eq!(targets, &expected_targets);

        let province_targets = major.economy.ai_province_targets.as_ref().unwrap();
        for province in ProvinceId::all() {
            let expected = if expected_provinces.contains(&province.get()) {
                AiTargetState::MissionQueued
            } else {
                AiTargetState::Unmarked
            };
            assert_eq!(province_targets[province], expected);
        }
        assert_eq!(major.economy.army_movement_budget, 15);
    }
    let human = &state.nations().major(MajorNationId::new(6)).economy;
    assert!(human.ai_zone_targets.is_none());
    assert!(human.ai_province_targets.is_none());
    assert_eq!(human.army_movement_budget, 15);
    for province in ProvinceId::all() {
        assert_eq!(state.map().provinces[province].development_stage(), 0);
        assert!(
            MajorNationId::all()
                .all(|nation| !state.map().provinces[province].explored_by_majors()[nation])
        );
    }
    assert_eq!(state.ocean().zones.len(), 83);
    for saved in &save.ocean.zones {
        let ZoneKind::Zone(zone) = &state.ocean().zones[saved.context_ordinal as usize] else {
            panic!("saved base zone projected as a port zone")
        };
        assert_projected_zone(zone, saved);
    }
    for saved in &save.ocean.port_zones {
        let ZoneKind::PortZone(port) = &state.ocean().zones[saved.zone.context_ordinal as usize]
        else {
            panic!("saved port zone projected as a base zone")
        };
        assert_projected_zone(&port.zone, &saved.zone);
        assert_eq!(port.port_tile.get(), saved.port_tile_index as u16);
        assert_eq!(port.zone.primary_neighbors.len(), 1);
        let linked = usize::from(port.zone.primary_neighbors[0].get());
        let ZoneKind::Zone(linked_zone) = &state.ocean().zones[linked] else {
            panic!("port zone linked to another port zone")
        };
        assert!(
            linked_zone
                .primary_neighbors
                .contains(&OceanZoneId::new(saved.zone.context_ordinal as u16))
        );
        let tile = usize::from(port.port_tile.get());
        assert_eq!(
            state.map()[port.port_tile]
                .former_owner_nation
                .and_then(TileOwnerTag::nation)
                .unwrap()
                .get(),
            save.map.tiles[tile].former_owner_nation as u8,
        );
    }
    assert_eq!(state.ocean().routes.len(), save.ocean.route_segments.len());
    for (route, &[start_row, start_column, end_row, end_column]) in
        state.ocean().routes.iter().zip(&save.ocean.route_segments)
    {
        assert_eq!(
            *route,
            OceanRoute {
                start_column,
                start_row,
                end_column,
                end_row,
            }
        );
    }
}

fn assert_projected_zone(zone: &Zone, saved: &LegacyZone) {
    assert_eq!(zone.display_name, saved.display_name);
    assert_eq!(
        zone.status_code,
        (saved.status_code != -1).then_some(saved.status_code)
    );
    assert_eq!(
        zone.target_tile.map(TileId::get),
        (saved.tile_or_terrain_id != -1).then_some(saved.tile_or_terrain_id as u16)
    );
    assert_eq!(
        zone.seed_owner.map(TileOwnerTag::get),
        (saved.seed_nation_id != -1).then_some(saved.seed_nation_id as u8)
    );
    assert_eq!(
        zone.active_tile.map(TileId::get),
        (saved.active_tile_index != -1).then_some(saved.active_tile_index as u16)
    );
}

#[test]
fn retail_projection_preserves_minister_identity_and_direct_state() {
    let save = LegacySaveV62::parse(RETAIL_FIXTURE);
    let state = save.game_state(game_context());
    assert_eq!(
        save.simulation.game_setup.foreign_minister_policy_ids,
        [1, 4, 2, 4, 3, 5, 3]
    );
    assert_eq!(
        state
            .nations()
            .majors()
            .map(|nation| nation.economy.foreign_minister_personality)
            .collect::<Vec<_>>(),
        [
            ForeignMinisterPersonality::Trader,
            ForeignMinisterPersonality::Bill,
            ForeignMinisterPersonality::Textile,
            ForeignMinisterPersonality::Bill,
            ForeignMinisterPersonality::Diplomat,
            ForeignMinisterPersonality::Ted,
            ForeignMinisterPersonality::Base,
        ]
    );
    assert_eq!(
        state
            .nations()
            .majors()
            .map(|nation| nation.economy.foreign_minister_skill_index)
            .collect::<Vec<_>>(),
        [0, 4, 0, 4, 0, 5, 0]
    );
    assert!(state.nations().majors().enumerate().all(|(index, nation)| {
        let mut expansion_demand = [0_i16; CityFacilitySlot::COUNT];
        if index < 6 {
            expansion_demand[..7].copy_from_slice(&[2, 1, 2, 0, 2, 0, 0]);
        }
        let expected_interior = InteriorCivilianState::from_parts(
            None,
            None,
            ResourceTable::default(),
            AiCityOrderDemand::from_parts(
                TrainingOrderTable::default(),
                MilitaryRecruitOrderTable::default(),
                CivilianUnitTable::default(),
                ShipOrderTable::default(),
                0,
                ProductionTable::from_array(expansion_demand),
                0,
            ),
            0,
            ProductionTable::default(),
            0,
            ResourceTable::default(),
            ResourceTable::default(),
            ResourceTable::default(),
            ResourceTable::default(),
            0,
            Vec::new(),
        );
        nation.economy.development_grant_by_nation == NationTable::<i16>::default()
            && nation.economy.defense_minister_skill_index == 0
            && *nation.economy.interior_civilian == expected_interior
    }));
    assert_eq!(
        state
            .nations()
            .majors()
            .map(|nation| nation.towns.first().map(|town| town.tile))
            .collect::<Vec<_>>(),
        [3_494, 2_992, 2_862, 1_563, 1_420, 4_555, 1_685].map(|tile| Some(TileId::new(tile)))
    );
    assert_eq!(
        state
            .nations()
            .major(MajorNationId::new(6))
            .economy
            .foreign_minister_personality,
        ForeignMinisterPersonality::Base,
        "the human constructs the base minister even though setup policy 3 names Diplomat"
    );
}

#[test]
fn projects_mission_holds_and_ordered_pending_development_actions() {
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE);
    first_great_power_mut(&mut save)
        .ministers
        .interior
        .as_mut()
        .unwrap()
        .integer_lists[2] = vec![34, 7];

    let state = save.game_state(game_context());
    let held_mission_indices = state
        .missions()
        .iter()
        .enumerate()
        .filter_map(|(index, mission)| mission.held.then_some(index))
        .collect::<Vec<_>>();
    assert_eq!(held_mission_indices, [62, 63, 64]);
    let interior_civilian = serde_json::to_value(
        &*state
            .nations()
            .major(MajorNationId::new(0))
            .economy
            .interior_civilian,
    )
    .unwrap();
    assert_eq!(
        interior_civilian["pending_development_actions"],
        serde_json::json!([
            {"kind": "industry", "slot": "lumber_mill"},
            {"kind": "land_unit", "unit_type": "artillery"}
        ])
    );
    assert_eq!(
        interior_civilian["average_development_order_allocation"],
        serde_json::json!(0)
    );
    assert_eq!(
        serde_json::to_value(&state.missions()[62]).unwrap()["held"],
        serde_json::json!(true)
    );
}

#[test]
fn retail_projection_preserves_country_and_province_semantics() {
    let save = LegacySaveV62::parse(RETAIL_FIXTURE);
    let state = save.game_state(game_context());

    let nation_zero = &state.nations().major(MajorNationId::new(0)).common;
    assert_eq!(nation_zero.status(), CountryStatus::Independent);
    assert_eq!(
        nation_zero.owned_regions(),
        [79, 80, 89, 90, 91, 100, 101, 111]
            .map(ProvinceId::new)
            .to_vec()
    );

    let province_zero = &state.map().provinces[ProvinceId::new(0)];
    assert_eq!(province_zero.owner(), Some(NationId::new(12)));
    assert_eq!(province_zero.former_owner(), Some(NationId::new(12)));
    assert_eq!(province_zero.adjacency(), [8, 1, 17].map(ProvinceId::new));
    assert_eq!(province_zero.region_class, Some(0));
    assert_eq!(province_zero.fort_level(), 0);
    assert_eq!(province_zero.city_tile(), Some(TileId::new(695)));
    assert_eq!(
        province_zero.resource_development_by_type(),
        &ResourceTable::default()
    );
    assert_eq!(province_zero.city_score(), 0);

    let province_seventy_nine = &state.map().provinces[ProvinceId::new(79)];
    assert_eq!(province_seventy_nine.owner(), Some(NationId::new(0)));
    assert_eq!(
        province_seventy_nine.adjacency(),
        [71, 72, 80, 78, 89, 90].map(ProvinceId::new)
    );
    assert_eq!(province_seventy_nine.region_class, Some(4));
    assert_eq!(province_seventy_nine.fort_level(), 0);
    assert_eq!(province_seventy_nine.city_tile(), Some(TileId::new(3_706)));
    assert_eq!(
        province_seventy_nine.resource_development_by_type(),
        &ResourceTable::default()
    );
    assert_eq!(province_seventy_nine.city_score(), 0);

    for province in 120..PROVINCE_COUNT {
        assert_eq!(
            state.map().provinces[ProvinceId::new(province as u16)],
            ProvinceState::default()
        );
    }

    assert!(state.do_nation_territories_share_region_class(NationId::new(0), NationId::new(19)));
    assert!(!state.do_nation_territories_share_region_class(NationId::new(0), NationId::new(1)));
    assert!(state.are_nations_border_linked(NationId::new(0), NationId::new(19)));
    assert!(!state.are_nations_border_linked(NationId::new(0), NationId::new(1)));
}

#[test]
fn country_status_projection_decodes_retail_encodings() {
    for (encoded, expected) in [
        (-1, CountryStatus::Independent),
        (100, CountryStatus::ProtectorateOf(NationId::new(0))),
        (122, CountryStatus::ProtectorateOf(NationId::new(22))),
        (200, CountryStatus::ColonyOf(NationId::new(0))),
        (222, CountryStatus::ColonyOf(NationId::new(22))),
    ] {
        assert_eq!(country_status_from_retail(encoded), expected);
    }
}

#[test]
fn preserves_and_projects_the_one_based_scenario_map_index() {
    const SCENARIO_MAP_OFFSET: usize = 60;
    let mut bytes = [0_u8; SCENARIO_MAP_OFFSET + std::mem::size_of::<i16>()];

    bytes[SCENARIO_MAP_OFFSET..].copy_from_slice(&1_i16.to_le_bytes());
    let setup = read_game_setup(&mut LegacyStream::new(&bytes));
    assert_eq!(setup.scenario_map_index_plus_one, 1);

    bytes[SCENARIO_MAP_OFFSET..].copy_from_slice(&(-1_i16).to_le_bytes());
    let setup = read_game_setup(&mut LegacyStream::new(&bytes));
    assert_eq!(setup.scenario_map_index_plus_one, -1);

    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE);
    save.simulation.game_setup.scenario_map_index_plus_one = 1;
    assert_eq!(
        save.game_state(game_context()).turn().scenario_map,
        Some(ScenarioMapId::new(0))
    );
    save.simulation.game_setup.scenario_map_index_plus_one = -1;
    assert_eq!(save.game_state(game_context()).turn().scenario_map, None);
}

#[test]
fn semantic_projection_preserves_inactive_pending_action_payload() {
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE);
    let prefix = &mut first_great_power_mut(&mut save).prefix;
    let action = PendingActionKind::NavyGrowthReward as usize;
    prefix.pending_action_status[action] = 0;
    prefix.pending_action_payload_by_action[action] = 0;

    let state = save.game_state(game_context());
    assert_eq!(
        state
            .nations()
            .majors()
            .next()
            .unwrap()
            .economy
            .pending_actions[PendingActionKind::NavyGrowthReward]
            .payload(),
        Some(0)
    );
}

#[test]
fn navy_growth_handled_reward_levels_round_trip_through_retail_save() {
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE);
    let prefix = &mut first_great_power_mut(&mut save).prefix;
    let action = PendingActionKind::NavyGrowthReward as usize;
    prefix.pending_action_status[action] = 0x34;
    prefix.pending_action_payload_by_action[action] = 1;

    let state = save.game_state(game_context());
    let pending = state
        .nations()
        .major(MajorNationId::new(0))
        .economy
        .pending_actions[PendingActionKind::NavyGrowthReward];
    assert_eq!(pending.status(), PendingActionStatus::from_retail(0x34));
    assert_eq!(pending.completed_level(), Some(1));
    assert_eq!(pending.payload(), Some(1));

    let bytes = LegacySaveV62::from_game_state(&state, "- Autosave -", 0).to_bytes();
    let round_tripped =
        load_game_from_bytes(&bytes, game_context()).expect("rust-written save loads");
    let pending = round_tripped
        .nations()
        .major(MajorNationId::new(0))
        .economy
        .pending_actions[PendingActionKind::NavyGrowthReward];
    assert_eq!(pending.status(), PendingActionStatus::from_retail(0x34));
    assert_eq!(pending.completed_level(), Some(1));

    let mut save = LegacySaveV62::parse(&bytes);
    first_great_power_mut(&mut save)
        .prefix
        .pending_action_status[action] = 0x39;
    first_great_power_mut(&mut save)
        .prefix
        .pending_action_payload_by_action[action] = 6;
    let level_six = save.game_state(game_context());
    let pending = level_six
        .nations()
        .major(MajorNationId::new(0))
        .economy
        .pending_actions[PendingActionKind::NavyGrowthReward];
    assert_eq!(pending.status(), PendingActionStatus::from_retail(0x39));
    assert_eq!(pending.completed_level(), Some(6));
}

#[test]
fn deal_book_projection_reconstructs_retail_sorted_load_order() {
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE);
    let list = &mut first_great_power_mut(&mut save)
        .prefix
        .diplomacy_tracked_slots[0];
    let record = |kind: i16, nation: i16, amount: i16, eligibility: i16, price: i32| {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&nation.to_le_bytes());
        bytes.extend_from_slice(&amount.to_le_bytes());
        bytes.extend_from_slice(&eligibility.to_le_bytes());
        bytes.extend_from_slice(&price.to_le_bytes());
        bytes
    };
    list.records = vec![record(1, 8, 11, 1, 123), record(0, 0, 22, 0, 456)];

    let state = save.game_state(game_context());
    assert_eq!(
        state
            .nations()
            .major(MajorNationId::new(0))
            .economy
            .deal_book[TradeCommodity::Cotton],
        vec![
            TradeDealBookEntry {
                kind: DealBookEntryKind::Accept,
                nation: NationId::new(0),
                amount: 22,
                unit_price: 456,
            },
            TradeDealBookEntry {
                kind: DealBookEntryKind::Offer,
                nation: NationId::new(8),
                amount: 11,
                unit_price: 123,
            },
        ]
    );
}

#[test]
fn fixture_dto_write_round_trips_projected_game_state() {
    let original = LegacySaveV62::parse(RETAIL_FIXTURE).game_state(game_context());
    let bytes = LegacySaveV62::parse(RETAIL_FIXTURE).to_bytes();
    let round_tripped = LegacySaveV62::parse(&bytes).game_state(game_context());
    assert_eq!(round_tripped, original);
}

#[test]
fn game_state_write_round_trips_semantically_through_the_parser() {
    let original = LegacySaveV62::parse(RETAIL_FIXTURE).game_state(game_context());
    let bytes = LegacySaveV62::from_game_state(&original, "- Autosave -", 0).to_bytes();
    let round_tripped =
        load_game_from_bytes(&bytes, game_context()).expect("rust-written save loads");
    assert_eq!(round_tripped, original);
}

#[test]
fn failed_load_leaves_an_existing_game_state_untouched() {
    let original = LegacySaveV62::parse(RETAIL_FIXTURE).game_state(game_context());
    let mut current = original.clone();
    let error = load_game_from_bytes(b"not a save file!!", game_context()).unwrap_err();
    assert!(matches!(error, LoadGameError::InvalidMagic));
    assert_eq!(current, original);
    current = original.clone();
    assert_eq!(current, original);
}
