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
    let lists = &mut first_great_power_mut(&mut save).prefix.relationship_lists;
    lists[0].records = vec![relationship_record(-7, 2), relationship_record(9, 0)];
    lists[1].records = vec![relationship_record(0x134, 5), relationship_record(0x12d, 1)];
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
        for province in (0..ProvinceId::COUNT).map(ProvinceId::new) {
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
    for province in (0..ProvinceId::COUNT).map(ProvinceId::new) {
        assert_eq!(state.map.provinces[province].development_stage(), 0);
        assert!(
            (0..MajorNationId::COUNT)
                .map(MajorNationId::new)
                .all(|nation| !state.map.provinces[province].explored_by_majors()[nation])
        );
    }
    assert_eq!(state.ocean.zones.len(), 83);
    for saved in &save.ocean.zones {
        let ZoneKind::Zone(zone) = &state.ocean.zones[saved.context_ordinal as usize] else {
            panic!("saved base zone projected as a port zone")
        };
        assert_projected_zone(zone, saved);
    }
    for saved in &save.ocean.port_zones {
        let ZoneKind::PortZone(port) = &state.ocean.zones[saved.zone.context_ordinal as usize]
        else {
            panic!("saved port zone projected as a base zone")
        };
        assert_projected_zone(&port.zone, &saved.zone);
        assert_eq!(port.port_tile.get(), saved.port_tile_index as u16);
        let tile = usize::from(port.port_tile.get());
        assert_eq!(
            state.map[port.port_tile]
                .former_owner_nation
                .and_then(TileOwnerTag::nation)
                .unwrap()
                .get(),
            save.map.tiles[tile].former_owner_nation as u8,
        );
    }
    assert_eq!(state.ocean.routes.len(), save.ocean.route_segments.len());
    for (route, &[start_row, start_column, end_row, end_column]) in
        state.ocean.routes.iter().zip(&save.ocean.route_segments)
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
fn projects_every_saved_ocean_field_without_country_projection() {
    let save = LegacySaveV62::parse(RETAIL_FIXTURE);
    let map = save.map_mgr();
    let ocean = ocean_state(&save.ocean, &map);

    assert_eq!(
        ocean.zones.len(),
        save.ocean.zones.len() + save.ocean.port_zones.len()
    );
    for saved in &save.ocean.zones {
        let ZoneKind::Zone(zone) = &ocean.zones[saved.context_ordinal as usize] else {
            panic!("saved base zone projected as a port zone")
        };
        assert_projected_zone(zone, saved);
    }
    for saved in &save.ocean.port_zones {
        let ordinal = saved.zone.context_ordinal as usize;
        let ZoneKind::PortZone(port) = &ocean.zones[ordinal] else {
            panic!("saved port zone projected as a base zone")
        };
        assert_projected_zone(&port.zone, &saved.zone);
        assert_eq!(port.port_tile.get(), saved.port_tile_index as u16);
        assert_eq!(port.zone.primary_neighbors.len(), 1);
        let linked = usize::from(port.zone.primary_neighbors[0].get());
        assert!(matches!(ocean.zones[linked], ZoneKind::Zone(_)));
        let ZoneKind::Zone(linked_zone) = &ocean.zones[linked] else {
            unreachable!()
        };
        assert!(
            linked_zone
                .primary_neighbors
                .contains(&OceanZoneId::new(ordinal as u16))
        );
    }
    assert_eq!(ocean.routes.len(), save.ocean.route_segments.len());
    for (route, &[start_row, start_column, end_row, end_column]) in
        ocean.routes.iter().zip(&save.ocean.route_segments)
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

#[test]
fn ocean_projection_uses_port_tile_for_former_owner() {
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE);
    let newest = save.ocean.port_zones.len() - 1;
    let next_newest = newest - 1;
    let newest_zone = save.ocean.port_zones[newest].zone.context_ordinal;
    let next_newest_zone = save.ocean.port_zones[next_newest].zone.context_ordinal;
    let newest_tile = save.ocean.port_zones[newest].port_tile_index as usize;
    let next_newest_tile = save.ocean.port_zones[next_newest].port_tile_index as usize;
    save.ocean.port_zones[newest].zone.seed_nation_id = 6;
    save.ocean.port_zones[next_newest].zone.seed_nation_id = 5;
    save.map.tiles[newest_tile].former_owner_nation = 0;
    save.map.tiles[next_newest_tile].former_owner_nation = 0;

    let map = save.map_mgr();
    let ocean = ocean_state(&save.ocean, &map);
    for (ordinal, tile) in [
        (newest_zone, newest_tile),
        (next_newest_zone, next_newest_tile),
    ] {
        let ZoneKind::PortZone(port) = &ocean.zones[ordinal as usize] else {
            panic!("saved port zone projected as a base zone")
        };
        assert_eq!(usize::from(port.port_tile.get()), tile);
        assert_eq!(
            map[port.port_tile]
                .former_owner_nation
                .and_then(TileOwnerTag::nation),
            Some(NationId::new(0))
        );
    }
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
    assert!(state.nations().majors().take(6).all(|nation| {
        nation.economy.ai_development_pressure == Some(AiDevelopmentPressureState::default())
    }));
    assert_eq!(
        state
            .nations()
            .major(MajorNationId::new(6))
            .economy
            .ai_development_pressure,
        None
    );
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

    let province_zero = &state.map.provinces[ProvinceId::new(0)];
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

    let province_seventy_nine = &state.map.provinces[ProvinceId::new(79)];
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
            state.map.provinces[ProvinceId::new(province as u16)],
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
fn retail_river_sprites_project_to_canonical_connection_codes() {
    for (sprite, connection_code) in [
        (0x0b, 1),
        (0x0d, 3),
        (0x0e, 3),
        (0x1a, 9),
        (0x1b, 1),
        (0x2a, 9),
        (0x2b, 0x0a),
        (0x2c, 0x0b),
        (0x2d, 0x0b),
        (0x32, 0x0f),
        (0x33, 0x13),
        (0x37, 0x10),
        (0x38, 0x11),
        (0x39, 0x11),
        (0x3a, 0x12),
    ] {
        assert_eq!(
            RiverSprite::from_retail(sprite).unwrap().connection_code(),
            connection_code
        );
    }
    assert_eq!(RiverSprite::from_retail(0), None);
    assert_eq!(RiverSprite::from_retail(1), None);
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
fn parses_the_retail_beginning_of_game_prefix() {
    let save = LegacySaveV62::parse(RETAIL_FIXTURE);
    assert_eq!(save.header.format_version, 62);
    assert_eq!(save.header.save_label, "- Autosave -");
    assert_eq!(save.header.preview_owner_nation_by_tile.len(), 6480);
    assert_eq!(save.header.preview_difficulty, 1);
    assert_eq!(save.header.preview_active_nation, 6);
    assert_eq!(save.simulation.economic_turn, 1);
    assert_eq!(save.simulation.active_nation, 6);
    assert_eq!(save.simulation.turn_state_code, 5);
    assert_eq!(save.simulation.nation_count, 7);
    assert_eq!(save.simulation.minor_nation_count, 16);
    assert_eq!(save.simulation.diplomacy_year_term_raw, 1914);
    assert_eq!(save.simulation.nation_names[0], "Zimm");
    assert_eq!(save.simulation.nation_names[6], " Testland");
    assert_eq!(save.simulation.nation_names[22], "Sindel");
    assert_eq!(save.animator_idle_frequency, 2);
    let cotton = &save.market.rows[TradeCommodity::Cotton as usize];
    assert_eq!(cotton.previous_price, 100);
    assert_eq!(cotton.price, 100);
    assert_eq!(cotton.base_price, 100);
    assert_eq!(cotton.request_count, 0);
    assert_eq!(cotton.offer_count, 0);
    assert_eq!(cotton.amount_offered, 0);
    assert_eq!(cotton.adjusted_offer_count, 0.0);
    assert_eq!(cotton.maximum_offer_by_nation, [0; NATION_COUNT]);
    assert_eq!(
        save.market.rows[TradeCommodity::Arms as usize].base_price,
        900
    );
    assert_eq!(
        save.technology.priority_slots,
        [
            0, 0, 0, 9, 32, 31, 27, 39, 47, 50, 64, 90, 93, 117, 111, 132, 140, 153, 166, 172, 200,
            204, 225, 230, 229, 246, 248, 268, 274,
        ]
    );
    assert_eq!(save.diplomacy.relation_standing_scores[0], 0x100);
    assert_eq!(
        save.diplomacy.relation_propagation_matrix[1],
        DiplomaticRelationship::Peace.retail()
    );
    assert_eq!(save.diplomacy.relation_turn_stamp_matrix[1], -1);
    assert_eq!(
        save.diplomacy.relation_side_effect_matrix[1],
        DiplomaticMissionLevel::Embassy.retail()
    );
    assert_eq!(save.diplomacy.congress_leadership[0], -1);
    assert_eq!(save.minor_nations[0].diplomacy_save_fields, [7, 8, 9, 10]);
    assert_eq!(save.map.tiles.len(), 6480);
    assert_eq!(save.map.provinces.len(), 384);
    assert_eq!(save.map.no_horizontal_wrap, 0);
    assert_eq!(save.map.tiles[0].terrain_kind, 5);
    assert_eq!(save.map.tiles[0].owner_nation, 82);
    assert_eq!(save.map.recruit_search_active, 1);
    assert_eq!(save.map.tiles[1_685].recruit_search_visited, 1);
    assert_eq!(save.map.tiles[0].per_tile_visited, 0);
    assert_eq!(save.map.tiles[0].marker_slot_index, 0);
    assert_eq!(save.map.tiles[0].tile_action_ordinal, -1);
    let world = save.map_mgr();
    assert_eq!(world.topology, MapTopology::Wrapping);
    assert!(world.recruit_search_active);
    assert_eq!(world[TileId::new(0)].terrain, TerrainKind::Water);
    assert_eq!(
        world[TileId::new(0)].owner_nation,
        Some(TileOwnerTag::new(82))
    );
    assert_eq!(world[TileId::new(1_685)].recruit_search_visited, 1);
    assert_eq!(world[TileId::new(0)].per_tile_visited, 0);
    assert_eq!(world[TileId::new(0)].marker_slot_index, 0);
    assert_eq!(world[TileId::new(0)].tile_action_ordinal, -1);
    assert!(!save.ocean.zones.is_empty());
    assert!(save.navy.ships.is_empty());
    assert!(save.navy.admirals.is_empty());
    assert!(save.navy.task_forces.is_empty());
    assert_eq!(save.army_report_count, 0);

    assert_eq!(save.major_nations.len(), 7);
    assert_eq!(save.minor_nations.len(), 16);

    let first = save.major_nations[0].great_power();
    let country = &first.country;
    assert_eq!(country.identity, "Zimm");
    assert_eq!(country.alternate_identity, "Zimm");
    assert_eq!(country.nation_slot, 0);
    assert_eq!(country.encoded_country_status, -1);
    assert_eq!(country.treasury, 10_000);
    assert_eq!(country.home_tile, 3_494);
    assert_eq!(country.overlay_anchor_tile, -1);
    assert_eq!(country.need_level_by_nation, [100; NATION_COUNT]);
    assert_eq!(country.military_units.len(), 27);
    assert_eq!(country.military_units[0].name, "1st Minutemen");
    assert_eq!(country.military_units[0].persistent_id, 0x113);
    assert_eq!(country.military_units[0].stationed_province, 79);
    assert_eq!(country.military_units[0].strength, 500);
    let unit_states = country.military_unit_states(NationId::new(0));
    assert_eq!(unit_states.len(), 27);
    assert_eq!(unit_states[0].id().get(), 275);
    assert_eq!(unit_states[0].unit_type(), MilitaryUnitKind::Minutemen);
    assert_eq!(
        *unit_states[0].order().targets(),
        [Some(ProvinceId::new(79)); 3]
    );
    assert_eq!(unit_states[26].id().get(), 301);

    assert_eq!(first.prefix.capacities, [0, 0, 15, 11]);
    assert_eq!(first.prefix.relationship_lists.len(), 19);
    assert_eq!(first.prefix.relationship_lists[0].record_size, 4);
    assert_eq!(first.prefix.relationship_lists[2].record_size, 12);
    assert_eq!(first.prefix.minister_presence_mask, 0x0f);
    assert!(first.ministers.foreign.is_some());
    assert_eq!(
        first.ministers.interior.as_ref().unwrap().integer_lists[0].len(),
        8
    );
    assert_eq!(
        first.ministers.interior.as_ref().unwrap().integer_lists[1].len(),
        20
    );
    assert!(first.ministers.defense.is_some());

    let city = first.city.as_ref().unwrap();
    assert!(city.tasks.is_empty());
    assert_eq!(city.transport_requests.record_size, 4);
    assert!(city.transport_requests.records.is_empty());
    assert_eq!(city.population.count, 7);
    assert_eq!(city.population.strength, 12);
    assert_eq!(city.population.baseline_labor, [4, 2, 1]);
    assert_eq!(city.stockpile[7..16], [20, 10, 24, 8, 19, 0, 5, 5, 0]);
    assert_eq!(
        city.production_orders[7..16],
        [999, 999, 999, 999, 0, 0, 999, 999, 0]
    );

    let city_state = city.city_state();
    assert_eq!(*city_state.orders, CityOrders::default());
    assert_eq!(
        city_state.population.accumulator().get().to_bits(),
        1_088_421_888
    );

    let post_city = &first.post_city;
    assert_eq!(post_city.towns.len(), 1);
    assert_eq!(post_city.towns[0].name, "FrogCity");
    assert_eq!(post_city.towns[0].tile_index, 3_494);
    assert_eq!(post_city.civilian_units.len(), 2);
    assert_eq!(post_city.diplomacy_budget_base, 50_000);
    assert_eq!(post_city.special_resource_trade_balance, 0);

    let LegacyMajorNationState::Auto(first_auto) = &save.major_nations[0] else {
        panic!("first fixture nation is computer-controlled")
    };
    assert_eq!(first_auto.auto_prefix.mission_count, 11);
    let missions = &first_auto.missions;
    assert_eq!(missions.len(), 11);
    let LegacyMission::DefendProvince { army, .. } = &missions[0] else {
        panic!("first fixture mission is not defend province")
    };
    assert_eq!(army.present_location, 79);
    let LegacyMission::DefendProvince { army, .. } = &missions[7] else {
        panic!("eighth fixture mission is not defend province")
    };
    assert_eq!(army.present_location, 111);
    let LegacyMission::ControlSeaZone { navy, .. } = &missions[8] else {
        panic!("ninth fixture mission is not control sea zone")
    };
    assert_eq!(navy.target_zone, 22);
    let LegacyMission::Escort { navy, .. } = &missions[9] else {
        panic!("tenth fixture mission is not escort")
    };
    assert_eq!(navy.target_zone, 66);
    let LegacyMission::ScatteredShips { common, .. } = &missions[10] else {
        panic!("eleventh fixture mission is not scattered ships")
    };
    assert_eq!(common.importance_bits, 981_668_463);

    let mission_states = missions
        .iter()
        .map(|mission| mission.mission_state(NationId::new(0), &country.military_units))
        .collect::<Vec<_>>();
    let MissionData::DefendProvince { province, army } = &mission_states[0].data else {
        panic!("first mission is not defend province");
    };
    assert_eq!(*province, ProvinceId::new(79));
    assert!(army.units.is_empty());
    let MissionData::ControlSeaZone(navy) = &mission_states[8].data else {
        panic!("ninth mission is not control sea zone");
    };
    assert_eq!(navy.target_zone, Some(OceanZoneId::new(22)));
    assert_eq!(mission_states[0].path_nation, None);
    assert_eq!(mission_states[10].importance_bits, 981_668_463);

    let auto_mission_count = save
        .major_nations
        .iter()
        .take(6)
        .enumerate()
        .map(|(nation, major)| {
            let LegacyMajorNationState::Auto(major) = major else {
                panic!("fixture nation {nation} is computer-controlled")
            };
            assert_eq!(major.great_power.country.nation_slot, nation as i16);
            assert_eq!(major.missions.len(), 11);
            major.missions.len()
        })
        .sum::<usize>();
    assert_eq!(auto_mission_count, 66);

    // The seventh major is player-controlled and therefore has no
    // TAutoGreatPower suffix or mission queue.
    let player_major = save.major_nations[6].great_power();
    assert_eq!(player_major.country.nation_slot, 6);
    assert_eq!(player_major.country.identity, " Testland");
    assert_eq!(player_major.country.alternate_identity, " Testland");
    for (nation, minor) in (7..NATION_COUNT).zip(&save.minor_nations) {
        assert_eq!(minor.country.nation_slot, nation as i16);
        assert_eq!(minor.diplomacy_save_extension.len(), RESOURCE_KIND_COUNT);
    }
    assert_eq!(save.help.index_records.record_size, 14);
    assert_eq!(save.help.index_records.records.len(), 30);

    let mut game = save.game_state(LegacyGameStateContext {
        crt_rand_state: 1,
        map_generation_lcg: 0,
        zone_status_lcg: 3_916_827_792,
        selected_nation: NationId::new(6),
    });
    assert_eq!(game.nations().display_name(NationId::new(0)), Some("Zimm"));
    assert_eq!(
        game.nations().display_name(NationId::new(6)),
        Some("Testland")
    );
    assert_eq!(
        game.nations().display_name(NationId::new(22)),
        Some("Sindel")
    );
    let expected_civilian_count = save
        .major_nations
        .iter()
        .map(|nation| nation.great_power().post_city.civilian_units.len())
        .sum::<usize>();
    assert_eq!(game.military_units().len(), 461);
    assert!(expected_civilian_count > 0);
    assert_eq!(game.civilian_units().len(), expected_civilian_count);
    assert_eq!(game.civilian_units()[0].nation(), NationId::new(0));
    assert_eq!(
        game.civilian_units()[0].id().get(),
        save.major_nations[0].great_power().post_city.civilian_units[0].persistent_id
    );
    assert_eq!(game.missions().len(), 66);
    assert_eq!(game.unit_ids().current(), 950);
    assert_eq!(
        game.nations()
            .minor(MinorNationId::new(7))
            .unwrap()
            .consortium_members
            .map(MinorNationId::get),
        [7, 8, 9, 10]
    );
    assert_eq!(game.civilian_units().len(), expected_civilian_count);
    assert!(game.all_humans_finished());
    assert!(!game.turn().in_linear_phase());
    game.reset_turn_flags();
    assert!(
        game.nations()
            .majors()
            .take(6)
            .all(|nation| nation.economy.turn_finished)
    );
    assert!(
        !game
            .nations()
            .major(MajorNationId::new(6))
            .economy
            .turn_finished
    );
    let mut turn = *game.turn();
    turn.advance_season();
    assert_eq!(turn.economic_turn, 2);
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
fn semantic_projection_preserves_multiple_towns_in_order() {
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE);
    let towns = &mut first_great_power_mut(&mut save).post_city.towns;
    let mut second = towns[0].clone();
    second.name = "Altown".to_owned();
    second.tile_index = 3_495;
    towns.push(second);

    let state = save.game_state(game_context());
    let towns = &state.nations().major(MajorNationId::new(0)).towns;
    assert_eq!(towns.len(), 2);
    assert_eq!(towns[0].name, "FrogCity");
    assert_eq!(towns[1].name, "Altown");
    assert_eq!(towns[1].tile, TileId::new(3_495));
}

#[test]
fn deal_book_projection_reconstructs_retail_sorted_load_order() {
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE);
    let list = &mut first_great_power_mut(&mut save).prefix.relationship_lists[2];
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
