use super::PROVINCE_COUNT;
use super::errors::*;
use super::model::*;
use super::normalize::*;
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

fn game_context() -> LegacyGameStateContext {
    LegacyGameStateContext {
        crt_rand_state: 1,
        map_generation_lcg: 0,
        zone_status_lcg: 3_916_827_792,
        selected_nation: NationId::new(6),
    }
}

const NATION_PAIR_BYTES: usize = NATION_COUNT * NATION_COUNT * 2;
const RELATIONSHIP_OFFSET: usize = NATION_PAIR_BYTES;
const TURN_STAMP_OFFSET: usize = RELATIONSHIP_OFFSET + NATION_PAIR_BYTES;
const INFLUENCE_THRESHOLD_OFFSET: usize = TURN_STAMP_OFFSET + NATION_PAIR_BYTES;
const INFLUENCE_SIDE_OFFSET: usize = INFLUENCE_THRESHOLD_OFFSET + PROVINCE_COUNT * 2;
const MISSION_LEVEL_OFFSET: usize = INFLUENCE_SIDE_OFFSET + PROVINCE_COUNT + 2;
const CONGRESS_OFFSET: usize = MISSION_LEVEL_OFFSET + NATION_PAIR_BYTES;

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

    let state = read_item_order(&mut stream, ManufacturedItem::Steel).unwrap();

    assert_eq!(stream.position(), 66);
    assert_eq!(state.progress.quantity, 3);
    assert_eq!(
        state.progress.limiting_constraint,
        ProductionConstraint::Capacity
    );
    assert_eq!(state.progress.tracking_by_resource[ResourceKind::Coal], 3);
    assert_eq!(state.progress.tracking_by_resource[ResourceKind::Iron], 3);
    assert_eq!(state.progress.reserved_workforce, 0);
    assert_eq!(state.progress.accumulated_value, 27);
    assert_eq!(state.requested_quantity, 5);
}

#[test]
fn rejects_item_order_with_the_wrong_static_production_slot() {
    let mut bytes = nonzero_steel_order_payload();
    bytes[64..66].copy_from_slice(&3_i16.to_le_bytes());
    let mut stream = LegacyStream::new(&bytes);

    assert!(matches!(
        read_item_order(&mut stream, ManufacturedItem::Steel),
        Err(LegacySaveError::InvalidCityOrder { .. })
    ));
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

    let save = LegacySaveV62::parse(&bytes).unwrap();
    let state = save.game_state(game_context()).unwrap();
    assert_eq!(state.turn().diplomacy_year_term_raw, -1234);
    assert!(state.technology().advanced_iron_working);
    assert!(state.technology().marine_engineering);
    assert_eq!(
        state.market().rows[TradeCommodity::Oil].maximum_offer_by_nation[NationId::new(22)],
        321
    );
}

#[test]
fn technology_decoder_requires_boolean_resource_type_flags() {
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
    let technology = read_technology_state(&mut stream).unwrap();
    assert!(technology.advanced_iron_working);
    assert!(technology.marine_engineering);
    assert!(technology.oil_drilling_available());
    assert_eq!(technology.scheduled_unlock_turn_by_technology[4], 17);
    assert_eq!(
        technology.research_status_by_nation[MajorNationId::new(4)][4],
        TechnologyResearchStatus::Pending
    );
    assert!(technology.industry_enabled_by_slot[CityFacilitySlot::OilRefinery as usize]);
    assert!(
        technology.military_unit_ability_active_by_nation[MajorNationId::new(2)]
            [MilitaryUnitKind::SiegeArtillery]
    );
    assert!(technology.city_capabilities_by_nation[MajorNationId::new(2)].advanced_iron_working);
    assert!(technology.city_capabilities_by_nation[MajorNationId::new(3)].oil_drilling);
    assert!(
        technology.city_capabilities_by_nation[MajorNationId::new(1)]
            .university
            .available[CivilianUnitKind::Driller]
    );
    assert_eq!(
        technology.city_capabilities_by_nation[MajorNationId::new(1)]
            .university
            .requirement_levels[ResourceKind::Oil],
        3
    );
    assert_eq!(
        technology.city_capabilities_by_nation[MajorNationId::new(3)]
            .fort_level_cap
            .get(),
        1
    );
    assert_eq!(stream.position(), TECH_SERIALIZED_SIZE_V62);

    for (offset, value) in [
        (TECH_ADVANCED_IRON_WORKING_OFFSET_V62, 2),
        (TECH_MARINE_ENGINEERING_OFFSET_V62, u8::MAX),
        (
            TECH_GLOBAL_UNLOCK_FLAGS_OFFSET_V62 + TECH_OIL_DRILLING_ID,
            2,
        ),
        (TECH_INDUSTRY_ENABLED_OFFSET_V62 + 13, 2),
        (
            TECH_ABILITY_ACTIVE_ROWS_OFFSET_V62 + 6 * TECH_ABILITY_ACTIVE_ROW_SIZE + 29,
            2,
        ),
    ] {
        let mut bytes = [0_u8; TECH_SERIALIZED_SIZE_V62];
        bytes[offset] = value;
        assert!(matches!(
            read_technology_state(&mut LegacyStream::new(&bytes)),
            Err(LegacySaveError::InvalidBoolean {
                value: invalid,
                ..
            }) if invalid == value
        ));
    }

    let mut bytes = [0_u8; TECH_SERIALIZED_SIZE_V62];
    bytes[TECH_ORDER_CAP_ROWS_OFFSET_V62 + TECH_OIL_DRILLING_ID] = 3;
    assert!(matches!(
        read_technology_state(&mut LegacyStream::new(&bytes)),
        Err(LegacySaveError::StateProjection(message))
            if message == "major nation 0 technology 19 status 3 is invalid"
    ));

    let mut bytes = [0_u8; TECH_SERIALIZED_SIZE_V62];
    bytes[TECH_UNIVERSITY_AVAILABILITY_OFFSET_V62] = 2;
    assert!(matches!(
        read_technology_state(&mut LegacyStream::new(&bytes)),
        Err(LegacySaveError::InvalidBoolean { value: 2, .. })
    ));

    let mut bytes = [0_u8; TECH_SERIALIZED_SIZE_V62];
    bytes[TECH_FINAL_REQUIREMENT_LEVELS_OFFSET_V62..][..2].copy_from_slice(&4_i16.to_be_bytes());
    assert!(matches!(
        read_technology_state(&mut LegacyStream::new(&bytes)),
        Err(LegacySaveError::StateProjection(message))
            if message.contains("university requirement level 4")
    ));
}

#[test]
fn trade_maximum_decoder_keeps_all_nation_slots_and_rejects_negatives() {
    let mut bytes = [0_u8; MARKET_ROW_SERIALIZED_SIZE_V62];
    let nation_zero_offset = MARKET_MAXIMUM_OFFER_OFFSET_V62;
    let nation_twenty_two_offset = MARKET_MAXIMUM_OFFER_OFFSET_V62 + 22 * 2;
    assert_eq!(nation_zero_offset, 0x70);
    assert_eq!(nation_twenty_two_offset, 0x9c);
    bytes[nation_zero_offset..nation_zero_offset + 2].copy_from_slice(&17_i16.to_be_bytes());
    bytes[nation_twenty_two_offset..nation_twenty_two_offset + 2]
        .copy_from_slice(&222_i16.to_be_bytes());

    let mut stream = LegacyStream::new(&bytes);
    let row = read_trade_market_row(&mut stream, 6).unwrap();
    assert_eq!(stream.position(), MARKET_ROW_SERIALIZED_SIZE_V62);
    assert_eq!(row.maximum_offer_by_nation[NationId::new(0)], 17);
    assert_eq!(row.maximum_offer_by_nation[NationId::new(22)], 222);

    bytes[nation_twenty_two_offset..nation_twenty_two_offset + 2]
        .copy_from_slice(&(-1_i16).to_be_bytes());
    assert!(matches!(
        read_trade_market_row(&mut LegacyStream::new(&bytes), 6),
        Err(LegacySaveError::NegativeTradeOfferMaximum {
            commodity: 6,
            nation: 22,
            value: -1,
        })
    ));
}

#[test]
fn reads_the_exact_v62_diplomacy_payload_and_endianness() {
    let bytes = valid_diplomacy_payload();
    let mut stream = LegacyStream::new(&bytes);
    let diplomacy = read_diplomacy_state(&mut stream).unwrap();

    assert_eq!(stream.position(), DIPLOMACY_SERIALIZED_SIZE_V62);
    assert_eq!(
        diplomacy.standings[NationId::new(0)][NationId::new(0)],
        0x1234
    );
    assert_eq!(
        diplomacy.relationship_turns[NationId::new(0)][NationId::new(0)],
        Some(7)
    );
    assert_eq!(diplomacy.influence_thresholds[ProvinceId::new(0)], 0x2345);
    assert_eq!(
        diplomacy.influence_sides[ProvinceId::new(0)],
        Some(MajorNationId::new(6))
    );
    assert_eq!(diplomacy.last_diplomatic_effort_turn, 0x3456);
    assert_eq!(
        diplomacy.mission_levels[NationId::new(0)][NationId::new(1)],
        DiplomaticMissionLevel::Embassy
    );
    assert_eq!(diplomacy.congress.chairman, Some(MajorNationId::new(6)));
    assert_eq!(diplomacy.congress.counterpart, None);
    assert_eq!(diplomacy.congress.neutral_support, 3);
    assert_eq!(
        diplomacy.special_relation_sources[MinorNationId::new(7)],
        Some(MajorNationId::new(5))
    );
    assert_eq!(diplomacy.last_processed_nation, None);
    assert_eq!(diplomacy.proposal_mode_raw, 0);
}

#[test]
fn rejects_malformed_closed_diplomacy_domains_and_sentinels() {
    for (offset, replacement) in [
        (RELATIONSHIP_OFFSET, 1_i16.to_be_bytes()),
        (TURN_STAMP_OFFSET, (-2_i16).to_be_bytes()),
        (MISSION_LEVEL_OFFSET, 3_i16.to_be_bytes()),
        (CONGRESS_OFFSET, 7_i16.to_be_bytes()),
    ] {
        let mut bytes = valid_diplomacy_payload();
        bytes[offset..offset + 2].copy_from_slice(&replacement);
        assert!(matches!(
            read_diplomacy_state(&mut LegacyStream::new(&bytes)),
            Err(LegacySaveError::InvalidDiplomacyValue { .. })
        ));
    }

    let mut bytes = valid_diplomacy_payload();
    bytes[INFLUENCE_SIDE_OFFSET] = 7;
    assert!(matches!(
        read_diplomacy_state(&mut LegacyStream::new(&bytes)),
        Err(LegacySaveError::InvalidDiplomacyValue { .. })
    ));
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
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    let lists = &mut first_great_power_mut(&mut save).prefix.relationship_lists;
    lists[0].records = vec![relationship_record(-7, 2), relationship_record(9, 0)];
    lists[1].records = vec![relationship_record(0x134, 5), relationship_record(0x12d, 1)];
    let mut context = game_context();
    context.crt_rand_state = 0x1234_5678;

    let state = save.game_state(context).unwrap();
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
fn rejects_relationship_queues_that_need_unavailable_load_time_rng() {
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    first_great_power_mut(&mut save).prefix.relationship_lists[0].records =
        vec![relationship_record(1, 2), relationship_record(2, 2)];

    assert!(matches!(
        save.game_state(game_context()),
        Err(LegacySaveError::StateProjection(message))
            if message == "nation 0 turn-event queue contains distinguishable records from source 2; retail load order depends on unavailable pre-load CRT state"
    ));
}

#[test]
fn accepts_identical_equal_source_relationship_records_without_rng_draws() {
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    let lists = &mut first_great_power_mut(&mut save).prefix.relationship_lists;
    lists[0].records = vec![relationship_record(-7, 2), relationship_record(-7, 2)];
    lists[1].records = vec![relationship_record(0x12d, 1), relationship_record(0x12d, 1)];
    let mut context = game_context();
    context.crt_rand_state = 0x1234_5678;

    let state = save.game_state(context).unwrap();
    let pending = &state.pending().nations[MajorNationId::new(0)];
    assert_eq!(
        pending.turn_events,
        vec![
            DiplomacyNotice {
                source: NationId::new(2),
                code: -7,
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
                source: NationId::new(1),
                policy: DiplomacyPolicy::JoinEmpire,
            },
        ]
    );
    assert_eq!(state.rng().crt_rand.state(), 0x1234_5678);
}

#[test]
fn validates_relationship_record_shape_source_and_policy() {
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    first_great_power_mut(&mut save).prefix.relationship_lists[0].record_size = 2;
    assert!(matches!(
        save.game_state(game_context()),
        Err(LegacySaveError::StateProjection(message))
            if message == "nation 0 turn-event queue has record size 2; expected 4"
    ));

    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    first_great_power_mut(&mut save).prefix.relationship_lists[0].records =
        vec![relationship_record(1, 23)];
    assert!(matches!(
        save.game_state(game_context()),
        Err(LegacySaveError::StateProjection(message))
            if message == "nation slot 23 is outside the retail range 0..=22"
    ));

    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    first_great_power_mut(&mut save).prefix.relationship_lists[1].records =
        vec![relationship_record(0x12c, 1)];
    assert!(matches!(
        save.game_state(game_context()),
        Err(LegacySaveError::UnsupportedDiplomacyPolicy {
            nation: 0,
            target: 1,
            entry: 0x12c,
        })
    ));
}

#[test]
fn projects_exact_fixture_phase_ten_inputs_and_newest_port_owners() {
    let save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    assert_eq!(save.ocean.zones.len(), 60);
    assert_eq!(save.ocean.port_zones.len(), 23);
    let state = save.game_state(game_context()).unwrap();
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
        let targets = major.economy().ai_zone_targets.as_ref().unwrap();
        assert_eq!(targets.len(), 83);
        let mut expected_targets = vec![AiTargetState::Unmarked; 83];
        for ordinal in expected_zones {
            expected_targets[ordinal] = AiTargetState::MissionQueued;
        }
        assert_eq!(targets, &expected_targets);

        let province_targets = major.economy().ai_province_targets.as_ref().unwrap();
        for province in (0..ProvinceId::COUNT).map(ProvinceId::new) {
            let expected = if expected_provinces.contains(&province.get()) {
                AiTargetState::MissionQueued
            } else {
                AiTargetState::Unmarked
            };
            assert_eq!(province_targets[province], expected);
        }
        assert_eq!(major.economy().army_movement_budget, 15);
    }
    let human = state.nations().major(MajorNationId::new(6)).economy();
    assert!(human.ai_zone_targets.is_none());
    assert!(human.ai_province_targets.is_none());
    assert_eq!(human.army_movement_budget, 15);
    for province in (0..ProvinceId::COUNT).map(ProvinceId::new) {
        assert_eq!(state.provinces()[province].development_stage(), 0);
        assert!(
            (0..MajorNationId::COUNT)
                .map(MajorNationId::new)
                .all(|nation| !state.provinces()[province].explored_by_majors()[nation])
        );
    }
    assert_eq!(state.port_zone_owners().len(), 23);
    for (owner, saved) in state
        .port_zone_owners()
        .iter()
        .zip(save.ocean.port_zones.iter().rev())
    {
        assert_eq!(owner.zone.get(), saved.context_ordinal as u16);
        let tile = saved.port_tile_index.unwrap() as usize;
        assert_eq!(
            owner.former_owner.get(),
            save.map.tiles[tile].former_owner_nation as u8
        );
    }
}

#[test]
fn validates_phase_ten_map_target_domains() {
    let save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    assert_eq!(validate_ocean_contexts(&save.ocean).unwrap(), 83);

    let mut ocean = save.ocean.clone();
    ocean.zones[0].context_ordinal = -1;
    assert!(matches!(
        validate_ocean_contexts(&ocean),
        Err(LegacySaveError::StateProjection(message))
            if message == "ocean context ordinal -1 is negative"
    ));

    let mut ocean = save.ocean.clone();
    ocean.zones[1].context_ordinal = ocean.zones[0].context_ordinal;
    assert!(matches!(
        validate_ocean_contexts(&ocean),
        Err(LegacySaveError::StateProjection(message))
            if message == "ocean context ordinal 0 is duplicated"
    ));

    let mut ocean = save.ocean.clone();
    ocean.zones[0].context_ordinal = 83;
    assert!(matches!(
        validate_ocean_contexts(&ocean),
        Err(LegacySaveError::StateProjection(message))
            if message == "ocean context ordinal 83 is outside the live range 0..83"
    ));

    let mut ocean = save.ocean.clone();
    ocean
        .zones
        .extend(std::iter::repeat_n(ocean.zones[0].clone(), 30));
    assert!(matches!(
        validate_ocean_contexts(&ocean),
        Err(LegacySaveError::StateProjection(message))
            if message == "ocean has 113 live contexts; AI state supports at most 112"
    ));

    let mut flags = [0; AI_ZONE_TARGET_CAPACITY];
    flags[0] = 3;
    assert!(matches!(
        ai_zone_targets(&flags, 83, 0),
        Err(LegacySaveError::StateProjection(message))
            if message == "AI nation 0 ocean context 0 has invalid target state 3"
    ));
    flags[0] = 0;
    flags[83] = 1;
    assert!(matches!(
        ai_zone_targets(&flags, 83, 0),
        Err(LegacySaveError::StateProjection(message))
            if message == "AI nation 0 unused ocean context 83 has nonzero target state 1"
    ));

    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    let LegacyMajorNationState::Auto(nation) = &mut save.major_nations[0] else {
        unreachable!()
    };
    nation.auto_prefix.map_node_state_flags[0] = 3;
    assert!(matches!(
        save.game_state(game_context()),
        Err(LegacySaveError::StateProjection(message))
            if message == "AI nation 0 province 0 has invalid target state 3"
    ));

    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    save.map.provinces[0].explored_by_nation_mask = 0x80;
    assert!(matches!(
        save.game_state(game_context()),
        Err(LegacySaveError::StateProjection(message))
            if message == "province 0 exploration mask has unsupported upper bit set"
    ));
}

#[test]
fn port_owner_projection_uses_port_tile_former_owner_and_newest_order() {
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    let newest = save.ocean.port_zones.len() - 1;
    let next_newest = newest - 1;
    let newest_zone = save.ocean.port_zones[newest].context_ordinal;
    let next_newest_zone = save.ocean.port_zones[next_newest].context_ordinal;
    let newest_tile = save.ocean.port_zones[newest].port_tile_index.unwrap() as usize;
    let next_newest_tile = save.ocean.port_zones[next_newest].port_tile_index.unwrap() as usize;
    save.ocean.port_zones[newest].seed_nation_id = 6;
    save.ocean.port_zones[next_newest].seed_nation_id = 5;
    save.map.tiles[newest_tile].former_owner_nation = 0;
    save.map.tiles[next_newest_tile].former_owner_nation = 0;

    let owners = port_zone_owners(&save.ocean, &save.map).unwrap();
    assert_eq!(
        &owners[..2],
        &[
            PortZoneOwner {
                zone: OceanZoneId::new(newest_zone as u16),
                former_owner: NationId::new(0),
            },
            PortZoneOwner {
                zone: OceanZoneId::new(next_newest_zone as u16),
                former_owner: NationId::new(0),
            },
        ]
    );
}

#[test]
fn retail_projection_preserves_minister_identity_and_direct_state() {
    let save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    let state = save.game_state(game_context()).unwrap();
    assert_eq!(
        save.simulation.game_setup.foreign_minister_policy_ids,
        [1, 4, 2, 4, 3, 5, 3]
    );
    assert_eq!(
        state
            .nations()
            .majors()
            .map(|nation| nation.economy().foreign_minister_personality)
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
            .map(|nation| nation.economy().foreign_minister_skill_index)
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
        nation.economy().development_grant_by_nation == NationTable::<i16>::default()
            && nation.economy().defense_minister_skill_index == 0
            && *nation.economy().interior_civilian == expected_interior
    }));
    assert!(state.nations().majors().take(6).all(|nation| {
        nation.economy().ai_development_pressure == Some(AiDevelopmentPressureState::default())
    }));
    assert_eq!(
        state
            .nations()
            .major(MajorNationId::new(6))
            .economy()
            .ai_development_pressure,
        None
    );
    assert_eq!(
        state
            .nations()
            .majors()
            .map(|nation| nation.city().home_town)
            .collect::<Vec<_>>(),
        [3_494, 2_992, 2_862, 1_563, 1_420, 4_555, 1_685].map(|tile| Some(TownState::new(
            TileId::new(tile),
            true,
            true,
            true
        )))
    );
    assert_eq!(
        state
            .nations()
            .major(MajorNationId::new(6))
            .economy()
            .foreign_minister_personality,
        ForeignMinisterPersonality::Base,
        "the human constructs the base minister even though setup policy 3 names Diplomat"
    );
}

#[test]
fn projects_mission_holds_and_ordered_pending_development_actions() {
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    first_great_power_mut(&mut save)
        .ministers
        .interior
        .as_mut()
        .unwrap()
        .integer_lists[2] = vec![34, 7];

    let state = save.game_state(game_context()).unwrap();
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
            .economy()
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
fn rejects_pending_development_actions_outside_both_retail_domains() {
    for invalid in [-1, 44] {
        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        first_great_power_mut(&mut save)
            .ministers
            .interior
            .as_mut()
            .unwrap()
            .integer_lists[2] = vec![invalid];

        assert!(matches!(
            save.game_state(game_context()),
            Err(LegacySaveError::StateProjection(message))
                if message == format!(
                    "major nation 0 pending development action {invalid} is out of range"
                )
        ));
    }
}

#[test]
fn retail_projection_preserves_country_and_province_semantics() {
    let save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    let state = save.game_state(game_context()).unwrap();

    let nation_zero = state.nations().major(MajorNationId::new(0)).common();
    assert_eq!(nation_zero.status(), CountryStatus::Independent);
    assert_eq!(
        nation_zero.owned_regions(),
        [79, 80, 89, 90, 91, 100, 101, 111]
            .map(ProvinceId::new)
            .to_vec()
    );

    let province_zero = &state.provinces()[ProvinceId::new(0)];
    assert_eq!(province_zero.owner(), Some(NationId::new(12)));
    assert_eq!(province_zero.former_owner(), Some(NationId::new(12)));
    assert_eq!(province_zero.adjacency(), [8, 1, 17].map(ProvinceId::new));
    assert_eq!(province_zero.region_class(), Some(0));
    assert_eq!(province_zero.fort_level(), 0);
    assert_eq!(province_zero.city_tile(), Some(TileId::new(695)));
    assert_eq!(
        province_zero.resource_development_by_type(),
        &ResourceTable::default()
    );
    assert_eq!(province_zero.city_score(), 0);

    let province_seventy_nine = &state.provinces()[ProvinceId::new(79)];
    assert_eq!(province_seventy_nine.owner(), Some(NationId::new(0)));
    assert_eq!(
        province_seventy_nine.adjacency(),
        [71, 72, 80, 78, 89, 90].map(ProvinceId::new)
    );
    assert_eq!(province_seventy_nine.region_class(), Some(4));
    assert_eq!(province_seventy_nine.fort_level(), 0);
    assert_eq!(province_seventy_nine.city_tile(), Some(TileId::new(3_706)));
    assert_eq!(
        province_seventy_nine.resource_development_by_type(),
        &ResourceTable::default()
    );
    assert_eq!(province_seventy_nine.city_score(), 0);

    for province in 120..PROVINCE_COUNT {
        assert_eq!(
            state.provinces()[ProvinceId::new(province as u16)],
            ProvinceState::default()
        );
    }

    assert!(state.do_nation_territories_share_region_class(NationId::new(0), NationId::new(19)));
    assert!(!state.do_nation_territories_share_region_class(NationId::new(0), NationId::new(1)));
    assert!(state.are_nations_border_linked(NationId::new(0), NationId::new(19)));
    assert!(!state.are_nations_border_linked(NationId::new(0), NationId::new(1)));
}

#[test]
fn country_status_projection_accepts_only_retail_encodings() {
    for (encoded, expected) in [
        (-1, CountryStatus::Independent),
        (100, CountryStatus::ProtectorateOf(NationId::new(0))),
        (122, CountryStatus::ProtectorateOf(NationId::new(22))),
        (200, CountryStatus::ColonyOf(NationId::new(0))),
        (222, CountryStatus::ColonyOf(NationId::new(22))),
    ] {
        assert_eq!(country_status_from_retail(encoded).unwrap(), expected);
    }
    for encoded in [-2, 0, 99, 123, 199, 223] {
        assert!(country_status_from_retail(encoded).is_err());
    }
}

#[test]
fn semantic_projection_rejects_malformed_territory_inputs() {
    for count in [-1, 13] {
        let save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        let mut province = save.map.provinces[0].clone();
        province.adjacent_region_count = count;
        assert!(province_state(0, &province).is_err());
    }
    for adjacent in [-1, 384] {
        let save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        let mut province = save.map.provinces[0].clone();
        province.adjacent_region_count = 1;
        province.adjacent_region_ids[0] = adjacent;
        assert!(province_state(0, &province).is_err());
    }

    let save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    let mut province = save.map.provinces[0].clone();
    province.owner_nation = 23;
    assert!(province_state(0, &province).is_err());
    province.owner_nation = 0;
    province.former_owner_nation = 23;
    assert!(province_state(0, &province).is_err());
    province.former_owner_nation = 0;
    province.region_class = 24;
    assert!(province_state(0, &province).is_err());

    for owned_region in [-1, 384] {
        let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
        first_great_power_mut(&mut save).country.owned_regions[0] = owned_region;
        assert!(save.game_state(game_context()).is_err());
    }

    let mut mismatched_index = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    mismatched_index.map.provinces[79].owner_nation = 1;
    let error = mismatched_index.game_state(game_context()).unwrap_err();
    assert!(matches!(
        error,
        LegacySaveError::StateProjection(detail)
            if detail.contains("invalid territory index")
                && detail.contains("province ProvinceId(79)")
    ));

    let mut too_short = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    too_short.map.provinces.pop();
    assert!(too_short.game_state(game_context()).is_err());
    let mut too_long = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    too_long
        .map
        .provinces
        .push(too_long.map.provinces[0].clone());
    assert!(too_long.game_state(game_context()).is_err());

    let mut stale_tail = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    stale_tail.map.provinces[120].adjacent_region_ids[0] = 384;
    assert!(stale_tail.game_state(game_context()).is_ok());
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
fn normalizes_the_one_based_scenario_map_while_reading_game_setup() {
    const SCENARIO_MAP_OFFSET: usize = 60;
    let mut bytes = [0_u8; SCENARIO_MAP_OFFSET + std::mem::size_of::<i16>()];

    bytes[SCENARIO_MAP_OFFSET..].copy_from_slice(&1_i16.to_le_bytes());
    let setup = read_game_setup(&mut LegacyStream::new(&bytes)).unwrap();
    assert_eq!(setup.scenario_map, Some(ScenarioMapId::new(0)));

    bytes[SCENARIO_MAP_OFFSET..].copy_from_slice(&(-1_i16).to_le_bytes());
    let setup = read_game_setup(&mut LegacyStream::new(&bytes)).unwrap();
    assert_eq!(setup.scenario_map, None);
}

#[test]
fn rejects_negative_army_mission_unit_counts_as_invalid_counts() {
    let mut bytes = [0_u8; 2 + 5 * 4 + 2];
    bytes[22..].copy_from_slice(&(-1_i16).to_le_bytes());

    let error = read_army_mission(&mut LegacyStream::new(&bytes)).unwrap_err();
    let LegacySaveError::InvalidCount {
        context,
        value,
        maximum,
    } = error
    else {
        panic!("expected invalid count, got {error:?}");
    };
    assert_eq!(context, "army mission units");
    assert_eq!(value, -1);
    assert_eq!(maximum, MAX_MILITARY_UNITS);
}

#[test]
fn parses_the_retail_beginning_of_game_prefix() {
    let save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
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
    assert_eq!(
        save.market.rows[TradeCommodity::Cotton],
        TradeMarketRow {
            previous_price: 100,
            price: 100,
            base_price: 100,
            request_count: 0,
            offer_count: 0,
            amount_offered: 0,
            adjusted_offer_count: 0.0,
            maximum_offer_by_nation: NationTable::default(),
        }
    );
    assert_eq!(save.market.rows[TradeCommodity::Arms].base_price, 900);
    let expected_technology = TechnologyState {
        scheduled_unlock_turn_by_technology: [
            0, 0, 0, 9, 32, 31, 27, 39, 47, 50, 64, 90, 93, 117, 111, 132, 140, 153, 166, 172, 200,
            204, 225, 230, 229, 246, 248, 268, 274,
        ],
        ..TechnologyState::default()
    };
    assert_eq!(save.technology, expected_technology);
    assert_eq!(
        save.diplomacy.standings[NationId::new(0)][NationId::new(0)],
        0x100
    );
    assert_eq!(
        save.diplomacy.relationships[NationId::new(0)][NationId::new(1)],
        DiplomaticRelationship::Peace
    );
    assert_eq!(
        save.diplomacy.relationship_turns[NationId::new(0)][NationId::new(1)],
        None
    );
    assert_eq!(
        save.diplomacy.mission_levels[NationId::new(0)][NationId::new(1)],
        DiplomaticMissionLevel::Embassy
    );
    assert_eq!(save.diplomacy.congress.chairman, None);
    assert_eq!(save.minor_nations[0].diplomacy_save_fields, [7, 8, 9, 10]);
    assert_eq!(save.map.tiles.len(), 6480);
    assert_eq!(save.map.provinces.len(), 384);
    assert_eq!(save.map.no_horizontal_wrap, 0);
    assert_eq!(save.map.tiles[0].terrain_kind, 5);
    assert_eq!(save.map.tiles[0].owner_nation, 82);
    let world = save.world_state().unwrap();
    assert_eq!(world.topology(), MapTopology::Wrapping);
    assert_eq!(world[TileId::new(0)].terrain, TerrainKind::Water);
    assert_eq!(
        world[TileId::new(0)].owner_nation,
        Some(TileOwnerTag::new(82))
    );
    assert!(!save.ocean.zones.is_empty());
    assert!(save.navy.ships.is_empty());
    assert!(save.navy.admirals.is_empty());
    assert!(save.navy.task_forces.is_empty());
    assert_eq!(save.army_report_count, 0);
    assert_eq!(save.remaining_manager_chain_offset, 0x4dc51);

    let (country, suffix_offset) =
        parse_country_base_at(RETAIL_FIXTURE, save.remaining_manager_chain_offset).unwrap();
    assert_eq!(country.identity, "Zimm");
    assert_eq!(country.alternate_identity, "Zimm");
    assert_eq!(country.nation_slot, 0);
    assert_eq!(country.status, CountryStatus::Independent);
    assert_eq!(country.treasury, 10_000);
    assert_eq!(country.home_tile, 3_494);
    assert_eq!(country.overlay_anchor_tile, -1);
    assert_eq!(country.need_level_by_nation, [100; NATION_COUNT]);
    assert_eq!(country.military_units.len(), 27);
    assert_eq!(country.military_units[0].name, "1st Minutemen");
    assert_eq!(country.military_units[0].persistent_id, 0x113);
    assert_eq!(country.military_units[0].stationed_province, 79);
    assert_eq!(country.military_units[0].strength, 500);
    let unit_states = country.military_unit_states(NationId::new(0)).unwrap();
    assert_eq!(unit_states.len(), 27);
    assert_eq!(unit_states[0].id().get(), 275);
    assert_eq!(unit_states[0].unit_type(), MilitaryUnitKind::Minutemen);
    assert_eq!(
        *unit_states[0].order().targets(),
        [Some(ProvinceId::new(79)); 3]
    );
    assert_eq!(unit_states[26].id().get(), 301);
    assert_eq!(suffix_offset, 0x4e2a3);

    let (great_power, optional_payload_offset) =
        parse_great_power_prefix_at(RETAIL_FIXTURE, suffix_offset).unwrap();
    assert_eq!(great_power.capacities, [0, 0, 15, 11]);
    assert_eq!(great_power.relationship_lists.len(), 19);
    assert_eq!(great_power.relationship_lists[0].record_size, 4);
    assert_eq!(great_power.relationship_lists[2].record_size, 12);
    assert_eq!(great_power.minister_presence_mask, 0x0f);
    assert_eq!(optional_payload_offset, 0x4eae0);

    let (ministers, city_offset) = parse_great_power_ministers_at(
        RETAIL_FIXTURE,
        optional_payload_offset,
        great_power.minister_presence_mask,
        save.simulation.game_setup.foreign_minister_policy_ids[0],
    )
    .unwrap();
    assert!(ministers.foreign.is_some());
    assert_eq!(
        ministers.interior.as_ref().unwrap().integer_lists[0].len(),
        8
    );
    assert_eq!(
        ministers.interior.as_ref().unwrap().integer_lists[1].len(),
        20
    );
    assert!(ministers.defense.is_some());
    assert_eq!(city_offset, 0x4edd0);

    let (city, city_suffix_offset) = parse_city_at(RETAIL_FIXTURE, city_offset).unwrap();
    assert_eq!(city.orders, CityOrders::default());
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
    assert_eq!(city_suffix_offset, 0x4fbf6);

    let city_state = city
        .city_state(Some(TownState::new(TileId::new(3_494), true, true, true)))
        .unwrap();
    assert_eq!(
        city_state.home_town.map(TownState::tile),
        Some(TileId::new(3_494))
    );
    assert_eq!(*city_state.orders, CityOrders::default());
    assert_eq!(
        city_state.population.accumulator().get().to_bits(),
        1_088_421_888
    );

    let (post_city, auto_offset) =
        parse_great_power_post_city_at(RETAIL_FIXTURE, city_suffix_offset).unwrap();
    assert_eq!(post_city.towns.len(), 1);
    assert_eq!(post_city.towns[0].name, "FrogCity");
    assert_eq!(post_city.towns[0].tile_index, 3_494);
    assert_eq!(post_city.civilian_units.len(), 2);
    assert_eq!(post_city.diplomacy_budget_base, 50_000);
    assert_eq!(post_city.special_resource_trade_balance, 0);
    assert_eq!(auto_offset, 0x4fcc1);

    let (auto, first_mission_offset) =
        parse_auto_great_power_prefix_at(RETAIL_FIXTURE, auto_offset).unwrap();
    assert_eq!(auto.mission_count, 11);
    assert_eq!(first_mission_offset, 0x4fec1);

    let mut archive = LegacyMfcArchiveState::default();
    let (missions, second_nation_offset) = parse_missions_at(
        RETAIL_FIXTURE,
        first_mission_offset,
        auto.mission_count,
        &mut archive,
    )
    .unwrap();
    assert_eq!(missions.len(), 11);
    assert_eq!(second_nation_offset, 0x500be);
    assert_eq!(missions[0].class, "TDefendProvinceMission");
    assert_eq!(missions[0].army.as_ref().unwrap().present_location, 79);
    assert_eq!(missions[7].army.as_ref().unwrap().present_location, 111);
    assert_eq!(missions[8].class, "TControlSeaZoneMission");
    assert_eq!(missions[8].navy.as_ref().unwrap().target_zone, 22);
    assert_eq!(missions[9].class, "TEscortMission");
    assert_eq!(missions[9].navy.as_ref().unwrap().target_zone, 66);
    assert_eq!(missions[10].class, "TScatteredShipsMission");
    assert_eq!(missions[10].importance_bits, 981_668_463);

    let mission_states = missions
        .iter()
        .enumerate()
        .map(|(queue_index, mission)| {
            mission
                .mission_state(NationId::new(0), queue_index, &country.military_units)
                .unwrap()
        })
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

    let mut archive = LegacyMfcArchiveState::default();
    let mut nation_offset = save.remaining_manager_chain_offset;
    let mut global_mission_index = 0;
    for nation in 0..6 {
        let (major, next_offset) = parse_auto_great_power_record_at(
            RETAIL_FIXTURE,
            nation_offset,
            save.simulation.game_setup.foreign_minister_policy_ids[nation],
            &mut archive,
        )
        .unwrap();
        assert_eq!(major.great_power.country.nation_slot, nation as i16);
        assert_eq!(major.missions.len(), 11);
        for (queue_index, mission) in major.missions.iter().enumerate() {
            let state = mission
                .mission_state(
                    NationId::new(nation as u8),
                    queue_index,
                    &major.great_power.country.military_units,
                )
                .unwrap();
            assert_eq!(state.nation, NationId::new(nation as u8));
            global_mission_index += 1;
        }
        nation_offset = next_offset;
    }
    assert_eq!(global_mission_index, 66);

    // The seventh major is player-controlled and therefore has no
    // TAutoGreatPower suffix or mission queue.
    let (player_major, minor_nations_offset) = parse_great_power_record_at(
        RETAIL_FIXTURE,
        nation_offset,
        save.simulation.game_setup.foreign_minister_policy_ids[6],
    )
    .unwrap();
    assert_eq!(player_major.country.nation_slot, 6);
    assert_eq!(player_major.country.identity, " Testland");
    assert_eq!(player_major.country.alternate_identity, " Testland");
    assert!(minor_nations_offset > nation_offset);

    let mut minor_offset = minor_nations_offset;
    for nation in 7..NATION_COUNT {
        let (minor, next_offset) = parse_minor_record_at(RETAIL_FIXTURE, minor_offset).unwrap();
        assert_eq!(minor.country.nation_slot, nation as i16);
        assert_eq!(minor.diplomacy_save_extension.len(), RESOURCE_KIND_COUNT);
        minor_offset = next_offset;
    }
    assert_eq!(minor_offset, 0x62503);
    let (help, end_offset) = parse_help_manager_at(RETAIL_FIXTURE, minor_offset).unwrap();
    assert_eq!(help.index_records.record_size, 14);
    assert_eq!(help.index_records.records.len(), 30);
    assert_eq!(end_offset, RETAIL_FIXTURE.len());

    assert_eq!(save.major_nations.len(), 7);
    assert_eq!(save.minor_nations.len(), 16);
    assert_eq!(save.help, help);
    assert_eq!(save.end_offset, RETAIL_FIXTURE.len());

    let mut game = save
        .game_state(LegacyGameStateContext {
            crt_rand_state: 1,
            map_generation_lcg: 0,
            zone_status_lcg: 3_916_827_792,
            selected_nation: NationId::new(6),
        })
        .unwrap();
    assert_eq!(game.market(), &save.market);
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
            .all(|nation| nation.economy().turn_finished)
    );
    assert!(
        !game
            .nations()
            .major(MajorNationId::new(6))
            .economy()
            .turn_finished
    );
    let mut turn = *game.turn();
    turn.advance_season();
    assert_eq!(turn.economic_turn, 2);
}

#[test]
fn semantic_projection_rejects_missing_major_aggregates() {
    let context = game_context();

    let mut missing_major = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    missing_major.major_nations.pop();
    assert!(matches!(
        missing_major.game_state(context),
        Err(LegacySaveError::StateProjection(message))
            if message == "major nation slot 6 is absent"
    ));

    let mut missing_city = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    match &mut missing_city.major_nations[0] {
        LegacyMajorNationState::Auto(nation) => nation.great_power.city = None,
        LegacyMajorNationState::Other(nation) => nation.city = None,
    }
    assert!(matches!(
        missing_city.game_state(context),
        Err(LegacySaveError::StateProjection(message))
            if message == "major nation slot 0 has no city"
    ));
}

#[test]
fn semantic_projection_rejects_nonfinite_population_accumulator() {
    let context = game_context();
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    let city = first_great_power_mut(&mut save).city.as_mut().unwrap();
    city.population.count_float_bits = f32::NAN.to_bits();

    assert!(matches!(
        save.game_state(context),
        Err(LegacySaveError::StateProjection(message))
            if message == "population accumulator is not finite"
    ));
}

#[test]
fn semantic_projection_rejects_unit_id_counter_overflow() {
    let context = game_context();
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    save.simulation.persistent_unit_id_counter = i32::MAX;

    assert!(matches!(
        save.game_state(context),
        Err(LegacySaveError::StateProjection(message))
            if message == "persistent unit ID counter overflows while loading units"
    ));
}

#[test]
fn semantic_projection_preserves_inactive_pending_action_payload() {
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    let prefix = &mut first_great_power_mut(&mut save).prefix;
    prefix.pending_actions[PendingActionKind::NavyGrowthReward] =
        PendingActionState::new(PendingActionStatus::None, Some(0));

    let state = save.game_state(game_context()).unwrap();
    assert_eq!(
        state
            .nations()
            .majors()
            .next()
            .unwrap()
            .economy()
            .pending_actions[PendingActionKind::NavyGrowthReward]
            .payload(),
        Some(0)
    );
}

#[test]
fn pending_action_decode_rejects_payload_below_sentinel() {
    assert!(matches!(
        pending_action_from_retail(0, -2),
        Err(LegacySaveError::StateProjection(message))
            if message == "pending-action payload -2 is below the -1 sentinel"
    ));
    assert!(pending_action_from_retail(0x35, 0).is_err());
    assert_eq!(
        pending_action_from_retail(0, 0).unwrap(),
        PendingActionState::new(PendingActionStatus::None, Some(0))
    );
}

#[test]
fn semantic_projection_rejects_invalid_diplomacy_grant_flags() {
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    first_great_power_mut(&mut save)
        .prefix
        .diplomacy_grant_by_nation[0] = -2;

    assert!(matches!(
        save.game_state(game_context()),
        Err(LegacySaveError::UnsupportedDiplomacyGrantFlags {
            nation: 0,
            target: 0,
            entry: -2,
        })
    ));
}

#[test]
fn semantic_projection_rejects_invalid_mission_province_ids() {
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    let LegacyMajorNationState::Auto(nation) = &mut save.major_nations[0] else {
        panic!("first fixture nation is computer-controlled");
    };
    nation.missions[0].army.as_mut().unwrap().present_location = -2;

    assert!(matches!(
        save.game_state(game_context()),
        Err(LegacySaveError::StateProjection(message))
            if message == "province ID -2 is out of range"
    ));
}

#[test]
fn semantic_projection_rejects_unimplemented_serialized_payloads() {
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    save.navy.admirals.push(LegacyAdmiral {
        nation: 0,
        name: String::new(),
        experience: 0,
        ship_index: 0,
    });
    assert!(matches!(
        save.game_state(game_context()),
        Err(LegacySaveError::StateProjection(message))
            if message == "semantic projection of non-empty retail navy relationships is not implemented"
    ));

    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    let LegacyMajorNationState::Auto(nation) = &mut save.major_nations[0] else {
        panic!("first fixture nation is computer-controlled");
    };
    nation.missions[8]
        .navy
        .as_mut()
        .unwrap()
        .ship_ordinals
        .push(0);
    assert!(matches!(
        save.game_state(game_context()),
        Err(LegacySaveError::StateProjection(message))
            if message == "semantic projection of navy mission ship ordinal 0 is not implemented"
    ));

    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    let city = first_great_power_mut(&mut save).city.as_mut().unwrap();
    city.tasks.push(LegacyCityTask {
        kind: 1,
        payload: vec![0; 8],
    });
    assert!(matches!(
        save.game_state(game_context()),
        Err(LegacySaveError::StateProjection(message))
            if message == "semantic projection of city tasks is not implemented"
    ));

    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    let city = first_great_power_mut(&mut save).city.as_mut().unwrap();
    let record_size = city.transport_requests.record_size;
    city.transport_requests
        .records
        .push(vec![0; usize::from(record_size)]);
    assert!(matches!(
        save.game_state(game_context()),
        Err(LegacySaveError::StateProjection(message))
            if message == "semantic projection of city transport requests is not implemented"
    ));

    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
    let towns = &mut first_great_power_mut(&mut save).post_city.towns;
    let duplicate = towns[0].clone();
    towns.push(duplicate);
    assert!(matches!(
        save.game_state(game_context()),
        Err(LegacySaveError::StateProjection(message))
            if message == "major nation slot 0 has 2 towns; semantic projection supports one city"
    ));
}

#[test]
fn deal_book_projection_reconstructs_retail_sorted_load_order() {
    let mut save = LegacySaveV62::parse(RETAIL_FIXTURE).unwrap();
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

    let state = save.game_state(game_context()).unwrap();
    assert_eq!(
        state
            .nations()
            .major(MajorNationId::new(0))
            .economy()
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
fn rejects_bad_magic_old_versions_and_truncation() {
    let mut bad_magic = RETAIL_FIXTURE.to_vec();
    bad_magic[0] = 0;
    assert!(matches!(
        LegacySaveV62::parse(&bad_magic),
        Err(LegacySaveError::InvalidMagic(_))
    ));

    let mut old = RETAIL_FIXTURE.to_vec();
    old[4..8].copy_from_slice(&0x22_u32.to_le_bytes());
    assert!(matches!(
        LegacySaveV62::parse(&old),
        Err(LegacySaveError::UnsupportedVersion(0x22))
    ));
    assert!(matches!(
        LegacySaveV62::parse(&RETAIL_FIXTURE[..100]),
        Err(LegacySaveError::Truncated { .. })
    ));
    assert!(matches!(
        LegacySaveV62::parse(&[]),
        Err(LegacySaveError::Truncated {
            offset: 0,
            requested: 4,
            remaining: 0,
        })
    ));
}

#[test]
fn rejects_unsupported_tile_transport_link_bits() {
    for (field, bits) in [("transport_links", 0x40), ("pending_rail_links", 0x80)] {
        assert!(matches!(
            decode_tile_transport_links(7, field, bits),
            Err(LegacySaveError::UnsupportedTileTransportLinkBits {
                tile: 7,
                field: actual_field,
                bits: actual_bits,
            }) if actual_field == field && actual_bits == bits
        ));
    }
}
