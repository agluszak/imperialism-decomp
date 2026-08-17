use super::*;
use crate::test_support::{game_state, major_nation};

fn major(id: u8) -> MajorNationId {
    MajorNationId::new(id)
}

fn nation(id: u8) -> NationId {
    NationId::new(id)
}

fn independent_minor(id: u8) -> MinorNation {
    MinorNation {
        common: NationCommonState::from_parts(
            format!("M{id}"),
            CountryStatus::Independent,
            Vec::new(),
            5_000,
            None,
            NationTable::default(),
        ),
        consortium_members: [MinorNationId::new(id); 4],
        trade: MinorTradeState::default(),
    }
}

fn computer_major() -> MajorNation {
    let mut nation = major_nation();
    nation.auto = Some(AutoGreatPowerState::default());
    nation
}

#[test]
fn grant_to_a_peer_transfers_treasury_and_raises_embassy_standing() {
    let mut state = game_state();
    let source = major(0);
    let target = nation(1);
    state.nations.majors[source]
        .as_mut()
        .unwrap()
        .common
        .treasury = 20_000;
    assert!(
        state
            .nations
            .major_mut(source)
            .unwrap()
            .set_diplomacy_grant(
                target,
                Some(DiplomacyGrant {
                    amount: 1_000,
                    recurring: false,
                }),
            )
    );
    let source_treasury = state.nations.majors[source]
        .as_mut()
        .unwrap()
        .common
        .treasury;
    let target_treasury = state.nations.majors[major(1)]
        .as_mut()
        .unwrap()
        .common
        .treasury;
    let standing = state.diplomacy.standings[source.nation()][target];

    assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);

    assert_eq!(
        state.nations.majors[source]
            .as_mut()
            .unwrap()
            .common
            .treasury,
        source_treasury
    );
    assert_eq!(
        state.nations.majors[major(1)]
            .as_mut()
            .unwrap()
            .common
            .treasury,
        target_treasury + 1_000
    );
    assert_eq!(
        state.diplomacy.standings[source.nation()][target],
        standing + 2
    );
    assert_eq!(
        state.nations.majors[source]
            .as_mut()
            .unwrap()
            .economy
            .diplomacy_grants_by_nation[target],
        None
    );
    assert_eq!(
        state.nations.majors[source]
            .as_mut()
            .unwrap()
            .economy
            .grant_total_cost,
        0
    );
    assert_eq!(
        state.pending.nations[major(1)].turn_events,
        [DiplomacyNotice {
            source: nation(0),
            code: 1_000,
        }]
    );
}

#[test]
fn consulate_policy_sets_symmetric_mission_level_and_news() {
    let mut state = game_state();
    let source = major(0);
    let target = nation(7);
    state.nations.minors[MinorNationId::new(7)] = Some(independent_minor(7));
    state.nations.majors[source]
        .as_mut()
        .unwrap()
        .economy
        .diplomacy_policy_by_nation[target] = Some(DiplomacyPolicy::BuildConsulate);

    assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);

    assert_eq!(
        state.diplomacy.mission_levels[source.nation()][target],
        DiplomaticMissionLevel::TradeConsulate
    );
    assert_eq!(
        state.diplomacy.mission_levels[target][source.nation()],
        DiplomaticMissionLevel::TradeConsulate
    );
    assert_eq!(
        state.nations.majors[source]
            .as_mut()
            .unwrap()
            .economy
            .diplomacy_policy_by_nation[target],
        None
    );
    assert!(
        matches!(
            &state.pending.newspaper_events[..],
            [PendingNewspaperEvent::InterNation {
                event: InterNationNewsKind::TradeConsulateEstablished,
                subject,
                related_nations,
            }] if *subject == source && related_nations[target]
        ),
        "{:?}",
        state.pending.newspaper_events
    );
}

#[test]
fn minor_non_aggression_pact_is_accepted_immediately() {
    let mut state = game_state();
    let source = major(0);
    let target = nation(7);
    state.nations.minors[MinorNationId::new(7)] = Some(independent_minor(7));
    state.nations.majors[source]
        .as_mut()
        .unwrap()
        .economy
        .diplomacy_policy_by_nation[target] = Some(DiplomacyPolicy::NonAggressionPact);
    let standing = state.diplomacy.standings[source.nation()][target];

    assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);

    assert_eq!(
        state.diplomacy.relationships[source.nation()][target],
        DiplomaticRelationship::NonAggressionPact
    );
    assert_eq!(
        state.diplomacy.standings[source.nation()][target],
        standing + 10
    );
    assert_eq!(
        state.pending.nations[source].turn_events,
        [DiplomacyNotice {
            source: target,
            code: DiplomacyPolicy::NonAggressionPact.retail(),
        }]
    );
}

#[test]
fn human_offer_stops_for_a_reply_and_accepting_forms_the_alliance() {
    let mut state = game_state();
    state.nations.majors[major(1)] = Some(computer_major());
    state.nations.majors[major(1)]
        .as_mut()
        .unwrap()
        .economy
        .diplomacy_policy_by_nation[nation(0)] = Some(DiplomacyPolicy::Alliance);

    let prompt = match state.do_diplomacy() {
        DiplomacyPhaseResult::Offer(prompt) => prompt,
        other => panic!("expected an offer prompt, got {other:?}"),
    };
    assert_eq!(
        prompt,
        DiplomacyOfferPrompt {
            nation: major(0),
            index: 0,
            source: nation(1),
            policy: DiplomacyPolicy::Alliance,
        }
    );

    assert_eq!(
        state.resolve_diplomacy_offer(true),
        DiplomacyPhaseResult::Resolved
    );
    assert_eq!(
        state.diplomacy.relationships[nation(0)][nation(1)],
        DiplomaticRelationship::Alliance
    );
}

#[test]
fn declare_war_processes_one_transition_and_posts_declare_war_news() {
    let mut state = game_state();
    let source = major(0);
    let target = nation(1);
    state.nations.majors[source]
        .as_mut()
        .unwrap()
        .economy
        .diplomacy_policy_by_nation[target] = Some(DiplomacyPolicy::DeclareWar);

    assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);

    assert_eq!(
        state.diplomacy.relationships[source.nation()][target],
        DiplomaticRelationship::War
    );
    assert!(state.pending.war_transitions.is_empty());
    assert_eq!(
        state.nations.majors[source]
            .as_mut()
            .unwrap()
            .common
            .trade_policy_by_nation[target],
        TradePolicyScore::BOYCOTT
    );
    assert_eq!(
        state.diplomacy.mission_levels[source.nation()][target],
        DiplomaticMissionLevel::None
    );
    assert!(
        state.pending.newspaper_events.iter().any(|event| matches!(
            event,
            PendingNewspaperEvent::InterNation {
                event: InterNationNewsKind::WarDeclaredBySubject,
                subject,
                ..
            } if *subject == source
        )),
        "{:?}",
        state.pending.newspaper_events
    );
    assert!(
        state.pending.newspaper_events.iter().any(|event| matches!(
            event,
            PendingNewspaperEvent::InterNation {
                event: InterNationNewsKind::WarDeclaredAgainstSubject,
                subject,
                ..
            } if *subject == major(1)
        )),
        "{:?}",
        state.pending.newspaper_events
    );
}

#[test]
fn accepted_join_empire_makes_the_subject_a_colony() {
    let mut state = game_state();
    let source = major(0);
    let target = nation(7);
    state.nations.minors[MinorNationId::new(7)] = Some(independent_minor(7));
    state.diplomacy.standings[target][source.nation()] = 0xff;
    state.diplomacy.standings[source.nation()][target] = 0xff;
    state.nations.majors[source]
        .as_mut()
        .unwrap()
        .economy
        .diplomacy_policy_by_nation[target] = Some(DiplomacyPolicy::JoinEmpire);

    assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);

    assert_eq!(
        state.nations.minors[MinorNationId::new(7)]
            .as_ref()
            .unwrap()
            .common
            .status(),
        CountryStatus::ColonyOf(source.nation())
    );
    assert_eq!(
        state.diplomacy.relationships[target][source.nation()],
        DiplomaticRelationship::JoinedEmpire
    );
    assert_eq!(
        state.nations.majors[source]
            .as_mut()
            .unwrap()
            .economy
            .pending_actions[PendingActionKind::ColonyMonumentMerchantCapacity]
            .status(),
        PendingActionStatus::QUEUED
    );
    assert!(
        state.pending.newspaper_events.iter().any(|event| matches!(
            event,
            PendingNewspaperEvent::InterNation {
                event: InterNationNewsKind::NationJoinedEmpire,
                subject,
                ..
            } if *subject == source
        )),
        "{:?}",
        state.pending.newspaper_events
    );
}

#[test]
fn accepted_great_power_join_empire_is_a_colony_not_a_protectorate() {
    let mut state = game_state();
    state.nations.majors[major(1)] = Some(computer_major());
    state.nations.majors[major(1)]
        .as_mut()
        .unwrap()
        .economy
        .diplomacy_policy_by_nation[nation(0)] = Some(DiplomacyPolicy::JoinEmpire);

    let prompt = match state.do_diplomacy() {
        DiplomacyPhaseResult::Offer(prompt) => prompt,
        other => panic!("expected an offer prompt, got {other:?}"),
    };
    assert_eq!(prompt.policy, DiplomacyPolicy::JoinEmpire);
    assert_eq!(
        state.resolve_diplomacy_offer(true),
        DiplomacyPhaseResult::Resolved
    );
    assert_eq!(
        state.nations.majors[major(0)]
            .as_mut()
            .unwrap()
            .common
            .status(),
        CountryStatus::ColonyOf(nation(1))
    );
    assert_eq!(
        state.diplomacy.relationships[nation(0)][nation(1)],
        DiplomaticRelationship::JoinedEmpire
    );
    assert_eq!(
        state.nations.majors[major(1)]
            .as_mut()
            .unwrap()
            .economy
            .pending_actions[PendingActionKind::AnnexedGreatPowerCapitalExpansion]
            .status(),
        PendingActionStatus::QUEUED
    );
    assert_eq!(
        state
            .nations
            .live_majors()
            .filter(|(_, major)| major.common.status() == CountryStatus::Independent)
            .count(),
        6
    );
}

#[test]
fn war_penalty_adjusts_independent_third_parties() {
    let mut state = game_state();
    state.diplomacy.standings[nation(0)][nation(1)] = 0x5a;
    state.diplomacy.standings[nation(1)][nation(0)] = 0x5a;
    state.diplomacy.standings[nation(1)][nation(2)] = 0x20;
    state.diplomacy.standings[nation(2)][nation(1)] = 0x20;
    let before = state.diplomacy.standings[nation(0)][nation(2)];
    state.nations.majors[major(0)]
        .as_mut()
        .unwrap()
        .economy
        .diplomacy_policy_by_nation[nation(1)] = Some(DiplomacyPolicy::DeclareWar);

    assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);
    assert_ne!(state.diplomacy.standings[nation(0)][nation(2)], before);
}

#[test]
fn declaring_war_on_an_independent_minor_stops_for_the_favorite_human() {
    let mut state = game_state();
    state.nations.majors[major(1)] = Some(computer_major());
    state.nations.minors[MinorNationId::new(7)] = Some(independent_minor(7));
    state.diplomacy.mission_levels[nation(0)][nation(7)] = DiplomaticMissionLevel::Embassy;
    state.diplomacy.mission_levels[nation(7)][nation(0)] = DiplomaticMissionLevel::Embassy;
    state.diplomacy.standings[nation(7)][nation(0)] = 0xff;
    state.diplomacy.standings[nation(0)][nation(7)] = 0xff;
    state.nations.majors[major(1)]
        .as_mut()
        .unwrap()
        .economy
        .diplomacy_policy_by_nation[nation(7)] = Some(DiplomacyPolicy::DeclareWar);

    let prompt = match state.do_diplomacy() {
        DiplomacyPhaseResult::WarJoin(prompt) => prompt,
        other => panic!("expected a war-join prompt, got {other:?}"),
    };
    assert_eq!(prompt.kind, DiplomacyWarJoinKind::DefendMinor);
    assert_eq!(prompt.nation, major(0));
    assert_eq!(prompt.target, nation(7));
    assert_eq!(prompt.source, nation(1));

    assert_eq!(
        state.resolve_diplomacy_war_join(true),
        DiplomacyPhaseResult::Resolved
    );
    assert_eq!(
        state.nations.minors[MinorNationId::new(7)]
            .as_ref()
            .unwrap()
            .common
            .status(),
        CountryStatus::ColonyOf(nation(0))
    );
    assert_eq!(
        state.diplomacy.relationships[nation(0)][nation(1)],
        DiplomaticRelationship::War
    );
}

#[test]
fn ai_posts_a_non_aggression_pact_to_a_peaceful_embassy_minor() {
    let mut state = game_state();
    state.nations.majors[major(1)] = Some(computer_major());
    state.nations.minors[MinorNationId::new(7)] = Some(independent_minor(7));
    state.diplomacy.mission_levels[nation(1)][nation(7)] = DiplomaticMissionLevel::Embassy;
    state.diplomacy.mission_levels[nation(7)][nation(1)] = DiplomaticMissionLevel::Embassy;
    state.diplomacy.relationships[nation(1)][nation(7)] = DiplomaticRelationship::Peace;

    assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);
    assert_eq!(
        state.diplomacy.relationships[nation(1)][nation(7)],
        DiplomaticRelationship::NonAggressionPact
    );
}

fn empty_zone(neighbors: Vec<OceanZoneId>) -> Zone {
    Zone {
        display_name: String::new(),
        status_code: None,
        target_tile: None,
        seed_owner: None,
        active_tile: None,
        primary_neighbors: neighbors,
        secondary_neighbors: Vec::new(),
    }
}

fn province(owner: NationId, adjacency: &[u16], linked: &[u16]) -> ProvinceState {
    ProvinceState::new(
        Some(owner),
        Some(owner),
        0,
        adjacency.iter().copied().map(ProvinceId::new).collect(),
        vec![TileId::new(0); adjacency.len()],
        None,
        0,
        None,
        0,
        None,
        None,
        linked.iter().copied().map(TileId::new).collect(),
        ResourceTable::default(),
        MajorNationTable::default(),
        0,
        false,
        0,
        String::new(),
    )
}

#[test]
fn colony_annex_clears_boycotted_companies_and_deports_civilians() {
    let mut state = game_state();
    let source = major(0);
    let target = nation(7);
    let mut minor = independent_minor(7);
    minor.add_province(ProvinceId::new(0));
    state.nations.minors[MinorNationId::new(7)] = Some(minor);
    state.map.provinces[ProvinceId::new(0)] = province(target, &[], &[20]);
    state.map[TileId::new(20)].secondary_owner_nation = Some(major(1));
    state.nations.majors[source]
        .as_mut()
        .unwrap()
        .economy
        .colony_boycott_flags[nation(1)] = 1;
    state.civilian_units.insert(
        CivilianUnitId::new(1),
        CivilianUnitState::new(
            nation(1),
            CivilianUnitKind::Miner,
            CivilianLocation::OnMap(TileId::new(20)),
            CivilianWorkOrder::Idle,
            nation(1),
            0,
            false,
        )
        .unwrap(),
    );
    state.diplomacy.standings[target][source.nation()] = 0xff;
    state.diplomacy.standings[source.nation()][target] = 0xff;
    state.nations.majors[source]
        .as_mut()
        .unwrap()
        .economy
        .diplomacy_policy_by_nation[target] = Some(DiplomacyPolicy::JoinEmpire);

    assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);

    assert_eq!(state.map[TileId::new(20)].secondary_owner_nation, None);
    assert_eq!(state.civilian_units.len(), 1);
    assert_eq!(
        state.civilian_units[0].location.tile(),
        state.nations.majors[major(1)]
            .as_mut()
            .unwrap()
            .common
            .home_tile
    );
    assert!(
        state.pending.nations[major(1)]
            .turn_events
            .iter()
            .any(|notice| notice.source == target && notice.code == 0x137),
        "{:?}",
        state.pending.nations[major(1)].turn_events
    );
    assert!(
        state.pending.newspaper_events.iter().any(|event| matches!(
            event,
            PendingNewspaperEvent::InterNation {
                event: InterNationNewsKind::MinorTerritoryRelationshipAffected,
                subject,
                ..
            } if *subject == major(1)
        )),
        "{:?}",
        state.pending.newspaper_events
    );
}

#[test]
fn declaring_war_marks_the_target_first_port_zone_as_a_candidate() {
    let mut state = game_state();
    state.nations.majors[major(1)] = Some(computer_major());
    state.nations.majors[major(1)]
        .as_mut()
        .unwrap()
        .auto
        .as_mut()
        .unwrap()
        .zone_targets = vec![AiTargetState::Unmarked; 2];
    let mut minor = independent_minor(7);
    minor.add_province(ProvinceId::new(0));
    state.nations.minors[MinorNationId::new(7)] = Some(minor);
    state.map[TileId::new(30)].former_owner_nation = Some(TileOwnerTag::from_nation(nation(7)));
    state.ocean.zones = vec![
        ZoneKind::Zone(empty_zone(Vec::new())),
        ZoneKind::PortZone(PortZone {
            zone: empty_zone(vec![OceanZoneId::new(0)]),
            port_tile: TileId::new(30),
        }),
    ];
    state.nations.majors[major(1)]
        .as_mut()
        .unwrap()
        .economy
        .diplomacy_policy_by_nation[nation(7)] = Some(DiplomacyPolicy::DeclareWar);

    assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);
    assert_eq!(
        state.nations.majors[major(1)]
            .as_mut()
            .unwrap()
            .auto
            .as_ref()
            .map(|auto| &auto.zone_targets),
        Some(&vec![AiTargetState::Unmarked, AiTargetState::Candidate])
    );
    assert_eq!(
        state.nations.majors[major(1)]
            .as_mut()
            .unwrap()
            .economy
            .candidate_nation_flags[nation(7)],
        1
    );
}

fn peace_offer_from_human_to_ai() -> GameState {
    let mut state = game_state();
    state.nations.majors[major(1)] = Some(computer_major());
    state.diplomacy.relationships[nation(0)][nation(1)] = DiplomaticRelationship::War;
    state.diplomacy.relationships[nation(1)][nation(0)] = DiplomaticRelationship::War;
    state.ships.extend((0..10).map(|index| {
        (
            ShipId::new(index),
            ShipState {
                ship_type: ShipType::Frigate,
                location: OceanZoneId::new(0),
                aggression: 0,
                nation: nation(1),
                name: String::new(),
                strength: 900,
                experience: 0,
                selection: 0,
            },
        )
    }));
    state.nations.majors[major(0)]
        .as_mut()
        .unwrap()
        .economy
        .diplomacy_policy_by_nation[nation(1)] = Some(DiplomacyPolicy::PeaceTreaty);
    state
}

#[test]
fn ai_accepts_peace_when_the_enemy_capitol_is_safe() {
    let mut state = peace_offer_from_human_to_ai();
    assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);
    assert_eq!(
        state.diplomacy.relationships[nation(1)][nation(0)],
        DiplomaticRelationship::Peace
    );
}

#[test]
fn ai_rejects_peace_when_the_enemy_capitol_is_threatened() {
    let mut state = peace_offer_from_human_to_ai();
    state.nations.majors[major(0)]
        .as_mut()
        .unwrap()
        .common
        .home_tile = Some(TileId::new(1));
    state.map[TileId::new(1)].province = Some(ProvinceId::new(0));
    state.map.provinces[ProvinceId::new(0)] = province(nation(0), &[1], &[]);
    state.map.provinces[ProvinceId::new(1)] = province(nation(2), &[0], &[]);
    state.diplomacy.relationships[nation(0)][nation(2)] = DiplomaticRelationship::War;
    state.diplomacy.relationships[nation(2)][nation(0)] = DiplomaticRelationship::War;
    state.military_units.insert(
        MilitaryUnitId::new(1),
        MilitaryUnitState::new(
            nation(2),
            MilitaryUnitKind::Regulars,
            Some(ProvinceId::new(1)),
            MilitaryOrder::idle([None; 3], [None; 3]),
            nation(2),
            0,
            false,
            String::new(),
            500,
            0,
            0,
            0,
        ),
    );

    assert_eq!(state.do_diplomacy(), DiplomacyPhaseResult::Resolved);
    assert_eq!(
        state.diplomacy.relationships[nation(1)][nation(0)],
        DiplomaticRelationship::War
    );
}
