use super::*;
use imperialism_core::*;

fn nation_pair_table<T: Copy>(
    values: [T; NATION_COUNT * NATION_COUNT],
) -> NationTable<NationTable<T>> {
    NationTable::from_array(std::array::from_fn(|source| {
        NationTable::from_array(std::array::from_fn(|target| {
            values[source * NATION_COUNT + target]
        }))
    }))
}

fn optional_major_nation_from_i16(value: i16) -> Option<MajorNationId> {
    (value != -1).then(|| MajorNationId::new(value as u8))
}

pub(super) fn diplomacy_state(diplomacy: &LegacyDiplomacyState) -> DiplomacyState {
    DiplomacyState {
        standings: nation_pair_table(diplomacy.relation_standing_scores),
        relationships: nation_pair_table(diplomacy.relation_propagation_matrix.map(|value| {
            DiplomaticRelationship::try_from_retail(value).expect("retail diplomatic relationship")
        })),
        relationship_turns: nation_pair_table(
            diplomacy
                .relation_turn_stamp_matrix
                .map(|value| (value != -1).then_some(value)),
        ),
        influence_thresholds: ProvinceTable::from_array(diplomacy.relation_code_matrix),
        influence_sides: ProvinceTable::from_array(
            diplomacy
                .pending_policy_code_matrix
                .map(optional_major_nation_id),
        ),
        last_diplomatic_effort_turn: diplomacy.last_diplomatic_effort_turn,
        mission_levels: nation_pair_table(diplomacy.relation_side_effect_matrix.map(|value| {
            DiplomaticMissionLevel::try_from_retail(value).expect("retail diplomatic mission level")
        })),
        congress: DiplomaticCongressState {
            chairman: optional_major_nation_from_i16(diplomacy.congress_leadership[0]),
            counterpart: optional_major_nation_from_i16(diplomacy.congress_leadership[1]),
            chairman_support: diplomacy.congress_support[0],
            counterpart_support: diplomacy.congress_support[1],
            neutral_support: diplomacy.congress_support[2],
        },
        special_relation_sources: MinorNationTable::from_array(
            diplomacy
                .special_relation_source_slots
                .map(optional_major_nation_from_i16),
        ),
        special_relation_targets: MinorNationTable::from_array(
            diplomacy
                .special_relation_target_slots
                .map(optional_major_nation_from_i16),
        ),
        // The retail constructor restores both values before ReadFrom consumes the payload.
        last_processed_nation: None,
        proposal_mode_raw: 0,
    }
}

pub(super) fn diplomacy_dto(diplomacy: &DiplomacyState) -> LegacyDiplomacyState {
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

pub(super) fn diplomacy_notices(list: &LegacyFixedRecordList) -> Vec<DiplomacyNotice> {
    relationship_records(list)
        .into_iter()
        .map(|(code, source)| DiplomacyNotice { source, code })
        .collect()
}

pub(super) fn diplomacy_proposals(list: &LegacyFixedRecordList) -> Vec<DiplomacyProposal> {
    relationship_records(list)
        .into_iter()
        .map(|(entry, source)| DiplomacyProposal {
            source,
            policy: diplomacy_policy_from_retail(entry),
        })
        .collect()
}

fn relationship_records(list: &LegacyFixedRecordList) -> Vec<(i16, NationId)> {
    let mut records = list
        .records
        .iter()
        .map(|record| {
            let value = i16::from_le_bytes([record[0], record[1]]);
            let source = nation_id_from_retail_i16(i16::from_le_bytes([record[2], record[3]]));
            (value, source)
        })
        .collect::<Vec<_>>();
    records.sort_by_key(|(_, source)| *source);
    records
}

pub(super) fn diplomacy_grants_from_retail_entries(
    entries: [i16; NATION_COUNT],
) -> NationTable<Option<DiplomacyGrant>> {
    NationTable::from_array(entries.map(|entry| {
        if entry == -1 {
            None
        } else {
            Some(DiplomacyGrant {
                amount: i32::from(entry & 0x3fff),
                recurring: entry & 0x4000 != 0,
            })
        }
    }))
}

pub(super) fn diplomacy_policies_from_retail_entries(
    entries: [i16; NATION_COUNT],
) -> NationTable<Option<DiplomacyPolicy>> {
    NationTable::from_array(entries.map(|entry| match entry {
        -1 => None,
        _ => Some(diplomacy_policy_from_retail(entry)),
    }))
}

fn diplomacy_policy_from_retail(entry: i16) -> DiplomacyPolicy {
    match entry {
        0x12d => DiplomacyPolicy::JoinEmpire,
        0x12e => DiplomacyPolicy::Alliance,
        0x12f => DiplomacyPolicy::NonAggressionPact,
        0x130 => DiplomacyPolicy::PeaceTreaty,
        0x131 => DiplomacyPolicy::DeclareWar,
        0x132 => DiplomacyPolicy::JoinEmpireWithWarEntanglements,
        0x133 => DiplomacyPolicy::BuildConsulate,
        0x134 => DiplomacyPolicy::BuildEmbassy,
        _ => panic!("unrecovered diplomacy policy {entry:#06x}"),
    }
}

pub(super) fn grant_to_retail(grant: DiplomacyGrant) -> i16 {
    let amount = (grant.amount as i16) & 0x3fff;
    if grant.recurring {
        amount | 0x4000
    } else {
        amount
    }
}

pub(super) fn notices_to_records(notices: &[DiplomacyNotice]) -> LegacyFixedRecordList {
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

pub(super) fn proposals_to_records(proposals: &[DiplomacyProposal]) -> LegacyFixedRecordList {
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

pub(super) fn deal_book_state(
    lists: &[LegacyFixedRecordList; TRADE_CATEGORY_COUNT],
) -> TradeCommodityTable<Vec<TradeDealBookEntry>> {
    TradeCommodityTable::from_array(lists.each_ref().map(deal_book_entries))
}

fn deal_book_entries(list: &LegacyFixedRecordList) -> Vec<TradeDealBookEntry> {
    let mut entries = list
        .records
        .iter()
        .map(|record| {
            let kind = match i16::from_le_bytes([record[0], record[1]]) {
                0 => DealBookEntryKind::Accept,
                1 => DealBookEntryKind::Offer,
                value => panic!("unrecovered deal-book entry kind {value}"),
            };
            let nation_raw = i16::from_le_bytes([record[2], record[3]]);
            let nation = nation_id_from_retail_i16(nation_raw);
            let amount = i16::from_le_bytes([record[4], record[5]]);
            TradeDealBookEntry {
                kind,
                nation,
                amount,
                unit_price: i32::from_le_bytes([record[8], record[9], record[10], record[11]]),
            }
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.nation);
    entries
}

pub(super) fn deal_book_records(entries: &[TradeDealBookEntry]) -> LegacyFixedRecordList {
    let mut records = entries
        .iter()
        .map(|entry| {
            let mut record = vec![0_u8; 12];
            let kind = match entry.kind {
                DealBookEntryKind::Accept => 0_i16,
                DealBookEntryKind::Offer => 1_i16,
            };
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
