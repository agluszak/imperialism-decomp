use imperialism_core::*;

pub(super) fn optional_u8(value: i8) -> Option<u8> {
    (value != -1).then_some(value as u8)
}

pub(super) fn optional_u16(value: i16) -> Option<u16> {
    (value != -1).then_some(value as u16)
}

pub(super) fn optional_u16_from_i32(value: i32) -> Option<u16> {
    (value != -1).then_some(value as u16)
}

pub(super) fn option_i8(value: Option<u8>) -> i8 {
    value.map(|value| value as i8).unwrap_or(-1)
}

pub(super) fn option_i16(value: Option<usize>) -> i16 {
    match value {
        Some(value) => i16::try_from(value).expect("optional index fits retail i16"),
        None => -1,
    }
}

pub(super) fn option_i32(value: Option<usize>) -> i32 {
    value.map(|value| value as i32).unwrap_or(-1)
}

pub(super) fn n(value: i16) -> i32 {
    i32::from(value)
}

pub(super) fn ns<const N: usize>(values: [i16; N]) -> [i32; N] {
    values.map(i32::from)
}

pub(super) fn r16(value: i32) -> i16 {
    i16::try_from(value).expect("value fits retail i16")
}

pub(super) fn r16s<const N: usize>(values: [i32; N]) -> [i16; N] {
    values.map(r16)
}

pub(super) fn labor(values: [i16; 3]) -> LaborPool {
    LaborPool::new(n(values[0]), n(values[1]), n(values[2]))
}

pub(super) fn labor_i16(pool: LaborPool) -> [i16; 3] {
    [r16(pool.low), r16(pool.medium), r16(pool.high)]
}

pub(super) fn production_constraint_from_retail(value: i16) -> ProductionConstraint {
    match value {
        0 => ProductionConstraint::Resources,
        1 => ProductionConstraint::Workforce,
        2 => ProductionConstraint::Capacity,
        3 => ProductionConstraint::Treasury,
        _ => panic!("unrecovered city production constraint {value}"),
    }
}

pub(super) fn production_constraint_to_retail(constraint: ProductionConstraint) -> i16 {
    match constraint {
        ProductionConstraint::Resources => 0,
        ProductionConstraint::Workforce => 1,
        ProductionConstraint::Capacity => 2,
        ProductionConstraint::Treasury => 3,
    }
}

pub(super) fn ai_target_from_retail(value: u8) -> AiTargetState {
    match value {
        0 => AiTargetState::Unmarked,
        1 => AiTargetState::Candidate,
        2 => AiTargetState::MissionQueued,
        _ => panic!("unrecovered AI target state {value}"),
    }
}

pub(super) fn ai_target_to_retail(target: AiTargetState) -> u8 {
    match target {
        AiTargetState::Unmarked => 0,
        AiTargetState::Candidate => 1,
        AiTargetState::MissionQueued => 2,
    }
}

pub(super) fn technology_research_status_from_retail(value: u8) -> TechnologyResearchStatus {
    match value {
        0 => TechnologyResearchStatus::NotStarted,
        1 => TechnologyResearchStatus::Pending,
        2 => TechnologyResearchStatus::Researched,
        _ => panic!("unrecovered technology research status {value}"),
    }
}

pub(super) fn technology_research_status_to_retail(status: TechnologyResearchStatus) -> u8 {
    match status {
        TechnologyResearchStatus::NotStarted => 0,
        TechnologyResearchStatus::Pending => 1,
        TechnologyResearchStatus::Researched => 2,
    }
}

pub(super) fn deal_book_entry_kind_from_retail(value: i16) -> DealBookEntryKind {
    match value {
        0 => DealBookEntryKind::Accept,
        1 => DealBookEntryKind::Offer,
        _ => panic!("unrecovered deal-book entry kind {value}"),
    }
}

pub(super) fn deal_book_entry_kind_to_retail(kind: DealBookEntryKind) -> i16 {
    match kind {
        DealBookEntryKind::Accept => 0,
        DealBookEntryKind::Offer => 1,
    }
}

/// Setup-policy id 0 is `Arms` for an Auto great power and `Base` otherwise.
pub(super) fn foreign_minister_personality_from_retail(
    is_auto: bool,
    setup_policy_id: i16,
) -> ForeignMinisterPersonality {
    if !is_auto {
        return ForeignMinisterPersonality::Base;
    }
    match setup_policy_id {
        0 => ForeignMinisterPersonality::Arms,
        1 => ForeignMinisterPersonality::Trader,
        2 => ForeignMinisterPersonality::Textile,
        3 => ForeignMinisterPersonality::Diplomat,
        4 => ForeignMinisterPersonality::Bill,
        5 => ForeignMinisterPersonality::Ted,
        _ => panic!("unrecovered AI foreign-minister setup policy {setup_policy_id}"),
    }
}

pub(super) fn foreign_minister_personality_to_retail(
    personality: ForeignMinisterPersonality,
) -> i16 {
    match personality {
        ForeignMinisterPersonality::Base | ForeignMinisterPersonality::Arms => 0,
        ForeignMinisterPersonality::Trader => 1,
        ForeignMinisterPersonality::Textile => 2,
        ForeignMinisterPersonality::Diplomat => 3,
        ForeignMinisterPersonality::Bill => 4,
        ForeignMinisterPersonality::Ted => 5,
    }
}

pub(super) fn country_status_from_retail(value: i16) -> CountryStatus {
    match value {
        -1 => CountryStatus::Independent,
        100..=122 => CountryStatus::ProtectorateOf(
            NationId::from_retail_slot((value - 100) as u8).expect("encoded protectorate nation"),
        ),
        200..=222 => CountryStatus::ColonyOf(
            NationId::from_retail_slot((value - 200) as u8).expect("encoded colony nation"),
        ),
        _ => panic!("unrecovered encoded nation status {value}"),
    }
}

pub(super) fn country_status_to_retail(status: CountryStatus) -> i16 {
    match status {
        CountryStatus::Independent => -1,
        CountryStatus::ProtectorateOf(nation) => 100 + i16::from(nation.retail_slot()),
        CountryStatus::ColonyOf(nation) => 200 + i16::from(nation.retail_slot()),
    }
}
