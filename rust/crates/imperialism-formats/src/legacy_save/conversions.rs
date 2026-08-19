use imperialism_core::*;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyEncodeError {
    pub value: i32,
}

impl std::fmt::Display for LegacyEncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "value {} cannot be represented in a v62 retail save field",
            self.value
        )
    }
}

impl std::error::Error for LegacyEncodeError {}

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

pub(super) fn option_i16(value: Option<usize>) -> Result<i16, LegacyEncodeError> {
    match value {
        Some(value) => r16(i32::try_from(value).map_err(|_| LegacyEncodeError {
            value: value as i32,
        })?),
        None => Ok(-1),
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

pub(super) fn r16(value: i32) -> Result<i16, LegacyEncodeError> {
    i16::try_from(value).map_err(|_| LegacyEncodeError { value })
}

pub(super) fn usize_i16(value: usize) -> Result<i16, LegacyEncodeError> {
    r16(i32::try_from(value).map_err(|_| LegacyEncodeError { value: i32::MAX })?)
}

pub(super) fn r8(value: i32) -> Result<i8, LegacyEncodeError> {
    i8::try_from(value).map_err(|_| LegacyEncodeError { value })
}

pub(super) fn r16s<const N: usize>(values: [i32; N]) -> Result<[i16; N], LegacyEncodeError> {
    let mut encoded = [0; N];
    for (slot, value) in encoded.iter_mut().zip(values) {
        *slot = r16(value)?;
    }
    Ok(encoded)
}

pub(super) fn labor(values: [i16; 3]) -> LaborPool {
    LaborPool::new(n(values[0]), n(values[1]), n(values[2]))
}

pub(super) fn labor_i16(pool: LaborPool) -> Result<[i16; 3], LegacyEncodeError> {
    Ok([r16(pool.low)?, r16(pool.medium)?, r16(pool.high)?])
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

pub(super) fn pending_actions_from_retail(
    status: [i8; PENDING_ACTION_COUNT],
    payload: [i16; PENDING_ACTION_COUNT],
) -> PendingActions {
    PendingActions {
        navy_growth: growth_from_retail(status[0], payload[0]),
        army_growth: growth_from_retail(status[1], payload[1]),
        overseas_developer: flag_from_retail(status[2]),
        village_development: settlement_from_retail(status[3], payload[3]),
        town_development: settlement_from_retail(status[4], payload[4]),
        shipyard_ironworking: flag_from_retail(status[5]),
        conquered_capital_armory: flag_from_retail(status[6]),
        university_expansion: university_from_retail(status[7], payload[7]),
        railyard_expansion: flag_from_retail(status[8]),
        annexed_capital: nation_pending_from_retail(status[9], payload[9]),
        colony_monument: nation_pending_from_retail(status[10], payload[10]),
        council_lead_monument: flag_from_retail(status[11]),
        conquest_monument_armory: flag_from_retail(status[12]),
    }
}

pub(super) fn pending_actions_to_retail(
    actions: &PendingActions,
) -> Result<([i8; PENDING_ACTION_COUNT], [i16; PENDING_ACTION_COUNT]), LegacyEncodeError> {
    let mut status = [0_i8; PENDING_ACTION_COUNT];
    let mut payload = [-1_i16; PENDING_ACTION_COUNT];
    encode_growth(&mut status[0], &mut payload[0], actions.navy_growth)?;
    encode_growth(&mut status[1], &mut payload[1], actions.army_growth)?;
    encode_flag(&mut status[2], actions.overseas_developer);
    encode_settlement(&mut status[3], &mut payload[3], actions.village_development)?;
    encode_settlement(&mut status[4], &mut payload[4], actions.town_development)?;
    encode_flag(&mut status[5], actions.shipyard_ironworking);
    encode_flag(&mut status[6], actions.conquered_capital_armory);
    encode_university(
        &mut status[7],
        &mut payload[7],
        actions.university_expansion,
    )?;
    encode_flag(&mut status[8], actions.railyard_expansion);
    encode_nation_pending(&mut status[9], &mut payload[9], actions.annexed_capital);
    encode_nation_pending(&mut status[10], &mut payload[10], actions.colony_monument);
    encode_flag(&mut status[11], actions.council_lead_monument);
    encode_flag(&mut status[12], actions.conquest_monument_armory);
    Ok((status, payload))
}

fn growth_from_retail(status: i8, payload: i16) -> GrowthReward {
    match status {
        0 => GrowthReward::Idle,
        0x32 => GrowthReward::Queued {
            level: (payload != -1).then_some(i32::from(payload)),
        },
        0x33..=0x39 => GrowthReward::Granted {
            level: i32::from(status) - 0x33,
        },
        _ => GrowthReward::Idle,
    }
}

fn encode_growth(
    status: &mut i8,
    payload: &mut i16,
    value: GrowthReward,
) -> Result<(), LegacyEncodeError> {
    match value {
        GrowthReward::Idle => {}
        GrowthReward::Queued { level: None } => *status = 0x32,
        GrowthReward::Queued { level: Some(level) } => {
            *status = 0x32;
            *payload = r16(level)?;
        }
        GrowthReward::Granted { level } => {
            *status = i8::try_from(0x33 + level).map_err(|_| LegacyEncodeError {
                value: 0x33 + level,
            })?;
            *payload = r16(level)?;
        }
    }
    Ok(())
}

fn flag_from_retail(status: i8) -> FlagPending {
    match status {
        0x32 => FlagPending::Queued,
        value if value >= 0x33 => FlagPending::Handled,
        _ => FlagPending::Idle,
    }
}

fn encode_flag(status: &mut i8, value: FlagPending) {
    *status = match value {
        FlagPending::Idle => 0,
        FlagPending::Queued => 0x32,
        FlagPending::Handled => 0x33,
    };
}

fn settlement_from_retail(status: i8, payload: i16) -> SettlementPending {
    if status == 0x32 && payload >= 0 {
        SettlementPending::Queued {
            province: ProvinceId::new(payload as usize),
        }
    } else {
        SettlementPending::Idle
    }
}

fn encode_settlement(
    status: &mut i8,
    payload: &mut i16,
    value: SettlementPending,
) -> Result<(), LegacyEncodeError> {
    if let SettlementPending::Queued { province } = value {
        *status = 0x32;
        *payload = r16(province.get() as i32)?;
    }
    Ok(())
}

fn university_from_retail(status: i8, payload: i16) -> UniversityExpansion {
    match status {
        0x32 => UniversityExpansion::Queued {
            stage: i32::from(payload),
        },
        0x33 => UniversityExpansion::Level2,
        value if value >= 0x34 => UniversityExpansion::Level3,
        _ => UniversityExpansion::Idle,
    }
}

fn encode_university(
    status: &mut i8,
    payload: &mut i16,
    value: UniversityExpansion,
) -> Result<(), LegacyEncodeError> {
    match value {
        UniversityExpansion::Idle => {}
        UniversityExpansion::Queued { stage } => {
            *status = 0x32;
            *payload = r16(stage)?;
        }
        UniversityExpansion::Level2 => *status = 0x33,
        UniversityExpansion::Level3 => *status = 0x34,
    }
    Ok(())
}

fn nation_pending_from_retail(status: i8, payload: i16) -> NationPending {
    match status {
        0x32 => NationPending::Queued {
            nation: NationId::from_retail_slot(payload as u8).expect("pending nation slot"),
        },
        value if value >= 0x33 => NationPending::Handled,
        _ => NationPending::Idle,
    }
}

fn encode_nation_pending(status: &mut i8, payload: &mut i16, value: NationPending) {
    match value {
        NationPending::Idle => {}
        NationPending::Queued { nation } => {
            *status = 0x32;
            *payload = i16::from(nation.retail_slot());
        }
        NationPending::Handled => *status = 0x33,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r16_rejects_values_outside_i16() {
        assert_eq!(r16(i32::from(i16::MAX)).unwrap(), i16::MAX);
        assert_eq!(
            r16(i32::from(i16::MAX) + 1),
            Err(LegacyEncodeError { value: 32_768 })
        );
        assert_eq!(r16(i32::from(i16::MIN)).unwrap(), i16::MIN);
        assert_eq!(
            r16(i32::from(i16::MIN) - 1),
            Err(LegacyEncodeError { value: -32_769 })
        );
    }
}
