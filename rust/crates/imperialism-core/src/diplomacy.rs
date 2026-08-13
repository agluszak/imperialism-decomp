use crate::*;
use serde::{Deserialize, Serialize};

/// The authoritative bilateral relationship stored by retail diplomacy state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiplomaticRelationship {
    Alliance,
    NonAggressionPact,
    Peace,
    JoinedEmpire,
    War,
}

impl DiplomaticRelationship {
    pub const fn try_from_retail(value: i16) -> Option<Self> {
        match value {
            2 => Some(Self::Alliance),
            3 => Some(Self::NonAggressionPact),
            4 => Some(Self::Peace),
            5 => Some(Self::JoinedEmpire),
            6 => Some(Self::War),
            _ => None,
        }
    }

    pub const fn retail(self) -> i16 {
        match self {
            Self::Alliance => 2,
            Self::NonAggressionPact => 3,
            Self::Peace => 4,
            Self::JoinedEmpire => 5,
            Self::War => 6,
        }
    }
}

/// The bilateral diplomatic mission level stored by retail diplomacy state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiplomaticMissionLevel {
    None,
    TradeConsulate,
    Embassy,
}

impl DiplomaticMissionLevel {
    pub const fn try_from_retail(value: i16) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::TradeConsulate),
            2 => Some(Self::Embassy),
            _ => None,
        }
    }

    pub const fn retail(self) -> i16 {
        match self {
            Self::None => 0,
            Self::TradeConsulate => 1,
            Self::Embassy => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiplomaticCongressState {
    pub chairman: Option<MajorNationId>,
    pub counterpart: Option<MajorNationId>,
    pub chairman_support: i16,
    pub counterpart_support: i16,
    pub neutral_support: i16,
}

/// Persistent `TDiplomacyMgr` state plus its two constructor-restored runtime values.
///
/// Retail deliberately does not persist the pending-policy tier matrix, relation baseline copy,
/// or comparative-power rows. At the beginning-save/phase-6 boundary, the tier and power rows are
/// rebuilt before their later consumers, while the baseline belongs to multiplayer delta sync.
/// They must be represented when a modeled checkpoint can stop between those writes and reads;
/// the v62 payload alone cannot reconstruct them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiplomacyState {
    pub standings: NationTable<NationTable<i16>>,
    pub relationships: NationTable<NationTable<DiplomaticRelationship>>,
    pub relationship_turns: NationTable<NationTable<Option<i16>>>,
    pub influence_thresholds: ProvinceTable<i16>,
    pub influence_sides: ProvinceTable<Option<MajorNationId>>,
    pub last_diplomatic_effort_turn: i16,
    pub mission_levels: NationTable<NationTable<DiplomaticMissionLevel>>,
    pub congress: DiplomaticCongressState,
    pub special_relation_sources: MinorNationTable<Option<MajorNationId>>,
    pub special_relation_targets: MinorNationTable<Option<MajorNationId>>,
    pub last_processed_nation: Option<MajorNationId>,
    /// UI action-validation discriminator. Its meanings are recovered, but core rules do not
    /// interpret it yet, so the retail numeric domain remains visible.
    pub proposal_mode_raw: i16,
}

impl DiplomacyState {
    /// `InitializeTDiplomacyTurnStateManagerDefaults` followed by
    /// `RebuildCivilianOrderCompatibilityMatrices` for a complete random-game nation table.
    pub(crate) fn for_random_start(
        human_nation: MajorNationId,
        difficulty: Difficulty,
        rng: &mut RetailCrtRng,
    ) -> Self {
        let human = human_nation.nation();
        let mut standings = NationTable::from_fn(|source| {
            NationTable::from_fn(|target| {
                if source == target {
                    0xff
                } else if MinorNationId::from_nation(source).is_some()
                    && MinorNationId::from_nation(target).is_some()
                {
                    if (source.index() - MinorNationId::FIRST) / 4
                        == (target.index() - MinorNationId::FIRST) / 4
                    {
                        0x96
                    } else {
                        0x6e
                    }
                } else if MajorNationId::from_nation(source).is_some()
                    && source != human
                    && difficulty > Difficulty::Normal
                {
                    if difficulty == Difficulty::NighOnImpossible {
                        0x69
                    } else {
                        0x64
                    }
                } else {
                    0x5a
                }
            })
        });
        let mut mission_levels = NationTable::from_fn(|source| {
            NationTable::from_fn(|target| {
                if MajorNationId::from_nation(source).is_some()
                    && MajorNationId::from_nation(target).is_some()
                    && source != target
                {
                    DiplomaticMissionLevel::Embassy
                } else {
                    DiplomaticMissionLevel::None
                }
            })
        });

        if difficulty == Difficulty::Introductory {
            let first_minor = (rng.next_rand() as usize % 4) * 4 + MinorNationId::FIRST;
            for target in first_minor..first_minor + 4 {
                let target = NationId::new(target);
                let human = human_nation.nation();
                mission_levels[human][target] = DiplomaticMissionLevel::TradeConsulate;
                mission_levels[target][human] = DiplomaticMissionLevel::TradeConsulate;
                standings[human][target] = 0x6e;
                standings[target][human] = 0x6e;
            }
        }

        if difficulty > Difficulty::Normal {
            for source in MajorNationId::all() {
                if source == human_nation {
                    continue;
                }
                let target = NationId::new(
                    rng.next_rand() as usize % MinorNationId::COUNT + MinorNationId::FIRST,
                );
                let source = source.nation();
                mission_levels[source][target] = DiplomaticMissionLevel::TradeConsulate;
                mission_levels[target][source] = DiplomaticMissionLevel::TradeConsulate;
                standings[source][target] = 0x6e;
                standings[target][source] = 0x6e;
            }
        }

        if difficulty == Difficulty::NighOnImpossible {
            for source in MajorNationId::all() {
                if source == human_nation {
                    continue;
                }
                for target in MajorNationId::all() {
                    if target == human_nation {
                        continue;
                    }
                    let source = source.nation();
                    let target = target.nation();
                    standings[source][target] = 0x6e;
                    standings[target][source] = 0x6e;
                }
            }
        }

        Self {
            standings,
            relationships: NationTable::from_array(std::array::from_fn(|_| {
                NationTable::from_array([DiplomaticRelationship::Peace; crate::NATION_COUNT])
            })),
            relationship_turns: NationTable::default(),
            influence_thresholds: ProvinceTable::default(),
            influence_sides: ProvinceTable::default(),
            last_diplomatic_effort_turn: 0,
            mission_levels,
            congress: DiplomaticCongressState {
                chairman: None,
                counterpart: None,
                chairman_support: 0,
                counterpart_support: 0,
                neutral_support: 0,
            },
            special_relation_sources: MinorNationTable::default(),
            special_relation_targets: MinorNationTable::default(),
            last_processed_nation: None,
            proposal_mode_raw: 0,
        }
    }
}

/// A bilateral trade-preference score.
///
/// Retail recognizes several named steps, but save data can carry other
/// scores, so this is deliberately not a closed enum.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TradePolicyScore(i32);

impl TradePolicyScore {
    pub const NEUTRAL: Self = Self(100);
    pub const BOYCOTT: Self = Self(300);

    pub const fn new(score: i32) -> Self {
        Self(score)
    }

    pub const fn get(self) -> i32 {
        self.0
    }

    pub const fn retail(self) -> i32 {
        self.0
    }

    pub(crate) const fn decrement_step(self, treasury: i32) -> Self {
        match self.0 {
            100 => Self(95),
            95 => Self(90),
            90 => Self(75),
            75 if treasury > 10_000 => Self(50),
            _ => self,
        }
    }
}

impl Default for TradePolicyScore {
    fn default() -> Self {
        Self::NEUTRAL
    }
}

/// A current diplomatic grant to one nation.
///
/// `None` in the owning table means no grant. A present zero-valued grant is
/// retained because it still participates in retail diplomacy processing.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiplomacyGrant {
    pub amount: i32,
    pub recurring: bool,
}

/// A proposed diplomatic relationship with one nation.
///
/// The retail save stores these as numeric proposal codes. The core keeps the
/// relationship meaning; absent entries have no current policy.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiplomacyPolicy {
    JoinEmpire,
    Alliance,
    NonAggressionPact,
    PeaceTreaty,
    DeclareWar,
    JoinEmpireWithWarEntanglements,
    BuildConsulate,
    BuildEmbassy,
}

impl DiplomacyPolicy {
    pub const fn try_from_retail(value: i16) -> Option<Self> {
        match value {
            0x12d => Some(Self::JoinEmpire),
            0x12e => Some(Self::Alliance),
            0x12f => Some(Self::NonAggressionPact),
            0x130 => Some(Self::PeaceTreaty),
            0x131 => Some(Self::DeclareWar),
            0x132 => Some(Self::JoinEmpireWithWarEntanglements),
            0x133 => Some(Self::BuildConsulate),
            0x134 => Some(Self::BuildEmbassy),
            _ => None,
        }
    }

    pub const fn retail(self) -> i16 {
        match self {
            Self::JoinEmpire => 0x12d,
            Self::Alliance => 0x12e,
            Self::NonAggressionPact => 0x12f,
            Self::PeaceTreaty => 0x130,
            Self::DeclareWar => 0x131,
            Self::JoinEmpireWithWarEntanglements => 0x132,
            Self::BuildConsulate => 0x133,
            Self::BuildEmbassy => 0x134,
        }
    }
}

/// Outcome of one diplomacy-resolution pass.
///
/// Retail stops for a human offer dialog during replies, then later for a
/// war-join dialog while processing the first queued war transition.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DiplomacyPhaseResult {
    Resolved,
    Offer(DiplomacyOfferPrompt),
    WarJoin(DiplomacyWarJoinPrompt),
}

/// One human offer that retail would pose as a diplomacy-offer dialog.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiplomacyOfferPrompt {
    pub nation: MajorNationId,
    pub index: u8,
    pub source: NationId,
    pub policy: DiplomacyPolicy,
}

/// One human war-join dialog from `ProcessQueuedWarTransitions`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiplomacyWarJoinPrompt {
    pub nation: MajorNationId,
    pub target: NationId,
    pub source: NationId,
    pub kind: DiplomacyWarJoinKind,
    pub pair_first: NationId,
    pub pair_second: NationId,
    pub cursor: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiplomacyWarJoinKind {
    DefendMinor,
    AnnexMinor,
    JoinTargetAlly,
    JoinSourceAlly,
}

const PLAYER_DIPLOMACY_GRANT_AMOUNTS: [i32; 4] = [1_000, 3_000, 5_000, 10_000];
const PLAYER_TRADE_POLICY_SCORES: [TradePolicyScore; 7] = [
    TradePolicyScore::new(95),
    TradePolicyScore::new(90),
    TradePolicyScore::new(75),
    TradePolicyScore::new(50),
    TradePolicyScore::new(25),
    TradePolicyScore::new(0),
    TradePolicyScore::BOYCOTT,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlayerDiplomacyOrderResult {
    Applied,
    SelectedNation,
    Rejected(PlayerDiplomacyRejection),
    NeedsEntanglementConfirmation,
}

/// Retail `proposalArrayMode` values written by
/// `ValidateDiplomacyActionTypeAgainstTargetAndSetRejectCode` and the grant-funds
/// failure path, then shown through string group `0x2754` at index `mode - 1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PlayerDiplomacyRejection {
    EmbassyRequired,
    AlreadyAtWar,
    AllianceRequiresGreatPower,
    PeaceRequiresOngoingWar,
    AlreadyDeclaringWar,
    TradeConsulateRequired,
    AlliedNationCannotBeBoycotted,
    ConsulateAlreadyPresent,
    EmbassyRequiresConsulate,
    EmbassyAlreadyPresent,
    TargetIsColony,
    TargetIsNotIndependent,
    NonAggressionPactRequiresMinor,
    AlreadyHaveNonAggressionPact,
    AlreadyAllied,
    JoinEmpireRequiresMinor,
    InsufficientEmbassyFunds,
    InsufficientConsulateFunds,
    InsufficientGrantFunds,
}

impl PlayerDiplomacyRejection {
    pub const fn proposal_mode(self) -> i16 {
        match self {
            Self::EmbassyRequired => 1,
            Self::AlreadyAtWar => 2,
            Self::AllianceRequiresGreatPower => 3,
            Self::PeaceRequiresOngoingWar => 5,
            Self::AlreadyDeclaringWar => 6,
            Self::TradeConsulateRequired => 7,
            Self::AlliedNationCannotBeBoycotted => 8,
            Self::ConsulateAlreadyPresent => 9,
            Self::EmbassyRequiresConsulate => 0xa,
            Self::EmbassyAlreadyPresent => 0xb,
            Self::TargetIsColony => 0xc,
            Self::TargetIsNotIndependent => 0xd,
            Self::NonAggressionPactRequiresMinor => 0xf,
            Self::AlreadyHaveNonAggressionPact => 0x10,
            Self::AlreadyAllied => 0x11,
            Self::JoinEmpireRequiresMinor => 0x12,
            Self::InsufficientEmbassyFunds => 0x15,
            Self::InsufficientConsulateFunds => 0x16,
            Self::InsufficientGrantFunds => 0x17,
        }
    }
}

#[derive(Clone, Copy)]
enum PlayerDiplomacyAction {
    JoinEmpire,
    Alliance,
    NonAggressionPact,
    PeaceTreaty,
    DeclareWar,
    Grant,
    TradeSubsidy,
    Boycott,
    BuildConsulate,
    BuildEmbassy,
}

impl DiplomacyPolicy {
    const fn player_action(self) -> Option<PlayerDiplomacyAction> {
        match self {
            Self::JoinEmpire => Some(PlayerDiplomacyAction::JoinEmpire),
            Self::Alliance => Some(PlayerDiplomacyAction::Alliance),
            Self::NonAggressionPact => Some(PlayerDiplomacyAction::NonAggressionPact),
            Self::PeaceTreaty => Some(PlayerDiplomacyAction::PeaceTreaty),
            Self::DeclareWar => Some(PlayerDiplomacyAction::DeclareWar),
            Self::BuildConsulate => Some(PlayerDiplomacyAction::BuildConsulate),
            Self::BuildEmbassy => Some(PlayerDiplomacyAction::BuildEmbassy),
            Self::JoinEmpireWithWarEntanglements => None,
        }
    }

    const fn requires_entanglement_check(self) -> bool {
        matches!(self, Self::JoinEmpire | Self::Alliance)
    }
}

impl GameState {
    /// Toggles one grant selected on the player diplomacy map.
    ///
    /// Retail lets an existing matching grant be withdrawn directly. Posting or
    /// replacing a grant requires an independent foreign nation and an embassy.
    pub fn toggle_player_diplomacy_grant(
        &mut self,
        source: MajorNationId,
        target: NationId,
        grant: DiplomacyGrant,
    ) -> PlayerDiplomacyOrderResult {
        assert!(
            self.nations.majors[source].economy.diplomacy_eligible,
            "player diplomacy orders require a diplomacy-eligible major nation"
        );
        assert!(
            PLAYER_DIPLOMACY_GRANT_AMOUNTS.contains(&grant.amount),
            "player diplomacy grants use one of the four recovered amounts"
        );
        if source.nation() == target {
            return PlayerDiplomacyOrderResult::SelectedNation;
        }

        if self.nations.majors[source]
            .economy
            .diplomacy_grants_by_nation[target]
            == Some(grant)
        {
            let removed = self.set_diplomacy_grant(source, target, None);
            debug_assert!(removed, "removing a grant cannot fail");
            return PlayerDiplomacyOrderResult::Applied;
        }

        if let Err(rejection) =
            self.validate_player_diplomacy_action(source, target, PlayerDiplomacyAction::Grant)
        {
            return self.reject_player_diplomacy(rejection);
        }

        if self.set_diplomacy_grant(source, target, Some(grant)) {
            PlayerDiplomacyOrderResult::Applied
        } else {
            self.reject_player_diplomacy(PlayerDiplomacyRejection::InsufficientGrantFunds)
        }
    }

    /// Toggles one of the seven recovered player trade-policy choices.
    pub fn toggle_player_trade_policy(
        &mut self,
        source: MajorNationId,
        target: NationId,
        policy: TradePolicyScore,
    ) -> PlayerDiplomacyOrderResult {
        assert!(
            self.nations.majors[source].economy.diplomacy_eligible,
            "player diplomacy orders require a diplomacy-eligible major nation"
        );
        assert!(
            PLAYER_TRADE_POLICY_SCORES.contains(&policy),
            "player trade policy uses one of the seven recovered scores"
        );
        if source.nation() == target {
            return PlayerDiplomacyOrderResult::SelectedNation;
        }
        let action = if policy == TradePolicyScore::BOYCOTT {
            PlayerDiplomacyAction::Boycott
        } else {
            PlayerDiplomacyAction::TradeSubsidy
        };
        if let Err(rejection) = self.validate_player_diplomacy_action(source, target, action) {
            return self.reject_player_diplomacy(rejection);
        }

        let current = self.nations.majors[source].common.trade_policy_by_nation[target];
        let next = if current == policy {
            TradePolicyScore::NEUTRAL
        } else {
            policy
        };
        self.set_trade_policy(source, target, next);
        PlayerDiplomacyOrderResult::Applied
    }

    /// Toggles one treaty selected on the player diplomacy map.
    ///
    /// Matching a posted policy retracts it, including the consulate/embassy
    /// treasury refund. Alliance and join-empire inherit the target's wars only
    /// after `confirm_entanglements`.
    pub fn toggle_player_diplomacy_policy(
        &mut self,
        source: MajorNationId,
        target: NationId,
        policy: DiplomacyPolicy,
        confirm_entanglements: bool,
    ) -> PlayerDiplomacyOrderResult {
        assert!(
            self.nations.majors[source].economy.diplomacy_eligible,
            "player diplomacy orders require a diplomacy-eligible major nation"
        );
        let action = policy
            .player_action()
            .expect("player diplomacy map posts one of the seven treaty actions");
        if source.nation() == target {
            return PlayerDiplomacyOrderResult::SelectedNation;
        }

        if self.nations.majors[source]
            .economy
            .diplomacy_policy_by_nation[target]
            == Some(policy)
        {
            self.clear_player_diplomacy_policy(source, target);
            return PlayerDiplomacyOrderResult::Applied;
        }

        if let Err(rejection) = self.validate_player_diplomacy_action(source, target, action) {
            return self.reject_player_diplomacy(rejection);
        }
        if policy.requires_entanglement_check()
            && !confirm_entanglements
            && self.has_alliance_guard(target, source.nation())
        {
            return PlayerDiplomacyOrderResult::NeedsEntanglementConfirmation;
        }

        let _ = self.apply_player_diplomacy_policy(source, target, policy);
        PlayerDiplomacyOrderResult::Applied
    }

    /// Toggles the colony-boycott flag for a foreign nation that the player does
    /// not itself control.
    pub fn toggle_player_colony_boycott(
        &mut self,
        source: MajorNationId,
        target: NationId,
    ) -> PlayerDiplomacyOrderResult {
        assert!(
            self.nations.majors[source].economy.diplomacy_eligible,
            "player diplomacy orders require a diplomacy-eligible major nation"
        );
        if source.nation() == target {
            return PlayerDiplomacyOrderResult::SelectedNation;
        }
        if self.owner_slot(target) == source.nation() {
            return PlayerDiplomacyOrderResult::Applied;
        }
        let enabled = self.nations.majors[source].economy.colony_boycott_flags[target] == 0;
        self.set_colony_boycott(source, target, enabled);
        PlayerDiplomacyOrderResult::Applied
    }

    /// Retail standing-score classifier used by the diplomacy relationship overlay.
    pub fn diplomacy_relationship_notch(&self, source: NationId, target: NationId) -> u8 {
        let standing = self.diplomacy.standings[source][target];
        if standing <= 0x14 {
            0
        } else if standing <= 0x31 {
            1
        } else if standing <= 0x4f {
            2
        } else if standing <= 0x64 {
            3
        } else if standing <= 0x87 {
            4
        } else if standing <= 0xaa {
            5
        } else if standing <= 0xcd {
            6
        } else if standing <= 0xf0 {
            7
        } else {
            8
        }
    }

    fn reject_player_diplomacy(
        &mut self,
        rejection: PlayerDiplomacyRejection,
    ) -> PlayerDiplomacyOrderResult {
        self.diplomacy.proposal_mode_raw = rejection.proposal_mode();
        PlayerDiplomacyOrderResult::Rejected(rejection)
    }

    fn validate_player_diplomacy_action(
        &self,
        source: MajorNationId,
        target: NationId,
        action: PlayerDiplomacyAction,
    ) -> Result<(), PlayerDiplomacyRejection> {
        let source_nation = source.nation();
        match self.status_of(target) {
            CountryStatus::ColonyOf(_) => {
                return Err(PlayerDiplomacyRejection::TargetIsColony);
            }
            CountryStatus::ProtectorateOf(_) => {
                return Err(PlayerDiplomacyRejection::TargetIsNotIndependent);
            }
            CountryStatus::Independent => {}
        }

        let mission = self.diplomacy.mission_levels[source_nation][target];
        let relationship = self.diplomacy.relationships[source_nation][target];
        let at_war = relationship == DiplomaticRelationship::War;
        let treasury = self.nations.majors[source].common.treasury;
        match action {
            PlayerDiplomacyAction::JoinEmpire => {
                if mission != DiplomaticMissionLevel::Embassy {
                    return Err(PlayerDiplomacyRejection::EmbassyRequired);
                }
                if at_war {
                    return Err(PlayerDiplomacyRejection::AlreadyAtWar);
                }
                if MajorNationId::from_nation(target).is_some() {
                    return Err(PlayerDiplomacyRejection::JoinEmpireRequiresMinor);
                }
            }
            PlayerDiplomacyAction::Alliance => {
                if MajorNationId::from_nation(target).is_none() {
                    return Err(PlayerDiplomacyRejection::AllianceRequiresGreatPower);
                }
                if at_war {
                    return Err(PlayerDiplomacyRejection::AlreadyAtWar);
                }
                if relationship == DiplomaticRelationship::Alliance {
                    return Err(PlayerDiplomacyRejection::AlreadyAllied);
                }
            }
            PlayerDiplomacyAction::NonAggressionPact => {
                if mission != DiplomaticMissionLevel::Embassy {
                    return Err(PlayerDiplomacyRejection::EmbassyRequired);
                }
                if at_war {
                    return Err(PlayerDiplomacyRejection::AlreadyAtWar);
                }
                if relationship == DiplomaticRelationship::NonAggressionPact {
                    return Err(PlayerDiplomacyRejection::AlreadyHaveNonAggressionPact);
                }
                if MajorNationId::from_nation(target).is_some() {
                    return Err(PlayerDiplomacyRejection::NonAggressionPactRequiresMinor);
                }
            }
            PlayerDiplomacyAction::PeaceTreaty => {
                if !self.war_stamp_stale(source_nation, target) {
                    return Err(PlayerDiplomacyRejection::PeaceRequiresOngoingWar);
                }
            }
            PlayerDiplomacyAction::DeclareWar => {
                if at_war {
                    return Err(PlayerDiplomacyRejection::AlreadyDeclaringWar);
                }
            }
            PlayerDiplomacyAction::Grant => {
                if mission != DiplomaticMissionLevel::Embassy {
                    return Err(PlayerDiplomacyRejection::EmbassyRequired);
                }
            }
            PlayerDiplomacyAction::TradeSubsidy => {
                if mission == DiplomaticMissionLevel::None {
                    return Err(PlayerDiplomacyRejection::TradeConsulateRequired);
                }
            }
            PlayerDiplomacyAction::Boycott => {
                if relationship == DiplomaticRelationship::Alliance {
                    return Err(PlayerDiplomacyRejection::AlliedNationCannotBeBoycotted);
                }
            }
            PlayerDiplomacyAction::BuildConsulate => {
                if mission != DiplomaticMissionLevel::None {
                    return Err(PlayerDiplomacyRejection::ConsulateAlreadyPresent);
                }
                if at_war {
                    return Err(PlayerDiplomacyRejection::AlreadyAtWar);
                }
                if treasury < 500 {
                    return Err(PlayerDiplomacyRejection::InsufficientConsulateFunds);
                }
            }
            PlayerDiplomacyAction::BuildEmbassy => {
                if mission == DiplomaticMissionLevel::None {
                    return Err(PlayerDiplomacyRejection::EmbassyRequiresConsulate);
                }
                if mission == DiplomaticMissionLevel::Embassy {
                    return Err(PlayerDiplomacyRejection::EmbassyAlreadyPresent);
                }
                if at_war {
                    return Err(PlayerDiplomacyRejection::AlreadyAtWar);
                }
                if treasury < 5000 {
                    return Err(PlayerDiplomacyRejection::InsufficientEmbassyFunds);
                }
            }
        }
        Ok(())
    }

    fn clear_player_diplomacy_policy(&mut self, source: MajorNationId, target: NationId) {
        let previous = self.nations.majors[source]
            .economy
            .diplomacy_policy_by_nation[target];
        match previous {
            Some(DiplomacyPolicy::BuildConsulate) => {
                self.nations.majors[source].common.treasury += 500;
            }
            Some(DiplomacyPolicy::BuildEmbassy) => {
                self.nations.majors[source].common.treasury += 5000;
            }
            _ => {}
        }
        self.nations.majors[source]
            .economy
            .diplomacy_policy_by_nation[target] = None;
    }

    /// `TGreatPower::ApplyDiplomacyPolicyStateForTargetWithCostChecks` while the
    /// diplomacy map is open (`TSimMgr::mode != 6`), so declare-war does not
    /// queue a war transition.
    fn apply_player_diplomacy_policy(
        &mut self,
        source: MajorNationId,
        target: NationId,
        policy: DiplomacyPolicy,
    ) -> bool {
        let embassy = self.diplomacy.mission_levels[source.nation()][target]
            == DiplomaticMissionLevel::Embassy;
        let mut apply = true;
        match policy {
            DiplomacyPolicy::JoinEmpire
            | DiplomacyPolicy::Alliance
            | DiplomacyPolicy::NonAggressionPact
                if !embassy =>
            {
                apply = false;
            }
            DiplomacyPolicy::DeclareWar => {
                if self.diplomacy.relationships[target][source.nation()]
                    == DiplomaticRelationship::Alliance
                {
                    self.apply_peace_relationship(source.nation(), target, true);
                }
                if self.nations.majors[source].economy.diplomacy_eligible {
                    let _ = self.set_diplomacy_grant(source, target, None);
                }
            }
            DiplomacyPolicy::BuildConsulate => {
                apply = self.can_afford_diplomacy(source, 500);
                if apply {
                    self.nations.majors[source].common.treasury -= 500;
                }
            }
            DiplomacyPolicy::BuildEmbassy => {
                apply = self.can_afford_diplomacy(source, 5000);
                if apply {
                    self.nations.majors[source].common.treasury -= 5000;
                }
            }
            _ => {}
        }
        if apply {
            self.nations.majors[source]
                .economy
                .diplomacy_policy_by_nation[target] = Some(policy);
        }
        apply
    }

    /// Retail nation information panel military classification.
    pub fn diplomacy_military_power_band(&self, nation: MajorNationId) -> u8 {
        let scores = MajorNationId::all()
            .filter(|&candidate| self.major_is_event_eligible(candidate))
            .map(|candidate| self.military_power_score(candidate) as f32)
            .collect::<Vec<_>>();
        classify_diplomacy_information_band(self.military_power_score(nation) as f32, &scores)
    }

    /// Retail nation information panel industry classification.
    pub fn diplomacy_industry_band(&self, nation: MajorNationId) -> u8 {
        let scores = MajorNationId::all()
            .filter(|&candidate| self.major_is_event_eligible(candidate))
            .map(|candidate| self.diplomacy_industry_score(candidate) as f32)
            .collect::<Vec<_>>();
        classify_diplomacy_information_band(self.diplomacy_industry_score(nation) as f32, &scores)
    }

    /// Retail `TDiplomacyMgr::GetFavoriteTradePartner` read model.
    pub fn favorite_trade_partner(&self, minor: MinorNationId) -> Option<MajorNationId> {
        let minor_nation = minor.nation();
        let mut best_score = 0;
        let mut selected = None;
        for major in MajorNationId::all().filter(|&major| self.major_is_event_eligible(major)) {
            let policy = self.nations.majors[major].common.trade_policy_by_nation[minor_nation];
            let score = (200 - policy.retail())
                * i32::from(self.diplomacy.standings[minor_nation][major.nation()]);
            let select = if score > best_score {
                true
            } else if score == best_score {
                if self.nations.minors[minor].as_ref().is_some_and(|nation| {
                    nation.common.status() == CountryStatus::ColonyOf(major.nation())
                }) {
                    true
                } else {
                    let mut tie_seed = minor.index() as i32 * 7
                        + major.index() as i32
                        + self.turn.economic_turn
                        + score;
                    if tie_seed == 0 {
                        tie_seed = minor.index() as i32;
                    }
                    let draw = (tie_seed as u32).wrapping_mul(0x015a_4e35).wrapping_add(1);
                    (draw >> 12) & 1 != 0
                }
            } else {
                false
            };
            if select {
                best_score = score;
                selected = Some(major);
            }
        }
        selected
    }

    pub(crate) fn major_is_event_eligible(&self, nation: MajorNationId) -> bool {
        !matches!(
            self.nations.majors[nation].common.status(),
            CountryStatus::ProtectorateOf(_)
        )
    }

    fn diplomacy_industry_score(&self, nation: MajorNationId) -> i32 {
        let major = &self.nations.majors[nation];
        4 + [
            CityFacilitySlot::TextileMill,
            CityFacilitySlot::ClothingFactory,
            CityFacilitySlot::SteelMill,
            CityFacilitySlot::Metalworks,
            CityFacilitySlot::LumberMill,
            CityFacilitySlot::FurnitureFactory,
            CityFacilitySlot::OilRefinery,
        ]
        .into_iter()
        .map(|slot| i32::from(major.city.production_orders[slot]))
        .sum::<i32>()
    }
}

fn classify_diplomacy_information_band(own_score: f32, scores: &[f32]) -> u8 {
    if scores.len() < 2 {
        return 2;
    }
    let count = scores.len() as f32;
    let sum = scores.iter().sum::<f32>();
    let mean = sum / count;
    let sum_of_squares = scores.iter().map(|score| score * score).sum::<f32>();
    let deviation =
        ((sum_of_squares - 2.0 * mean * sum + mean * mean * count) / (count - 1.0)).sqrt();
    if own_score > mean + 2.0 * deviation {
        4
    } else if own_score > mean + deviation {
        3
    } else if own_score >= mean - deviation {
        2
    } else if own_score >= mean - 2.0 * deviation {
        1
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_start_diplomacy_preserves_retail_matrix_order_and_consortiums() {
        let mut rng = RetailCrtRng::from_state(1);
        let state =
            DiplomacyState::for_random_start(MajorNationId::new(6), Difficulty::Normal, &mut rng);

        assert_eq!(state.standings[NationId::new(0)][NationId::new(0)], 0xff);
        assert_eq!(state.standings[NationId::new(0)][NationId::new(1)], 0x5a);
        assert_eq!(state.standings[NationId::new(7)][NationId::new(10)], 0x96);
        assert_eq!(state.standings[NationId::new(7)][NationId::new(11)], 0x6e);
        assert_eq!(
            state.mission_levels[NationId::new(0)][NationId::new(1)],
            DiplomaticMissionLevel::Embassy
        );
        assert_eq!(
            state.mission_levels[NationId::new(0)][NationId::new(7)],
            DiplomaticMissionLevel::None
        );
        assert_eq!(rng.state(), 1, "Normal initialization consumes no CRT draw");
    }

    #[test]
    fn introductory_and_hard_diplomacy_consume_only_the_recovered_consulate_draws() {
        let mut introductory_rng = RetailCrtRng::from_state(1);
        let introductory = DiplomacyState::for_random_start(
            MajorNationId::new(6),
            Difficulty::Introductory,
            &mut introductory_rng,
        );
        assert_eq!(introductory_rng.state(), 2_745_024);
        for target in 11..15 {
            assert_eq!(
                introductory.mission_levels[NationId::new(6)][NationId::new(target)],
                DiplomaticMissionLevel::TradeConsulate
            );
        }

        let mut hard_rng = RetailCrtRng::from_state(1);
        let hard = DiplomacyState::for_random_start(
            MajorNationId::new(6),
            Difficulty::Hard,
            &mut hard_rng,
        );
        let mut expected_rng = RetailCrtRng::from_state(1);
        for _ in 0..MajorNationId::COUNT - 1 {
            expected_rng.next_rand();
        }
        assert_eq!(hard_rng, expected_rng);
        assert_eq!(
            hard.mission_levels[NationId::new(0)][NationId::new(16)],
            DiplomaticMissionLevel::TradeConsulate
        );
    }

    #[test]
    fn nigh_on_impossible_overwrites_ai_diagonal_standings_like_retail() {
        let mut rng = RetailCrtRng::from_state(1);
        let state = DiplomacyState::for_random_start(
            MajorNationId::new(6),
            Difficulty::NighOnImpossible,
            &mut rng,
        );

        assert_eq!(state.standings[NationId::new(0)][NationId::new(0)], 0x6e);
        assert_eq!(state.standings[NationId::new(6)][NationId::new(6)], 0xff);
    }
}
