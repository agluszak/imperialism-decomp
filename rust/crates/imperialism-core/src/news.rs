use crate::*;
use serde::{Deserialize, Serialize};

impl PendingWorkState {
    /// Retail's shared news list places a newly copied record at the front for
    /// the observed phase-six producer path. Newspaper selection traverses this
    /// stored order, so the semantic queue must preserve that LIFO behavior.
    pub(crate) fn queue_newspaper_event(&mut self, event: PendingNewspaperEvent) {
        self.newspaper_events.insert(0, event);
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PendingWorkState {
    pub nations: MajorNationTable<NationPendingWork>,
    /// Whether retail's post-combat map boundary has battle reports to present.
    pub combat_reports_pending: bool,
    pub newspaper_events: Vec<PendingNewspaperEvent>,
    pub war_transitions: Vec<WarTransition>,
}

pub const NEWS_TEMPLATE_COUNT: usize = 360;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NewsState {
    pub pages: MajorNationTable<Option<NewsPage>>,
    pub last_used_turn_by_nation_and_template: MajorNationTable<Vec<i16>>,
}

impl Default for NewsState {
    fn default() -> Self {
        Self {
            pages: MajorNationTable::default(),
            last_used_turn_by_nation_and_template: MajorNationTable::from_fn(|_| {
                vec![0; NEWS_TEMPLATE_COUNT]
            }),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NewsPage {
    /// Retail stores the page as `[column][row]`.
    pub stories: [[Option<NewsStory>; 3]; 3],
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NewsStory {
    pub template_index: u16,
    pub story_id: i16,
    pub feature: bool,
    pub arguments: [NewsArgument; 4],
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NewsArgument {
    #[default]
    Empty,
    NationMask {
        nations: NationTable<bool>,
    },
    NationList {
        nations: NationTable<bool>,
    },
    Province {
        province: ProvinceId,
    },
    Zone {
        ordinal: i16,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterNationNewsKind {
    WarDeclaredBySubject,
    WarDeclaredAgainstSubject,
    PeaceTreatyAccepted,
    JoinEmpireAccepted,
    AllianceAccepted,
    NonAggressionPactAccepted,
    PeaceTreatyRejected,
    JoinEmpireRejected,
    AllianceRejected,
    NonAggressionPactRejected,
    TradeConsulateEstablished,
    EmbassyEstablished,
    MinorEmpireAffiliationChanged,
    MinorTerritoryRelationshipAffected,
    PeaceRelationshipPropagated,
    WarWithIndependentMinor,
    AllianceRelationshipEstablished,
    NationJoinedEmpire,
    NationJoinedWar,
    NationTransferred,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PendingNewspaperEvent {
    InterNation {
        event: InterNationNewsKind,
        subject: MajorNationId,
        related_nations: NationTable<bool>,
    },
    Shortage {
        subject: MajorNationId,
        affected_nations: NationTable<bool>,
        resource: crate::ResourceKind,
    },
    Miscellaneous {
        audience: Option<MajorNationId>,
        story_code: i32,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct WarTransition {
    pub first: NationId,
    pub second: NationId,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct NationPendingWork {
    pub turn_events: Vec<DiplomacyNotice>,
    pub proposals: Vec<DiplomacyProposal>,
    pub turn_summary: Vec<TurnSummary>,
    pub turn_start_events: Vec<TurnStartEvent>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiplomacyNotice {
    pub source: NationId,
    pub code: i16,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiplomacyProposal {
    pub source: NationId,
    pub policy: DiplomacyPolicy,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TurnSummary {
    MilitaryRecruit {
        turn_tick: i32,
        unit_type: MilitaryUnitKind,
        count: i16,
    },
    /// A recovered queue record whose presentation meaning has not yet been
    /// interpreted by a Rust rule.
    Retail {
        turn_tick: i32,
        order_kind: i16,
        payload: i16,
        flags: i16,
    },
}
impl TurnSummary {
    pub(crate) const fn order_key(self) -> i16 {
        match self {
            Self::MilitaryRecruit { .. } => 3,
            Self::Retail { order_kind, .. } => order_kind,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TurnStartEvent {
    LandSale { tag: i32, sale: LandSale },
    Tagged { class: String, tag: i32 },
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LandSale {
    pub tile: TileId,
    pub nation: NationId,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn joined_war(counterpart: MajorNationId) -> PendingNewspaperEvent {
        let mut related_nations = NationTable::default();
        related_nations[counterpart.nation()] = true;
        PendingNewspaperEvent::InterNation {
            event: InterNationNewsKind::NationJoinedWar,
            subject: MajorNationId::new(0),
            related_nations,
        }
    }

    #[test]
    fn phase_six_news_records_use_the_retail_lifo_order() {
        let first = joined_war(MajorNationId::new(1));
        let second = joined_war(MajorNationId::new(2));
        let mut pending = PendingWorkState::default();

        pending.queue_newspaper_event(first.clone());
        assert_eq!(pending.newspaper_events, vec![first.clone()]);
        pending.queue_newspaper_event(second.clone());

        assert_eq!(pending.newspaper_events, vec![second, first]);
    }
}
