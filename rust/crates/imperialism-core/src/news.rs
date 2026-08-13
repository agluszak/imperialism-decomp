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

impl GameState {
    /// `TNewsMgr::AddTreatyEvent` for a single-player pass.
    pub(crate) fn add_treaty_event(
        &mut self,
        event: InterNationNewsKind,
        nation_a: NationId,
        nation_b: NationId,
    ) {
        if event.concatenates_into_existing_story() {
            self.concatenate_treaty(event, nation_a, nation_b);
            return;
        }

        if self.treaty_event_already_queued(event, nation_a, nation_b) {
            return;
        }

        if let Some(subject) = MajorNationId::from_nation(nation_a) {
            self.pending
                .queue_newspaper_event(inter_nation_event(event, subject, nation_b));
        }
        if MajorNationId::from_nation(nation_b).is_some() && event.also_queues_for_second_major() {
            let subject = MajorNationId::from_nation(nation_b).expect("checked major");
            self.pending
                .queue_newspaper_event(inter_nation_event(event, subject, nation_a));
        }
    }

    fn concatenate_treaty(
        &mut self,
        event: InterNationNewsKind,
        nation_a: NationId,
        nation_b: NationId,
    ) {
        let mut nation_a_handled = MajorNationId::from_nation(nation_a).is_none();
        let mut nation_b_handled = MajorNationId::from_nation(nation_b).is_none();
        if event.concatenate_skips_second_major() {
            nation_b_handled = true;
        }

        for pending in &mut self.pending.newspaper_events {
            let PendingNewspaperEvent::InterNation {
                event: queued,
                subject,
                related_nations,
            } = pending
            else {
                continue;
            };
            if *queued != event {
                continue;
            }
            if !nation_a_handled && subject.nation() == nation_a {
                related_nations[nation_b] = true;
                nation_a_handled = true;
            }
            if !nation_b_handled && subject.nation() == nation_b {
                related_nations[nation_a] = true;
                nation_b_handled = true;
            }
        }

        if !nation_a_handled {
            let subject = MajorNationId::from_nation(nation_a).expect("major subject");
            self.pending
                .queue_newspaper_event(inter_nation_event(event, subject, nation_b));
        }
        if !nation_b_handled {
            let subject = MajorNationId::from_nation(nation_b).expect("major subject");
            self.pending
                .queue_newspaper_event(inter_nation_event(event, subject, nation_a));
        }
    }

    fn treaty_event_already_queued(
        &self,
        event: InterNationNewsKind,
        nation_a: NationId,
        nation_b: NationId,
    ) -> bool {
        self.pending.newspaper_events.iter().any(|pending| {
            let PendingNewspaperEvent::InterNation {
                event: queued,
                subject,
                related_nations,
            } = pending
            else {
                return false;
            };
            *queued == event
                && ((subject.nation() == nation_a && related_nations[nation_b])
                    || (subject.nation() == nation_b && related_nations[nation_a]))
        })
    }
}

fn inter_nation_event(
    event: InterNationNewsKind,
    subject: MajorNationId,
    related: NationId,
) -> PendingNewspaperEvent {
    let mut related_nations = NationTable::default();
    related_nations[related] = true;
    PendingNewspaperEvent::InterNation {
        event,
        subject,
        related_nations,
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

impl InterNationNewsKind {
    /// Retail `InterNationEventKind` codes. Kept for save/oracle mapping.
    #[allow(dead_code)]
    pub(crate) const fn retail(self) -> i32 {
        match self {
            Self::WarDeclaredBySubject => 0x00,
            Self::WarDeclaredAgainstSubject => 0x01,
            Self::PeaceTreatyAccepted => 0x02,
            Self::JoinEmpireAccepted => 0x03,
            Self::AllianceAccepted => 0x04,
            Self::NonAggressionPactAccepted => 0x05,
            Self::PeaceTreatyRejected => 0x07,
            Self::JoinEmpireRejected => 0x09,
            Self::AllianceRejected => 0x0b,
            Self::NonAggressionPactRejected => 0x0d,
            Self::TradeConsulateEstablished => 0x12,
            Self::EmbassyEstablished => 0x14,
            Self::MinorEmpireAffiliationChanged => 0x16,
            Self::MinorTerritoryRelationshipAffected => 0x17,
            Self::PeaceRelationshipPropagated => 0x18,
            Self::WarWithIndependentMinor => 0x19,
            Self::AllianceRelationshipEstablished => 0x1a,
            Self::NationJoinedEmpire => 0x1b,
            Self::NationJoinedWar => 0x1c,
            Self::NationTransferred => 0x1d,
        }
    }

    /// `AddTreatyEvent` concatenates these into an existing story (`eventKind >= 0x05 && < 0x16`).
    pub(crate) const fn concatenates_into_existing_story(self) -> bool {
        matches!(
            self,
            Self::NonAggressionPactAccepted
                | Self::PeaceTreatyRejected
                | Self::JoinEmpireRejected
                | Self::AllianceRejected
                | Self::NonAggressionPactRejected
                | Self::TradeConsulateEstablished
                | Self::EmbassyEstablished
        )
    }

    /// After queuing the first great-power subject, also queue a swapped copy when
    /// the other party is a great power (`eventKind > 0x01 && < 0x19`).
    pub(crate) const fn also_queues_for_second_major(self) -> bool {
        matches!(
            self,
            Self::PeaceTreatyAccepted
                | Self::JoinEmpireAccepted
                | Self::AllianceAccepted
                | Self::NonAggressionPactAccepted
                | Self::PeaceTreatyRejected
                | Self::JoinEmpireRejected
                | Self::AllianceRejected
                | Self::NonAggressionPactRejected
                | Self::TradeConsulateEstablished
                | Self::EmbassyEstablished
                | Self::MinorEmpireAffiliationChanged
                | Self::MinorTerritoryRelationshipAffected
                | Self::PeaceRelationshipPropagated
        )
    }

    /// `ConcatenateTreaty` does not add the second great power as its own subject.
    pub(crate) const fn concatenate_skips_second_major(self) -> bool {
        matches!(
            self,
            Self::PeaceTreatyRejected
                | Self::JoinEmpireRejected
                | Self::AllianceRejected
                | Self::NonAggressionPactRejected
                | Self::TradeConsulateEstablished
                | Self::EmbassyEstablished
        )
    }
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
