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
    pub const fn retail(self) -> i32 {
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

impl GameState {
    /// Mirrors `TNewsMgr::StartNewsPhase` page construction without loading `news.tab`.
    pub fn construct_newspaper_pages(&mut self) {
        self.news.pages = MajorNationTable::default();
        let active = MajorNationId::from_nation(self.turn.active_nation);
        for nation in MajorNationId::all() {
            let eligible = self.nations.major(nation).economy.diplomacy_eligible;
            if eligible || active == Some(nation) {
                let page = self.create_newspaper(nation);
                if page.stories.iter().flatten().any(Option::is_some) {
                    self.news.pages[nation] = Some(page);
                }
            }
        }
        self.pending.newspaper_events.clear();
    }

    fn create_newspaper(&mut self, nation: MajorNationId) -> NewsPage {
        let mut page = NewsPage::default();
        let mut column = 0;
        let mut row = 0;
        let story_ids = self.data.news_story_ids();
        create_event_stories(
            &self.pending.newspaper_events,
            &self.battle_reports,
            &mut self.rng,
            nation,
            story_ids,
            &mut page,
            &mut column,
            &mut row,
        );

        let count = story_ids.len();
        if count == 0 || row >= 3 {
            return page;
        }

        let ticks = &mut self.news.last_used_turn_by_nation_and_template[nation];
        let mut order: Vec<u16> = (0..count as u16).collect();
        for i in 0..count.saturating_sub(1) {
            for j in i..count {
                if ticks[order[j] as usize] < ticks[order[i] as usize] {
                    order.swap(i, j);
                }
            }
        }

        let cur_tick = self.turn.economic_turn as i16;
        let year = (self.turn.economic_turn / 4) as i16;
        let mut misses = 0;
        while row < 3 && misses < 4 {
            let mut pick;
            loop {
                let mut r1 = self.rng.next_crt_rand() % count as i32;
                let r2 = self.rng.next_crt_rand() % count as i32;
                if r2 <= r1 {
                    r1 = r2;
                }
                pick = order[r1 as usize] as usize;
                if story_ids[pick] >= 0 {
                    break;
                }
            }
            if ticks[pick] == cur_tick {
                misses += 1;
                continue;
            }
            let id = story_ids[pick];
            if id > 9 && id % 10 == 0 {
                if year < id as i16 - 10 || year >= id as i16 {
                    continue;
                }
            } else if id != 1 {
                continue;
            }
            let other = random_other_major(&mut self.rng, nation);
            page.stories[column][row] = Some(NewsStory {
                template_index: pick as u16,
                story_id: id as i16,
                feature: true,
                arguments: [
                    nation_mask_arg(1 << nation.get()),
                    nation_mask_arg(1 << other.get()),
                    NewsArgument::Empty,
                    NewsArgument::Empty,
                ],
            });
            ticks[pick] = cur_tick;
            advance_page_cursor(&mut column, &mut row);
            misses = 0;
        }
        page
    }
}

#[allow(clippy::too_many_arguments)]
fn create_event_stories(
    events: &[PendingNewspaperEvent],
    battle_reports: &[BattleReport],
    rng: &mut RngState,
    nation: MajorNationId,
    story_ids: &[i32],
    page: &mut NewsPage,
    column: &mut usize,
    row: &mut usize,
) {
    let nation_slot = i32::from(nation.get());
    let mut ordinal = 0;
    let mut code = 0;
    while code <= 0x18 {
        if *row > 2 {
            break;
        }
        if (0xe..=0x11).contains(&code) {
            code += 1;
            continue;
        }
        match find_event(events, ordinal, |event| {
            event_code(event) == code && event_subject(event) == nation_slot
        }) {
            None => {
                ordinal = 0;
                code += 1;
            }
            Some((index, event)) => {
                ordinal = index + 1;
                let mask = event_mask(event);
                let mut want_id = -100 - code;
                if (5..=0x15).contains(&code) && mask_popcount(mask) > 1 {
                    want_id = -0x65 - code;
                }
                if let Some(template) = find_template(story_ids, want_id) {
                    place_event_story(
                        page,
                        column,
                        row,
                        template,
                        want_id,
                        nation_mask_arg(1 << event_subject(event)),
                        nation_mask_arg(mask),
                    );
                }
            }
        }
    }

    if *row >= 3 {
        return;
    }

    code = 0x19;
    while code <= 0x1d {
        if *row > 2 {
            break;
        }
        match find_event(events, ordinal, |event| {
            event_code(event) == code && event_subject(event) != nation_slot
        }) {
            None => {
                ordinal = 0;
                code += 1;
            }
            Some((index, event)) => {
                let mask = event_mask(event);
                if mask == 1 << nation.get() {
                    ordinal = 0;
                    code += 1;
                    continue;
                }
                ordinal = index + 1;
                let want_id = -100 - code;
                if let Some(template) = find_template(story_ids, want_id) {
                    place_event_story(
                        page,
                        column,
                        row,
                        template,
                        want_id,
                        nation_mask_arg(1 << event_subject(event)),
                        nation_mask_arg(mask),
                    );
                }
            }
        }
    }

    if *row >= 3 {
        return;
    }

    ordinal = 0;
    loop {
        match find_event(events, ordinal, |event| {
            matches!(event, PendingNewspaperEvent::Shortage { .. })
                && event_subject(event) == nation_slot
        }) {
            None => break,
            Some((index, event)) => {
                ordinal = index + 1;
                let mask = event_mask(event);
                let resource_bits = event_related(event);
                let mut want_id = -0x14;
                if mask_popcount(mask) > 1 {
                    want_id = -0x15;
                }
                if let Some(template) = find_template(story_ids, want_id) {
                    place_event_story(
                        page,
                        column,
                        row,
                        template,
                        want_id,
                        nation_list_arg(resource_bits),
                        nation_mask_arg(mask),
                    );
                }
                if *row > 2 {
                    break;
                }
            }
        }
    }

    if *row < 3 && !battle_reports.is_empty() {
        let report = &battle_reports[rng.next_crt_rand() as usize % battle_reports.len()];
        let (want_id, location) = if report.kind.is_land() {
            let BattleReportLocation::Province(province) = report.location else {
                panic!("land battle report requires a province location");
            };
            (
                i32::from(report.participant == Some(BattleReportSideSlot::Right)) - 0x1a,
                NewsArgument::Province { province },
            )
        } else {
            let BattleReportLocation::Zone(zone) = report.location else {
                panic!("naval battle report requires a zone location");
            };
            (
                -0x1b - i32::from(report.kind != BattleReportKind::SeaBattle),
                NewsArgument::Zone {
                    ordinal: zone.get() as i16,
                },
            )
        };
        if let Some(template) = find_template(story_ids, want_id) {
            page.stories[*column][*row] = Some(NewsStory {
                template_index: template as u16,
                story_id: want_id as i16,
                feature: true,
                arguments: [
                    location,
                    nation_mask_arg(1 << report.sides[BattleReportSideSlot::Left].nation.get()),
                    nation_mask_arg(1 << report.sides[BattleReportSideSlot::Right].nation.get()),
                    NewsArgument::Empty,
                ],
            });
            advance_page_cursor(column, row);
        }
    }

    for pass in 0..2 {
        if *row > 2 {
            return;
        }
        let target = if pass == 0 { nation_slot } else { 999 };
        ordinal = 0;
        loop {
            if *row > 2 {
                return;
            }
            match find_event(events, ordinal, |event| {
                matches!(event, PendingNewspaperEvent::Miscellaneous { .. })
                    && event_subject(event) == target
            }) {
                None => break,
                Some((index, event)) => {
                    ordinal = index + 1;
                    let want_id = -1000 - event_story_code(event);
                    if let Some(template) = find_template(story_ids, want_id) {
                        let parm0 = if event_subject(event) == -1 {
                            NewsArgument::Empty
                        } else {
                            nation_mask_arg(1i32.wrapping_shl(event_subject(event) as u32))
                        };
                        page.stories[*column][*row] = Some(NewsStory {
                            template_index: template as u16,
                            story_id: want_id as i16,
                            feature: false,
                            arguments: [
                                parm0,
                                NewsArgument::Empty,
                                NewsArgument::Empty,
                                NewsArgument::Empty,
                            ],
                        });
                        advance_page_cursor(column, row);
                    }
                }
            }
        }
    }
}

fn find_event(
    events: &[PendingNewspaperEvent],
    start: usize,
    predicate: impl Fn(&PendingNewspaperEvent) -> bool,
) -> Option<(usize, &PendingNewspaperEvent)> {
    events[start..]
        .iter()
        .enumerate()
        .find(|(_, event)| predicate(event))
        .map(|(offset, event)| (start + offset, event))
}

fn event_code(event: &PendingNewspaperEvent) -> i32 {
    match event {
        PendingNewspaperEvent::InterNation { event, .. } => event.retail(),
        PendingNewspaperEvent::Shortage { .. } => 0x0f,
        PendingNewspaperEvent::Miscellaneous { .. } => 0x11,
    }
}

fn event_subject(event: &PendingNewspaperEvent) -> i32 {
    match event {
        PendingNewspaperEvent::InterNation { subject, .. }
        | PendingNewspaperEvent::Shortage { subject, .. } => i32::from(subject.get()),
        PendingNewspaperEvent::Miscellaneous {
            audience: Some(nation),
            ..
        } => i32::from(nation.get()),
        PendingNewspaperEvent::Miscellaneous { audience: None, .. } => 999,
    }
}

fn event_mask(event: &PendingNewspaperEvent) -> i32 {
    match event {
        PendingNewspaperEvent::InterNation {
            related_nations, ..
        } => nations_to_bits(related_nations),
        PendingNewspaperEvent::Shortage {
            affected_nations, ..
        } => nations_to_bits(affected_nations),
        PendingNewspaperEvent::Miscellaneous { story_code, .. } => *story_code,
    }
}

fn event_related(event: &PendingNewspaperEvent) -> i32 {
    match event {
        PendingNewspaperEvent::Shortage { resource, .. } => 1 << resource.retail(),
        _ => 0,
    }
}

fn event_story_code(event: &PendingNewspaperEvent) -> i32 {
    match event {
        PendingNewspaperEvent::Miscellaneous { story_code, .. } => *story_code,
        _ => 0,
    }
}

fn nations_to_bits(nations: &NationTable<bool>) -> i32 {
    let mut bits = 0;
    for nation in NationId::all() {
        if nations[nation] {
            bits |= 1 << nation.get();
        }
    }
    bits
}

fn bits_to_nations(bits: i32) -> NationTable<bool> {
    let mut nations = NationTable::default();
    for nation in NationId::all() {
        nations[nation] = bits & (1 << nation.get()) != 0;
    }
    nations
}

fn mask_popcount(bits: i32) -> i32 {
    (0..0x17).filter(|bit| bits & (1 << bit) != 0).count() as i32
}

fn nation_mask_arg(bits: i32) -> NewsArgument {
    NewsArgument::NationMask {
        nations: bits_to_nations(bits),
    }
}

fn nation_list_arg(bits: i32) -> NewsArgument {
    NewsArgument::NationList {
        nations: bits_to_nations(bits),
    }
}

fn find_template(story_ids: &[i32], want_id: i32) -> Option<usize> {
    story_ids.iter().position(|&id| id == want_id)
}

fn place_event_story(
    page: &mut NewsPage,
    column: &mut usize,
    row: &mut usize,
    template: usize,
    want_id: i32,
    parm0: NewsArgument,
    parm1: NewsArgument,
) {
    page.stories[*column][*row] = Some(NewsStory {
        template_index: template as u16,
        story_id: want_id as i16,
        feature: false,
        arguments: [parm0, parm1, NewsArgument::Empty, NewsArgument::Empty],
    });
    advance_page_cursor(column, row);
}

fn advance_page_cursor(column: &mut usize, row: &mut usize) {
    *column += 1;
    if *column == 3 {
        *column = 0;
        *row += 1;
    }
}

fn random_other_major(rng: &mut RngState, nation: MajorNationId) -> MajorNationId {
    loop {
        let other = MajorNationId::new((rng.next_crt_rand() % 7) as u8);
        if other != nation {
            return other;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::game_state;

    fn joined_war(counterpart: MajorNationId) -> PendingNewspaperEvent {
        let mut related_nations = NationTable::default();
        related_nations[counterpart.nation()] = true;
        PendingNewspaperEvent::InterNation {
            event: InterNationNewsKind::NationJoinedWar,
            subject: MajorNationId::new(0),
            related_nations,
        }
    }

    fn filler_catalog() -> GameData {
        let mut ids = vec![1; NEWS_TEMPLATE_COUNT];
        ids[0] = -1003;
        GameData::from_news_story_ids(ids)
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

    #[test]
    fn world_misc_event_occupies_the_first_slot_on_every_human_page() {
        let mut state = game_state();
        state
            .pending
            .queue_newspaper_event(PendingNewspaperEvent::Miscellaneous {
                audience: None,
                story_code: 3,
            });
        state.set_game_data(filler_catalog());
        state.construct_newspaper_pages();

        let page = state.news.pages[MajorNationId::new(0)]
            .as_ref()
            .expect("human nation 0 receives a newspaper");
        let story = page.stories[0][0]
            .as_ref()
            .expect("misc event is placed first");
        assert_eq!(story.template_index, 0);
        assert_eq!(story.story_id, -1003);
        assert!(!story.feature);
        assert_eq!(story.arguments[0], nation_mask_arg(1i32.wrapping_shl(999)));
    }

    #[test]
    fn newspaper_construction_does_not_own_the_turn_phase() {
        let mut state = game_state();
        state.turn.phase = PhaseCode::RETURN_TO_MAP;
        state
            .pending
            .queue_newspaper_event(PendingNewspaperEvent::Miscellaneous {
                audience: None,
                story_code: 3,
            });
        state.set_game_data(filler_catalog());
        state.construct_newspaper_pages();
        assert_eq!(state.turn.phase, PhaseCode::RETURN_TO_MAP);
        assert!(state.pending.newspaper_events.is_empty());
        assert!(state.news.pages[MajorNationId::new(0)].is_some());
    }

    #[test]
    fn newspaper_uses_battle_location_participants_and_report_variant() {
        let mut state = game_state();
        state.append_battle_report(BattleReport {
            participant: Some(BattleReportSideSlot::Right),
            displayed_side: BattleReportSideSlot::Left,
            kind: BattleReportKind::LandBattle,
            location: BattleReportLocation::Province(ProvinceId::new(4)),
            sides: BattleReportSideTable::from_array([
                BattleReportSide {
                    nation: MajorNationId::new(1).nation(),
                    children: Vec::new(),
                    task_force_order: None,
                },
                BattleReportSide {
                    nation: MajorNationId::new(2).nation(),
                    children: Vec::new(),
                    task_force_order: None,
                },
            ]),
        });
        let mut ids = vec![1; NEWS_TEMPLATE_COUNT];
        ids[0] = -1003;
        ids[1] = -0x19;
        state.set_game_data(GameData::from_news_story_ids(ids));

        state.construct_newspaper_pages();

        let story = state.news.pages[MajorNationId::new(0)]
            .as_ref()
            .unwrap()
            .stories[0][0]
            .as_ref()
            .unwrap();
        assert_eq!(story.story_id, -0x19);
        assert!(story.feature);
        assert_eq!(
            story.arguments,
            [
                NewsArgument::Province {
                    province: ProvinceId::new(4),
                },
                nation_mask_arg(1 << 1),
                nation_mask_arg(1 << 2),
                NewsArgument::Empty,
            ]
        );
    }
}
