use crate::*;

const NEWS_STORY_IDS: [i16; NEWS_TEMPLATE_COUNT] = [
    -25, -26, -27, -28, -20, -21, -1000, 11, 12, 13, 14, 15, 21, 22, 23, 24, 25, -12, -10, -11, -9,
    -51, -52, -53, -54, -55, -56, -57, -58, -60, -102, -103, -104, -105, -106, -107, -108, -109,
    -110, -111, -112, -113, -114, -101, -100, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 30,
    40, 1, 1, 1, 50, 50, 20, 20, 10, 60, 20, 1, 1, 1, 1, 1, 20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 10, 10,
    10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 20, 20, 20,
    20, 20, 20, 10, 20, 20, 20, 20, 20, 20, 20, 10, 20, 20, 20, 20, 30, 30, 30, 30, 30, 30, 30, 30,
    20, 30, 30, 30, 30, 20, 30, 20, 30, 30, 30, 40, 40, 40, 40, 30, 40, 40, 40, 40, 30, 40, 40, 40,
    40, 40, 40, 40, 40, 40, 40, 40, 40, 40, -1103, -118, -119, -120, -121, 50, 50, 50, 50, 50, 50,
    50, 50, 50, 50, 50, 40, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, -1104,
    -1105, -1106, -1107, -1108, -1109, -1110, -1111, -1112, -1113, -1114, -1115, -1116, -1117,
    -1118, -1119, -1120, -1121, -1122, -1123, -1124, -1125, -1126, -1127, -1128, -1001, -1002, 30,
    60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60,
    60, 60, 60, 60, 70, 70, 70, 70, 70, 70, 70, 70, 70, 70, 70, 70, 70, 70, 70, 70, 70, 70, 70, 70,
    70, 70, 70, 70, 70, 70, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 80,
    80, 80, 80, 80, 80, 80, 80, 80, 80, 80, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90,
    90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 90, 60, -125,
    -126, -127, -128, -122, -123, -124, -129, 1,
];

impl PendingWorkState {
    /// Retail's shared news list places a newly copied record at the front for
    /// the observed phase-six producer path. Newspaper selection traverses this
    /// stored order, so the semantic queue must preserve that LIFO behavior.
    pub(crate) fn queue_newspaper_event(&mut self, event: PendingNewspaperEvent) {
        self.newspaper_events.insert(0, event);
    }
}

impl GameState {
    pub(crate) fn supports_first_turn_newspaper_phase(&self) -> bool {
        let Some(active) = MajorNationId::from_nation(self.turn.active_nation) else {
            return false;
        };
        self.turn.phase == PhaseCode::NEWSPAPER
            && self.turn.economic_turn == 2
            && self.turn.difficulty == Difficulty::Easy
            && self.turn.scenario_map.is_none()
            && self.turn.selected_nation == self.turn.active_nation
            && self
                .nations
                .majors
                .iter()
                .enumerate()
                .all(|(index, nation)| {
                    nation.economy.controller.is_human() == (index == usize::from(active.get()))
                })
            && self.news.pages.iter().all(Option::is_none)
            && self
                .news
                .last_used_turn_by_nation_and_template
                .iter()
                .all(|history| {
                    history.len() == NEWS_TEMPLATE_COUNT && history.iter().all(|tick| *tick == 0)
                })
            && self.pending.newspaper_events.len() == 5
            && self.pending.newspaper_events.iter().all(|event| {
                matches!(
                    event,
                    PendingNewspaperEvent::InterNation {
                        event: InterNationNewsKind::TradeConsulateEstablished,
                        subject,
                        related_nations,
                    } if *subject != active && !related_nations[active.nation()]
                )
            })
    }

    /// Mirrors the filler-story branch of `TNewspaperMgr::StartNewsPhase` for
    /// the first loaded Easy turn. Event stories do not target the active
    /// nation in this boundary, so retail fills its complete 3x3 page from
    /// NEWS.TAB and clears the shared event queue afterward.
    pub(crate) fn run_first_turn_newspaper_phase(&mut self) {
        debug_assert!(self.supports_first_turn_newspaper_phase());
        let active = MajorNationId::from_nation(self.turn.active_nation)
            .expect("the supported newspaper phase has an active major nation");
        let history = &mut self.news.last_used_turn_by_nation_and_template[active];
        let mut order = std::array::from_fn::<_, NEWS_TEMPLATE_COUNT, _>(|index| index);
        for first in 0..NEWS_TEMPLATE_COUNT {
            for second in first + 1..NEWS_TEMPLATE_COUNT {
                if history[order[second]] < history[order[first]] {
                    order.swap(first, second);
                }
            }
        }

        let mut page = NewsPage::default();
        let mut column = 0;
        let mut row = 0;
        let mut misses = 0;
        while row < 3 && misses < 4 {
            let template_index = loop {
                let first = self.rng.next_crt_rand() as usize % NEWS_TEMPLATE_COUNT;
                let second = self.rng.next_crt_rand() as usize % NEWS_TEMPLATE_COUNT;
                let candidate = order[first.min(second)];
                if NEWS_STORY_IDS[candidate] >= 0 {
                    break candidate;
                }
            };

            if history[template_index] == self.turn.economic_turn as i16 {
                misses += 1;
                continue;
            }
            let story_id = NEWS_STORY_IDS[template_index];
            let current_period = self.turn.economic_turn / 4;
            if story_id != 1
                && (story_id <= 0
                    || story_id % 10 != 0
                    || current_period < i32::from(story_id - 10)
                    || current_period >= i32::from(story_id))
            {
                continue;
            }

            let other = loop {
                let nation = MajorNationId::new(
                    (self.rng.next_crt_rand() as usize % usize::from(MajorNationId::COUNT)) as u8,
                );
                if nation != active {
                    break nation;
                }
            };
            let mut active_mask = NationTable::default();
            active_mask[active.nation()] = true;
            let mut other_mask = NationTable::default();
            other_mask[other.nation()] = true;
            page.stories[column][row] = Some(NewsStory {
                template_index: template_index as u16,
                story_id,
                feature: true,
                arguments: [
                    NewsArgument::NationMask {
                        nations: active_mask,
                    },
                    NewsArgument::NationMask {
                        nations: other_mask,
                    },
                    NewsArgument::Empty,
                    NewsArgument::Empty,
                ],
            });
            history[template_index] = self.turn.economic_turn as i16;
            misses = 0;
            column += 1;
            if column == 3 {
                column = 0;
                row += 1;
            }
        }

        self.news.pages[active] = Some(page);
        self.pending.newspaper_events.clear();
    }
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

    #[test]
    fn first_loaded_newspaper_matches_the_retail_page_and_rng_boundary() {
        let mut state = crate::test_support::game_state();
        state.turn.phase = PhaseCode::NEWSPAPER;
        state.turn.economic_turn = 2;
        state.turn.active_nation = NationId::new(6);
        state.turn.selected_nation = NationId::new(6);
        state.rng.crt_rand = RetailCrtRng::from_state(3_402_906_104);
        for slot in 0..MajorNationId::COUNT {
            state.nations.majors[MajorNationId::new(slot)]
                .economy
                .controller = if slot == 6 {
                MajorNationController::Human
            } else {
                MajorNationController::Computer
            };
        }
        state.pending.newspaper_events = [5, 4, 3, 1, 0]
            .into_iter()
            .map(|subject| PendingNewspaperEvent::InterNation {
                event: InterNationNewsKind::TradeConsulateEstablished,
                subject: MajorNationId::new(subject),
                related_nations: NationTable::default(),
            })
            .collect();

        assert!(state.supports_first_turn_newspaper_phase());
        state.run_first_turn_newspaper_phase();

        let active = MajorNationId::new(6);
        let page = state.news.pages[active].as_ref().unwrap();
        let expected_templates = [82, 84, 80, 81, 88, 60, 76, 57, 59];
        let expected_other_nations = [0, 1, 3, 3, 1, 1, 2, 4, 0];
        for (position, (&template, &other)) in expected_templates
            .iter()
            .zip(&expected_other_nations)
            .enumerate()
        {
            let story = page.stories[position % 3][position / 3].as_ref().unwrap();
            assert_eq!(story.template_index, template);
            assert_eq!(story.story_id, if template == 88 { 10 } else { 1 });
            let mut active_mask = NationTable::default();
            active_mask[active.nation()] = true;
            let mut other_mask = NationTable::default();
            other_mask[NationId::new(other)] = true;
            assert_eq!(
                story.arguments,
                [
                    NewsArgument::NationMask {
                        nations: active_mask,
                    },
                    NewsArgument::NationMask {
                        nations: other_mask,
                    },
                    NewsArgument::Empty,
                    NewsArgument::Empty,
                ]
            );
        }
        assert_eq!(state.rng.crt_rand.state(), 3_870_612_230);
        assert!(state.pending.newspaper_events.is_empty());
        assert_eq!(
            state.news.last_used_turn_by_nation_and_template[active]
                .iter()
                .filter(|tick| **tick == 2)
                .count(),
            9
        );
    }
}
