use crate::*;

const PRESSURE_FLOOR_BY_DIFFICULTY: [i32; 5] = [1_000, 500, 200, 100, 10];
const PRESSURE_MINIMUM_BY_DIFFICULTY: [i16; 5] = [2, 3, 4, 6, 10];
const PRESSURE_DECAY_BY_DIFFICULTY: [i16; 5] = [2, 2, 1, 1, 1];

impl GameState {
    pub(crate) fn supports_first_turn_pressure_phase(&self) -> bool {
        self.turn.phase == PhaseCode::GREAT_POWER_PRESSURE
            && self.turn.economic_turn == 1
            && self.turn.difficulty == Difficulty::Easy
            && self.turn.scenario_map.is_none()
            && self.turn.active_nation == NationId::new(6)
            && self.turn.selected_nation == self.turn.active_nation
            && self
                .nations
                .majors
                .iter()
                .enumerate()
                .all(|(slot, nation)| {
                    nation.economy.controller.is_human() == (slot == 6)
                        && (!nation.economy.controller.is_human() || nation.common.treasury >= 0)
                })
    }

    pub(crate) fn run_first_turn_pressure_phase(&mut self) {
        debug_assert!(self.supports_first_turn_pressure_phase());
        let difficulty = self.turn.difficulty as usize;
        for slot in (0..MajorNationId::COUNT).rev() {
            let nation = MajorNationId::new(slot);
            let state = &mut self.nations.majors[nation];
            if !state.economy.controller.is_human() {
                continue;
            }

            let aid_total = state
                .economy
                .aid_allocation_by_minor_nation
                .iter()
                .flat_map(|row| row.iter())
                .fold(0_i32, |total, (_, amount)| total + amount);
            let base_pressure = (aid_total
                + i32::from(state.economy.need_target_by_type[ResourceKind::Gold]) * 200
                + i32::from(state.economy.need_target_by_type[ResourceKind::Gems]) * 500
                + state.economy.budget_pool_base)
                .max(PRESSURE_FLOOR_BY_DIFFICULTY[difficulty]);
            state.economy.diplomacy_budget_base =
                (state.economy.diplomacy_budget_base * 90 + base_pressure * 1_000) / 100;

            if state.economy.pressure_counter != 0 {
                state.economy.escalation_counter = (state.economy.escalation_counter
                    - PRESSURE_DECAY_BY_DIFFICULTY[difficulty])
                    .max(PRESSURE_MINIMUM_BY_DIFFICULTY[difficulty]);
                state.economy.pressure_counter = 0;
            }
            state.economy.army_movement_budget = 0;
        }
    }

    pub(crate) fn supports_first_turn_deal_book_phase(&self) -> bool {
        self.turn.phase == PhaseCode::DEAL_BOOK
            && self.turn.economic_turn == 1
            && self.turn.difficulty == Difficulty::Easy
            && self.turn.scenario_map.is_none()
            && self.turn.active_nation == NationId::new(6)
            && self.turn.selected_nation == self.turn.active_nation
            && MajorNationId::from_nation(self.turn.active_nation).is_some()
            && !matches!(
                self.nations.country_status(self.turn.active_nation),
                None | Some(CountryStatus::ProtectorateOf(_))
            )
            && self.nations.owned_region_count(self.turn.active_nation) != Some(0)
    }

    pub(crate) fn supports_first_turn_quarter_gate_phase(&self) -> bool {
        if self.turn.phase != PhaseCode::QUARTER_GATE
            || self.turn.economic_turn != 1
            || self.turn.difficulty != Difficulty::Easy
            || self.turn.scenario_map.is_some()
            || self.turn.active_nation != NationId::new(6)
            || self.turn.selected_nation != self.turn.active_nation
            || self.diplomacy.last_processed_nation.is_some()
        {
            return false;
        }
        if self.turn.economic_turn % 40 != 0 {
            return true;
        }
        usize::try_from(self.turn.economic_turn / 40)
            .ok()
            .and_then(|index| self.turn.quarter_gate_by_decade.get(index))
            == Some(&0)
    }

    pub(crate) fn supports_first_turn_season_advance_phase(&self) -> bool {
        self.turn.phase == PhaseCode::SEASON_ADVANCE
            && self.turn.economic_turn == 1
            && self.turn.difficulty == Difficulty::Easy
            && self.turn.scenario_map.is_none()
            && self.turn.active_nation == NationId::new(6)
            && self.turn.selected_nation == self.turn.active_nation
    }

    pub(crate) fn supports_first_turn_technology_phase(&self) -> bool {
        self.turn.phase == PhaseCode::TECHNOLOGY_ADVANCES
            && self.turn.economic_turn == 2
            && self.turn.difficulty == Difficulty::Easy
            && self.turn.scenario_map.is_none()
            && self.turn.active_nation == NationId::new(6)
            && self.turn.selected_nation == self.turn.active_nation
            && self
                .technology
                .scheduled_unlock_turn_by_technology
                .iter()
                .all(|turn| i32::from(*turn) != self.turn.economic_turn)
            && self
                .technology
                .research_status_by_nation
                .iter()
                .flatten()
                .all(|status| *status != TechnologyResearchStatus::Pending)
    }

    pub(crate) fn supports_first_turn_map_return_phase(&self) -> bool {
        self.turn.phase == PhaseCode::RETURN_TO_MAP
            && self.turn.economic_turn == 2
            && self.turn.difficulty == Difficulty::Easy
            && self.turn.scenario_map.is_none()
            && self.turn.active_nation == NationId::new(6)
            && self.turn.selected_nation == self.turn.active_nation
            && MajorNationId::from_nation(self.turn.active_nation).is_some()
            && self.pending.nations.iter().all(|pending| {
                pending.turn_events.is_empty() && pending.turn_start_events.is_empty()
            })
    }

    pub(crate) fn run_first_turn_map_return_phase(&mut self) {
        debug_assert!(self.supports_first_turn_map_return_phase());
        for pending in self.pending.nations.iter_mut() {
            pending.turn_events.clear();
            pending.turn_start_events.clear();
        }
        // `ResetDualAudioCuePools` installs cues 2 and 3; the first synchronous
        // selection consumes one VC5 CRT draw before the strategic map opens.
        self.rng.next_crt_rand();
    }
}
