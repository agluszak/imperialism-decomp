use crate::{GameState, TurnState};

impl TurnState {
    /// Mirrors `TSimMgr::AdvanceSeason`.
    pub fn advance_season(&mut self) {
        self.economic_turn += 1;
    }

    /// Mirrors `TSimMgr::InLinearPhase` exactly, including unknown phase codes.
    pub const fn in_linear_phase(self) -> bool {
        self.phase.retail() <= crate::PhaseCode::PRE_MAP.retail()
            || self.phase.retail() >= crate::PhaseCode::TURN.retail()
    }
}


/// Why turn progression stopped and requires UI or a future phase port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnBlock {
    PlayerOrders,
    Unimplemented { phase: i32 },
}

/// Result of advancing the recovered global turn state machine once.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdvanceTurnOutcome {
    Continues { from: i32, to: i32 },
    Blocked { phase: i32, block: TurnBlock },
}

impl GameState {
    /// Advance one recoverable turn phase without pretending unported phases completed.
    pub fn advance_turn_step(&mut self) -> AdvanceTurnOutcome {
        let from = self.turn.phase.retail();
        match from {
            4 => {
                self.turn.phase = crate::PhaseCode::STRATEGIC_MAP;
                AdvanceTurnOutcome::Blocked { phase: 5, block: TurnBlock::PlayerOrders }
            }
            5 => {
                self.turn.phase = crate::PhaseCode::TURN;
                AdvanceTurnOutcome::Blocked { phase: 6, block: TurnBlock::Unimplemented { phase: 6 } }
            }
            0x10 => {
                self.turn.phase = crate::PhaseCode::from_retail(0x11);
                self.turn.advance_season();
                AdvanceTurnOutcome::Continues { from, to: 0x11 }
            }
            0x12 => {
                self.turn.phase = crate::PhaseCode::STRATEGIC_MAP;
                AdvanceTurnOutcome::Blocked { phase: 5, block: TurnBlock::PlayerOrders }
            }
            phase => AdvanceTurnOutcome::Blocked { phase, block: TurnBlock::Unimplemented { phase } },
        }
    }

    pub fn advance_until_blocked(&mut self) -> AdvanceTurnOutcome {
        loop {
            match self.advance_turn_step() {
                AdvanceTurnOutcome::Continues { .. } => continue,
                blocked => return blocked,
            }
        }
    }

    pub fn finish_player_orders(&mut self) -> AdvanceTurnOutcome {
        if self.turn.phase == crate::PhaseCode::STRATEGIC_MAP {
            self.advance_until_blocked()
        } else {
            let phase = self.turn.phase.retail();
            AdvanceTurnOutcome::Blocked { phase, block: TurnBlock::Unimplemented { phase } }
        }
    }

    pub fn resume_after_offer_sheet(&mut self) -> AdvanceTurnOutcome { self.resume_after_phase(9) }
    pub fn resume_after_deal_book(&mut self) -> AdvanceTurnOutcome { self.resume_after_phase(0xe) }
    pub fn resume_after_newspaper(&mut self) -> AdvanceTurnOutcome { self.resume_after_phase(0x12) }

    fn resume_after_phase(&mut self, expected: i32) -> AdvanceTurnOutcome {
        let phase = self.turn.phase.retail();
        if phase == expected { self.advance_until_blocked() }
        else { AdvanceTurnOutcome::Blocked { phase, block: TurnBlock::Unimplemented { phase } } }
    }
}

impl GameState {
    /// Mirrors `TSimMgr::AllHumansFinished` across all seven major nations.
    pub fn all_humans_finished(&self) -> bool {
        self.nations
            .majors
            .iter()
            .all(|nation| nation.economy.turn_finished)
    }

    /// Mirrors `TSimMgr::ResetTurnFlags`: only diplomacy-eligible major nations
    /// have their completion flag cleared.
    pub fn reset_turn_flags(&mut self) {
        for major in self.nations.majors.iter_mut() {
            reset_finished_flag(
                major.economy.controller.is_human(),
                &mut major.economy.turn_finished,
            );
        }
    }
}

fn reset_finished_flag(eligible: bool, finished: &mut bool) {
    if eligible {
        *finished = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Difficulty, NationId};

    #[test]
    fn advances_the_season_and_classifies_linear_phases() {
        let mut turn = TurnState {
            scenario_map: None,
            economic_turn: 2,
            phase: crate::PhaseCode::HOME_PLACEMENT,
            difficulty: Difficulty::Easy,
            active_nation: NationId::new(6),
            selected_nation: NationId::new(6),
        };
        turn.advance_season();
        assert_eq!(turn.economic_turn, 3);
        assert!(!turn.in_linear_phase());
        turn.phase = crate::PhaseCode::PRE_MAP;
        assert!(turn.in_linear_phase());
        turn.phase = crate::PhaseCode::TURN;
        assert!(turn.in_linear_phase());
    }

    #[test]
    fn resets_only_eligible_nation_flags() {
        let mut eligible = true;
        let mut ineligible = true;
        reset_finished_flag(true, &mut eligible);
        reset_finished_flag(false, &mut ineligible);
        assert!(!eligible);
        assert!(ineligible);
    }
}
