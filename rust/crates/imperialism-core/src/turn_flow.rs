use crate::{GameState, TurnState};
use serde::{Deserialize, Serialize};

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
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum TurnBlock {
    PlayerOrders,
    Ui(UiGate),
    Unsupported { phase: crate::PhaseCode },
}

/// Retail screens that can be exposed by global turn progression.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UiGate {
    DiplomacyMap,
    OfferSheet,
    Combat,
    DiplomacyOffer,
    DealBook,
    TechnologyAdvance,
    Newspaper,
    TurnAlert,
}

/// Result of resolving one recovered global turn phase.
///
/// A `visible_ui` on `Continues` is displayed by retail without waiting for
/// player intervention. UI that does wait is represented by
/// `Blocked { block: TurnBlock::Ui(_) }`.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TurnPhaseOutcome {
    Continues {
        from: crate::PhaseCode,
        to: crate::PhaseCode,
        visible_ui: Option<UiGate>,
    },
    Blocked {
        phase: crate::PhaseCode,
        block: TurnBlock,
    },
}

impl GameState {
    /// Advance one recoverable turn phase without pretending unported phases completed.
    pub fn advance_turn_step(&mut self) -> TurnPhaseOutcome {
        let from = self.turn.phase;
        match from.retail() {
            4 => {
                self.turn.phase = crate::PhaseCode::STRATEGIC_MAP;
                TurnPhaseOutcome::Blocked {
                    phase: crate::PhaseCode::STRATEGIC_MAP,
                    block: TurnBlock::PlayerOrders,
                }
            }
            5 if self.turn.economic_turn == 1 => {
                self.turn.phase = crate::PhaseCode::TURN;
                TurnPhaseOutcome::Continues {
                    from,
                    to: crate::PhaseCode::TURN,
                    visible_ui: None,
                }
            }
            5 => TurnPhaseOutcome::Blocked {
                phase: from,
                block: TurnBlock::Unsupported { phase: from },
            },
            6 => self.resolve_diplomacy_phase(),
            0x10 => {
                self.turn.phase = crate::PhaseCode::from_retail(0x11);
                self.turn.advance_season();
                TurnPhaseOutcome::Continues {
                    from,
                    to: self.turn.phase,
                    visible_ui: None,
                }
            }
            0x12 => TurnPhaseOutcome::Blocked {
                phase: from,
                block: TurnBlock::Unsupported { phase: from },
            },
            _ => TurnPhaseOutcome::Blocked {
                phase: from,
                block: TurnBlock::Unsupported { phase: from },
            },
        }
    }

    /// Advance across silent phases until retail exposes UI or progression
    /// blocks for input or an unsupported phase.
    pub fn advance_until_boundary(&mut self) -> TurnPhaseOutcome {
        loop {
            match self.advance_turn_step() {
                TurnPhaseOutcome::Continues {
                    visible_ui: None, ..
                } => continue,
                boundary => return boundary,
            }
        }
    }

    pub fn finish_player_orders(&mut self) -> TurnPhaseOutcome {
        assert_eq!(
            self.turn.phase,
            crate::PhaseCode::STRATEGIC_MAP,
            "player orders can finish only at the strategic-map boundary"
        );
        self.advance_until_boundary()
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
            diplomacy_year_term_raw: 1914,
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

    #[test]
    fn advance_until_boundary_stops_at_the_player_order_boundary() {
        let mut state = crate::test_support::game_state();
        state.turn.phase = crate::PhaseCode::HOME_PLACEMENT;

        assert_eq!(
            state.advance_until_boundary(),
            TurnPhaseOutcome::Blocked {
                phase: crate::PhaseCode::STRATEGIC_MAP,
                block: TurnBlock::PlayerOrders,
            }
        );
        assert_eq!(state.turn.phase, crate::PhaseCode::STRATEGIC_MAP);
    }

    #[test]
    fn first_turn_alert_phase_advances_without_alerts() {
        let mut state = crate::test_support::game_state();
        state.turn.economic_turn = 1;
        state.turn.phase = crate::PhaseCode::STRATEGIC_MAP;

        assert_eq!(
            state.advance_turn_step(),
            TurnPhaseOutcome::Continues {
                from: crate::PhaseCode::STRATEGIC_MAP,
                to: crate::PhaseCode::TURN,
                visible_ui: None,
            }
        );
        assert_eq!(state.turn.phase, crate::PhaseCode::TURN);
    }

    #[test]
    fn unported_alert_and_newspaper_phases_do_not_advance_state() {
        let mut state = crate::test_support::game_state();
        state.turn.economic_turn = 2;
        for phase in [5, 0x12] {
            state.turn.phase = crate::PhaseCode::from_retail(phase);
            assert_eq!(
                state.advance_turn_step(),
                TurnPhaseOutcome::Blocked {
                    phase: crate::PhaseCode::from_retail(phase),
                    block: TurnBlock::Unsupported {
                        phase: crate::PhaseCode::from_retail(phase),
                    },
                }
            );
            assert_eq!(state.turn.phase.retail(), phase);
        }
    }

    #[test]
    fn unsupported_diplomacy_branch_does_not_advance_state() {
        let mut state = crate::test_support::game_state();
        state.turn.economic_turn = 1;
        state.turn.phase = crate::PhaseCode::TURN;

        assert_eq!(
            state.advance_turn_step(),
            TurnPhaseOutcome::Blocked {
                phase: crate::PhaseCode::TURN,
                block: TurnBlock::Unsupported {
                    phase: crate::PhaseCode::TURN,
                },
            }
        );
        assert_eq!(state.turn.phase, crate::PhaseCode::TURN);
    }
}
