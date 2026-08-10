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
            || self.phase.retail() >= crate::PhaseCode::DIPLOMACY.retail()
    }
}

/// Why turn progression stopped and requires UI or a future phase port.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TurnBlock {
    PlayerOrders,
    Unimplemented { phase: crate::PhaseCode },
}

/// Ordered presentation work emitted by authoritative turn progression.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TurnEffect {
    ShowDiplomacyMap { nation: crate::MajorNationId },
    ShowOfferSheet { nation: crate::MajorNationId },
}

/// Result of advancing the recovered global turn state machine once.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdvanceTurnOutcome {
    Continues {
        from: crate::PhaseCode,
        to: crate::PhaseCode,
        effects: Vec<TurnEffect>,
    },
    Blocked {
        phase: crate::PhaseCode,
        block: TurnBlock,
        effects: Vec<TurnEffect>,
    },
}

impl GameState {
    /// Advance one recoverable turn phase without pretending unported phases completed.
    pub fn advance_turn_step(&mut self) -> AdvanceTurnOutcome {
        let from = self.turn.phase;
        match from {
            crate::PhaseCode::HOME_PLACEMENT => {
                self.turn.phase = crate::PhaseCode::STRATEGIC_MAP;
                AdvanceTurnOutcome::Blocked {
                    phase: crate::PhaseCode::STRATEGIC_MAP,
                    block: TurnBlock::PlayerOrders,
                    effects: Vec::new(),
                }
            }
            crate::PhaseCode::STRATEGIC_MAP if self.turn.economic_turn == 1 => {
                self.turn.phase = crate::PhaseCode::DIPLOMACY;
                AdvanceTurnOutcome::Continues {
                    from,
                    to: crate::PhaseCode::DIPLOMACY,
                    effects: Vec::new(),
                }
            }
            crate::PhaseCode::STRATEGIC_MAP => AdvanceTurnOutcome::Blocked {
                phase: from,
                block: TurnBlock::Unimplemented { phase: from },
                effects: Vec::new(),
            },
            crate::PhaseCode::DIPLOMACY if self.supports_first_turn_diplomacy_phase() => {
                let effects = self.first_turn_diplomacy_effects();
                self.run_diplomacy_phase();
                self.turn.phase = crate::PhaseCode::TRADE;
                AdvanceTurnOutcome::Continues {
                    from,
                    to: crate::PhaseCode::TRADE,
                    effects,
                }
            }
            crate::PhaseCode::TRADE if self.supports_first_turn_trade_phase() => {
                let nation = crate::MajorNationId::from_nation(self.turn.active_nation)
                    .expect("the supported trade phase has an active major nation");
                self.run_trade_phase();
                self.turn.phase = crate::PhaseCode::OFFER_SHEET;
                AdvanceTurnOutcome::Continues {
                    from,
                    to: crate::PhaseCode::OFFER_SHEET,
                    effects: vec![TurnEffect::ShowOfferSheet { nation }],
                }
            }
            crate::PhaseCode::OFFER_SHEET if self.supports_first_turn_civilian_phase() => {
                self.run_civilian_phase();
                self.turn.phase = crate::PhaseCode::MILITARY;
                AdvanceTurnOutcome::Continues {
                    from,
                    to: crate::PhaseCode::MILITARY,
                    effects: Vec::new(),
                }
            }
            crate::PhaseCode::MILITARY if self.supports_first_turn_military_phase() => {
                self.run_first_turn_military_phase();
                self.turn.phase = crate::PhaseCode::COMBAT_MOVES;
                AdvanceTurnOutcome::Continues {
                    from,
                    to: crate::PhaseCode::COMBAT_MOVES,
                    effects: Vec::new(),
                }
            }
            crate::PhaseCode::COMBAT_MOVES
                if self.supports_first_turn_no_combat_movement_phase() =>
            {
                self.run_first_turn_no_combat_movement_phase();
                self.turn.phase = crate::PhaseCode::MILITARY_CLEANUP;
                AdvanceTurnOutcome::Continues {
                    from,
                    to: crate::PhaseCode::MILITARY_CLEANUP,
                    effects: Vec::new(),
                }
            }
            crate::PhaseCode::MILITARY_CLEANUP
                if self.supports_first_turn_military_cleanup_phase() =>
            {
                self.run_first_turn_military_cleanup_phase();
                self.turn.phase = crate::PhaseCode::DIPLOMACY_OFFER;
                AdvanceTurnOutcome::Continues {
                    from,
                    to: crate::PhaseCode::DIPLOMACY_OFFER,
                    effects: Vec::new(),
                }
            }
            crate::PhaseCode::SEASON_ADVANCE => {
                self.turn.phase = crate::PhaseCode::TECHNOLOGY_ADVANCES;
                self.turn.advance_season();
                AdvanceTurnOutcome::Continues {
                    from,
                    to: crate::PhaseCode::TECHNOLOGY_ADVANCES,
                    effects: Vec::new(),
                }
            }
            crate::PhaseCode::NEWSPAPER => AdvanceTurnOutcome::Blocked {
                phase: from,
                block: TurnBlock::Unimplemented { phase: from },
                effects: Vec::new(),
            },
            phase => AdvanceTurnOutcome::Blocked {
                phase,
                block: TurnBlock::Unimplemented { phase },
                effects: Vec::new(),
            },
        }
    }

    pub fn advance_until_blocked(&mut self) -> AdvanceTurnOutcome {
        let mut effects = Vec::new();
        loop {
            match self.advance_turn_step() {
                AdvanceTurnOutcome::Continues {
                    effects: step_effects,
                    ..
                } => effects.extend(step_effects),
                AdvanceTurnOutcome::Blocked {
                    phase,
                    block,
                    effects: step_effects,
                } => {
                    effects.extend(step_effects);
                    return AdvanceTurnOutcome::Blocked {
                        phase,
                        block,
                        effects,
                    };
                }
            }
        }
    }

    pub fn finish_player_orders(&mut self) -> AdvanceTurnOutcome {
        assert_eq!(
            self.turn.phase,
            crate::PhaseCode::STRATEGIC_MAP,
            "player orders can finish only at the strategic-map boundary"
        );
        self.advance_until_blocked()
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
        turn.phase = crate::PhaseCode::DIPLOMACY;
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
    fn advance_until_blocked_stops_at_the_player_order_boundary() {
        let mut state = crate::test_support::game_state();
        state.turn.phase = crate::PhaseCode::HOME_PLACEMENT;

        assert_eq!(
            state.advance_until_blocked(),
            AdvanceTurnOutcome::Blocked {
                phase: crate::PhaseCode::STRATEGIC_MAP,
                block: TurnBlock::PlayerOrders,
                effects: Vec::new(),
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
            AdvanceTurnOutcome::Continues {
                from: crate::PhaseCode::STRATEGIC_MAP,
                to: crate::PhaseCode::DIPLOMACY,
                effects: Vec::new(),
            }
        );
        assert_eq!(state.turn.phase, crate::PhaseCode::DIPLOMACY);
    }

    #[test]
    fn unported_alert_and_newspaper_phases_do_not_advance_state() {
        let mut state = crate::test_support::game_state();
        state.turn.economic_turn = 2;
        for phase in [crate::PhaseCode::STRATEGIC_MAP, crate::PhaseCode::NEWSPAPER] {
            state.turn.phase = phase;
            assert_eq!(
                state.advance_turn_step(),
                AdvanceTurnOutcome::Blocked {
                    phase,
                    block: TurnBlock::Unimplemented { phase },
                    effects: Vec::new(),
                }
            );
            assert_eq!(state.turn.phase, phase);
        }
    }

    #[test]
    fn first_turn_diplomacy_phase_advances_to_trade() {
        let mut state = crate::test_support::game_state();
        state.turn.economic_turn = 1;
        state.turn.phase = crate::PhaseCode::DIPLOMACY;

        assert_eq!(
            state.advance_turn_step(),
            AdvanceTurnOutcome::Continues {
                from: crate::PhaseCode::DIPLOMACY,
                to: crate::PhaseCode::TRADE,
                effects: Vec::new(),
            }
        );
        assert_eq!(state.turn.phase, crate::PhaseCode::TRADE);
    }

    #[test]
    fn advance_until_blocked_preserves_the_diplomacy_map_effect() {
        let mut state = crate::test_support::game_state();
        state.turn.economic_turn = 1;
        state.turn.phase = crate::PhaseCode::DIPLOMACY;
        state.civilian_units.push(crate::CivilianUnitState {
            id: crate::CivilianUnitId::new(1),
            nation: crate::NationId::new(0),
            unit_type: crate::CivilianUnitKind::Miner,
            location: crate::CivilianLocation::OnMap(crate::TileId::new(0)),
            order: crate::CivilianWorkOrder::Idle,
            owner_nation: crate::NationId::new(0),
            roster_id: 0,
            registered: false,
        });

        assert_eq!(
            state.advance_until_blocked(),
            AdvanceTurnOutcome::Blocked {
                phase: crate::PhaseCode::TRADE,
                block: TurnBlock::Unimplemented {
                    phase: crate::PhaseCode::TRADE,
                },
                effects: vec![TurnEffect::ShowDiplomacyMap {
                    nation: crate::MajorNationId::new(0),
                }],
            }
        );
    }

    #[test]
    fn diplomacy_work_that_needs_ui_does_not_partially_advance_state() {
        let mut state = crate::test_support::game_state();
        state.turn.economic_turn = 1;
        state.turn.phase = crate::PhaseCode::DIPLOMACY;
        state.pending.nations[crate::MajorNationId::new(6)]
            .proposals
            .push(crate::DiplomacyProposal {
                source: crate::NationId::new(0),
                policy: crate::DiplomacyPolicy::Alliance,
            });
        let before = state.clone();

        assert_eq!(
            state.advance_turn_step(),
            AdvanceTurnOutcome::Blocked {
                phase: crate::PhaseCode::DIPLOMACY,
                block: TurnBlock::Unimplemented {
                    phase: crate::PhaseCode::DIPLOMACY,
                },
                effects: Vec::new(),
            }
        );
        assert_eq!(state, before);
    }
}
