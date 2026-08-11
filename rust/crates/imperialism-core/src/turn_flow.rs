use crate::{CountryStatus, Difficulty, GameState, MajorNationId, MinorNationId, NationId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TurnState {
    pub scenario_map: Option<ScenarioMapId>,
    pub economic_turn: i32,
    /// Raw persisted `TSimMgr` term consumed by diplomacy scaling.
    ///
    /// This is not the 1815-based display calendar.
    pub diplomacy_year_term_raw: i16,
    pub(crate) phase: PhaseCode,
    /// Persisted turn-flow status bits consumed by the alert and technology phases.
    pub turn_flow_status_flags: u32,
    /// Retail's decade-boundary presentation state, indexed by `economic_turn / 40`.
    pub quarter_gate_by_decade: [u8; 10],
    pub difficulty: Difficulty,
    pub active_nation: NationId,
    pub selected_nation: NationId,
}

impl TurnState {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        scenario_map: Option<ScenarioMapId>,
        economic_turn: i32,
        diplomacy_year_term_raw: i16,
        phase: PhaseCode,
        turn_flow_status_flags: u32,
        quarter_gate_by_decade: [u8; 10],
        difficulty: Difficulty,
        active_nation: NationId,
        selected_nation: NationId,
    ) -> Self {
        Self {
            scenario_map,
            economic_turn,
            diplomacy_year_term_raw,
            phase,
            turn_flow_status_flags,
            quarter_gate_by_decade,
            difficulty,
            active_nation,
            selected_nation,
        }
    }

    pub const fn phase(self) -> PhaseCode {
        self.phase
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(transparent)]
pub struct ScenarioMapId(u16);
impl ScenarioMapId {
    pub const fn new(index: u16) -> Self {
        Self(index)
    }

    pub const fn index(self) -> u16 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PhaseCode(i32);
impl PhaseCode {
    pub const CAPITAL_SELECTION: Self = Self(2);
    pub const PRE_MAP: Self = Self(3);
    pub const HOME_PLACEMENT: Self = Self(4);
    pub const STRATEGIC_MAP: Self = Self(5);
    pub const DIPLOMACY: Self = Self(6);
    pub const TRADE: Self = Self(7);
    pub const CITY_AND_TRANSPORT: Self = Self(8);
    pub const GREAT_POWER_PRESSURE: Self = Self(0x0b);
    pub const DEAL_BOOK: Self = Self(0x0c);
    pub const OFFER_SHEET: Self = Self(9);
    pub const MILITARY: Self = Self(10);
    pub const DIPLOMACY_OFFER: Self = Self(0x0d);
    pub const QUARTER_GATE: Self = Self(0x0e);
    pub const NEWSPAPER: Self = Self(0x0f);
    pub const SEASON_ADVANCE: Self = Self(0x10);
    pub const TECHNOLOGY_ADVANCES: Self = Self(0x11);
    pub const RETURN_TO_MAP: Self = Self(0x12);
    pub const COMBAT_MOVES: Self = Self(0x14);
    pub const MILITARY_CLEANUP: Self = Self(0x15);
    pub const ELIMINATION: Self = Self(0x19);
    pub const fn from_retail(value: i32) -> Self {
        Self(value)
    }
    pub const fn retail(self) -> i32 {
        self.0
    }
}

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

/// Why turn progression stopped and requires external input.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FlowStop {
    PlayerOrders,
    Show { screen: GameScreen },
    Unimplemented { phase: crate::PhaseCode },
}

/// Retail turn-flow screens that block until dismissed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GameScreen {
    DealBook,
    Newspaper,
}

/// Ordered presentation work emitted by authoritative turn progression that is not
/// already expressed by [`FlowStop::Show`].
///
/// Diplomacy-map and offer-sheet presentation remain `Continues` effects: retail advances
/// the phase while showing UI, single-step differentials compare these effects, and the
/// EasyTurn end-turn path does not gate on them the way DealBook/Newspaper do. Do not
/// promote them to [`FlowStop::Show`] without changing that oracle contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TurnEffect {
    ShowDiplomacyMap { nation: crate::MajorNationId },
    ShowOfferSheet { nation: crate::MajorNationId },
}

/// Per-step turn transition used by differentials. App code should prefer [`FlowStop`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AdvanceTurnOutcome {
    Continues {
        from: crate::PhaseCode,
        to: crate::PhaseCode,
        effects: Vec<TurnEffect>,
    },
    Blocked {
        stop: FlowStop,
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
                    stop: FlowStop::PlayerOrders,
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
                stop: FlowStop::Unimplemented { phase: from },
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
            crate::PhaseCode::OFFER_SHEET => match self.try_first_turn_civilian_phase() {
                Some(plan) => {
                    self.apply_civilian_phase_plan(plan);
                    self.turn.phase = crate::PhaseCode::MILITARY;
                    AdvanceTurnOutcome::Continues {
                        from,
                        to: crate::PhaseCode::MILITARY,
                        effects: Vec::new(),
                    }
                }
                None => AdvanceTurnOutcome::Blocked {
                    stop: FlowStop::Unimplemented { phase: from },
                    effects: Vec::new(),
                },
            },
            crate::PhaseCode::MILITARY => match self.try_first_turn_military_phase() {
                Some(plan) => {
                    self.apply_military_phase_plan(plan);
                    self.turn.phase = crate::PhaseCode::COMBAT_MOVES;
                    AdvanceTurnOutcome::Continues {
                        from,
                        to: crate::PhaseCode::COMBAT_MOVES,
                        effects: Vec::new(),
                    }
                }
                None => AdvanceTurnOutcome::Blocked {
                    stop: FlowStop::Unimplemented { phase: from },
                    effects: Vec::new(),
                },
            },
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
            crate::PhaseCode::MILITARY_CLEANUP => {
                match self.try_first_turn_military_cleanup_phase() {
                    Some(plan) => {
                        self.apply_military_cleanup_plan(plan);
                        self.turn.phase = crate::PhaseCode::DIPLOMACY_OFFER;
                        AdvanceTurnOutcome::Continues {
                            from,
                            to: crate::PhaseCode::DIPLOMACY_OFFER,
                            effects: Vec::new(),
                        }
                    }
                    None => AdvanceTurnOutcome::Blocked {
                        stop: FlowStop::Unimplemented { phase: from },
                        effects: Vec::new(),
                    },
                }
            }
            crate::PhaseCode::DIPLOMACY_OFFER
                if self.supports_first_turn_diplomacy_offer_phase() =>
            {
                self.turn.phase = crate::PhaseCode::ELIMINATION;
                AdvanceTurnOutcome::Continues {
                    from,
                    to: crate::PhaseCode::ELIMINATION,
                    effects: Vec::new(),
                }
            }
            crate::PhaseCode::ELIMINATION if self.supports_first_turn_no_elimination_phase() => {
                self.turn.phase = crate::PhaseCode::CITY_AND_TRANSPORT;
                AdvanceTurnOutcome::Continues {
                    from,
                    to: crate::PhaseCode::CITY_AND_TRANSPORT,
                    effects: Vec::new(),
                }
            }
            crate::PhaseCode::CITY_AND_TRANSPORT if self.try_first_turn_city_transport_phase() => {
                self.turn.phase = crate::PhaseCode::GREAT_POWER_PRESSURE;
                AdvanceTurnOutcome::Continues {
                    from,
                    to: crate::PhaseCode::GREAT_POWER_PRESSURE,
                    effects: Vec::new(),
                }
            }
            crate::PhaseCode::GREAT_POWER_PRESSURE if self.supports_first_turn_pressure_phase() => {
                self.run_first_turn_pressure_phase();
                self.turn.phase = crate::PhaseCode::DEAL_BOOK;
                AdvanceTurnOutcome::Continues {
                    from,
                    to: crate::PhaseCode::DEAL_BOOK,
                    effects: Vec::new(),
                }
            }
            crate::PhaseCode::DEAL_BOOK if self.supports_first_turn_deal_book_phase() => {
                self.turn.phase = crate::PhaseCode::QUARTER_GATE;
                AdvanceTurnOutcome::Blocked {
                    stop: FlowStop::Show {
                        screen: GameScreen::DealBook,
                    },
                    effects: Vec::new(),
                }
            }
            crate::PhaseCode::QUARTER_GATE if self.supports_first_turn_quarter_gate_phase() => {
                self.turn.phase = crate::PhaseCode::SEASON_ADVANCE;
                AdvanceTurnOutcome::Continues {
                    from,
                    to: crate::PhaseCode::SEASON_ADVANCE,
                    effects: Vec::new(),
                }
            }
            crate::PhaseCode::SEASON_ADVANCE if self.supports_first_turn_season_advance_phase() => {
                self.turn.phase = crate::PhaseCode::TECHNOLOGY_ADVANCES;
                self.turn.turn_flow_status_flags = 0;
                self.turn.advance_season();
                AdvanceTurnOutcome::Continues {
                    from,
                    to: crate::PhaseCode::TECHNOLOGY_ADVANCES,
                    effects: Vec::new(),
                }
            }
            crate::PhaseCode::TECHNOLOGY_ADVANCES
                if self.supports_first_turn_technology_phase() =>
            {
                self.turn.turn_flow_status_flags |= 0x40;
                self.turn.phase = crate::PhaseCode::NEWSPAPER;
                AdvanceTurnOutcome::Continues {
                    from,
                    to: crate::PhaseCode::NEWSPAPER,
                    effects: Vec::new(),
                }
            }
            crate::PhaseCode::NEWSPAPER if self.supports_first_turn_newspaper_phase() => {
                self.run_first_turn_newspaper_phase();
                self.turn.phase = crate::PhaseCode::RETURN_TO_MAP;
                AdvanceTurnOutcome::Blocked {
                    stop: FlowStop::Show {
                        screen: GameScreen::Newspaper,
                    },
                    effects: Vec::new(),
                }
            }
            crate::PhaseCode::RETURN_TO_MAP if self.supports_first_turn_map_return_phase() => {
                self.run_first_turn_map_return_phase();
                self.turn.phase = crate::PhaseCode::STRATEGIC_MAP;
                AdvanceTurnOutcome::Blocked {
                    stop: FlowStop::PlayerOrders,
                    effects: Vec::new(),
                }
            }
            phase => AdvanceTurnOutcome::Blocked {
                stop: FlowStop::Unimplemented { phase },
                effects: Vec::new(),
            },
        }
    }

    /// Advance until the next external boundary (player orders, blocking screen, or unported phase).
    pub fn advance_until_blocked(&mut self) -> AdvanceTurnOutcome {
        let mut effects = Vec::new();
        loop {
            match self.advance_turn_step() {
                AdvanceTurnOutcome::Continues {
                    effects: step_effects,
                    ..
                } => effects.extend(step_effects),
                AdvanceTurnOutcome::Blocked {
                    stop,
                    effects: step_effects,
                } => {
                    effects.extend(step_effects);
                    return AdvanceTurnOutcome::Blocked { stop, effects };
                }
            }
        }
    }

    /// Advance until the next external boundary. App-facing control flow.
    pub fn continue_turn(&mut self) -> FlowStop {
        match self.advance_until_blocked() {
            AdvanceTurnOutcome::Blocked { stop, .. } => stop,
            AdvanceTurnOutcome::Continues { .. } => {
                unreachable!("advance_until_blocked always stops at a boundary")
            }
        }
    }

    pub fn finish_player_orders(&mut self) -> FlowStop {
        assert_eq!(
            self.turn.phase,
            crate::PhaseCode::STRATEGIC_MAP,
            "player orders can finish only at the strategic-map boundary"
        );
        self.continue_turn()
    }

    /// Dismiss the screen implied by the current turn phase and continue.
    ///
    /// The phase already records which blocking screen is open; callers must not
    /// restate that fact as a gate argument.
    pub fn dismiss_blocking_screen(&mut self) -> FlowStop {
        match self.turn.phase {
            crate::PhaseCode::QUARTER_GATE | crate::PhaseCode::RETURN_TO_MAP => {
                self.continue_turn()
            }
            phase => FlowStop::Unimplemented { phase },
        }
    }

    fn supports_first_turn_diplomacy_offer_phase(&self) -> bool {
        self.turn.phase == crate::PhaseCode::DIPLOMACY_OFFER
            && self.turn.economic_turn == 1
            && self.turn.difficulty == crate::Difficulty::Easy
            && self.turn.scenario_map.is_none()
            && self.turn.active_nation == crate::NationId::new(6)
            && self.turn.selected_nation == self.turn.active_nation
            && !self.pending.combat_reports_pending
    }

    fn supports_first_turn_no_elimination_phase(&self) -> bool {
        self.turn.phase == crate::PhaseCode::ELIMINATION
            && self.turn.economic_turn == 1
            && self.turn.difficulty == crate::Difficulty::Easy
            && self.turn.scenario_map.is_none()
            && self.turn.active_nation == crate::NationId::new(6)
            && self.turn.selected_nation == self.turn.active_nation
            && self.supports_no_elimination_topology()
    }

    fn supports_no_elimination_topology(&self) -> bool {
        if MajorNationId::from_nation(self.turn.active_nation).is_none()
            || matches!(
                self.nations.country_status(self.turn.active_nation),
                Some(CountryStatus::ProtectorateOf(_)) | None
            )
            || (0..MajorNationId::COUNT)
                .map(MajorNationId::new)
                .any(|nation| self.nations.owned_region_count(nation.nation()) == Some(0))
            || (MinorNationId::FIRST..NationId::COUNT)
                .map(NationId::new)
                .any(|nation| self.nations.owned_region_count(nation) == Some(0))
        {
            return false;
        }

        (0..MajorNationId::COUNT)
            .map(MajorNationId::new)
            .filter(|nation| {
                !matches!(
                    self.nations.country_status(nation.nation()),
                    Some(CountryStatus::ProtectorateOf(_))
                )
            })
            .count()
            != 1
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

    #[test]
    fn advance_until_blocked_stops_at_the_player_order_boundary() {
        let mut state = crate::test_support::game_state();
        state.turn.phase = crate::PhaseCode::HOME_PLACEMENT;

        assert_eq!(state.continue_turn(), FlowStop::PlayerOrders,);
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
                    stop: FlowStop::Unimplemented { phase },
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
                stop: FlowStop::Unimplemented {
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
                stop: FlowStop::Unimplemented {
                    phase: crate::PhaseCode::DIPLOMACY,
                },
                effects: Vec::new(),
            }
        );
        assert_eq!(state, before);
    }
}
