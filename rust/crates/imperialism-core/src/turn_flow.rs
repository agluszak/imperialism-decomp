use crate::{
    Difficulty, DiplomacyOfferPrompt, DiplomacyPhaseResult, DiplomacyWarJoinPrompt, GameState,
    MajorNationId, NationId, PendingTradeOffer, TechnologyId, TradeProgress,
};
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
    /// Process-local last tick that showed turn alerts. Not stored in `.imp`.
    #[serde(default)]
    pub last_turn_alert_tick: i32,
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
            last_turn_alert_tick: 0,
        }
    }

    pub const fn phase(self) -> PhaseCode {
        self.phase
    }

    /// `abs(economicTurn) % 4`, the quarter index used to stagger AI diplomacy planning.
    pub(crate) const fn planning_quarter(self) -> u32 {
        self.economic_turn.unsigned_abs() % 4
    }

    /// `economicTurn / 4`, the year-quarter count diplomacy scoring reads.
    pub(crate) const fn year_quarters(self) -> i32 {
        self.economic_turn / 4
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
    pub const TOP_TEN_SCORES: Self = Self(0x16);
    pub const OPENING_CINEMATIC: Self = Self(0x17);
    pub const ELIMINATION: Self = Self(0x19);
    pub const fn from_retail(value: i32) -> Self {
        Self(value)
    }
    pub const fn retail(self) -> i32 {
        self.0
    }
}

/// Where the core turn driver stopped for presentation or an unported phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnStop {
    PlayerOrders,
    DiplomacyOffer(DiplomacyOfferPrompt),
    DiplomacyWarJoin(DiplomacyWarJoinPrompt),
    TradeOffer(PendingTradeOffer),
    TechnologyAdvance(TechnologyId),
    Newspaper,
    Unimplemented(PhaseCode),
}

/// Authoritative runtime resume state for an interruptible phase.
///
/// Included in semantic `GameState` serialization. The `.imp` writer omits it
/// because retail cannot save at these transient boundaries.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub enum TurnContinuation {
    #[default]
    None,
    DiplomacyOffer {
        nation: MajorNationId,
        index: u8,
    },
    DiplomacyWarJoin(DiplomacyWarJoinPrompt),
    Trade(crate::TradeSession),
    TechnologyReport(TechnologyId),
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

impl GameState {
    /// Ends player orders on the strategic map and runs the turn until the next stop.
    pub fn finish_player_orders(&mut self) -> TurnStop {
        assert_eq!(self.turn.phase(), PhaseCode::STRATEGIC_MAP);
        self.turn.phase = PhaseCode::DIPLOMACY;
        self.advance_turn()
    }

    /// Accepts or rejects the diplomacy offer stored in the current continuation.
    pub fn answer_current_diplomacy_offer(&mut self, accept: bool) -> TurnStop {
        let result = self.resolve_diplomacy_offer(accept);
        if let Some(stop) = self.stop_from_diplomacy(result) {
            return stop;
        }
        self.turn.phase = PhaseCode::TRADE;
        self.advance_turn()
    }

    /// Accepts or rejects the war-join dialog stored in the current continuation.
    pub fn answer_current_diplomacy_war_join(&mut self, accept: bool) -> TurnStop {
        let result = self.resolve_diplomacy_war_join(accept);
        if let Some(stop) = self.stop_from_diplomacy(result) {
            return stop;
        }
        self.turn.phase = PhaseCode::TRADE;
        self.advance_turn()
    }

    /// Applies the Offer Sheet decision and resumes ranked trade deals.
    pub fn answer_trade_offer(&mut self, quantity: i16, stop_buying: bool) -> TurnStop {
        match self.reply_to_trade_offer(quantity, stop_buying) {
            TradeProgress::Offer(offer) => TurnStop::TradeOffer(offer),
            TradeProgress::Complete => {
                self.turn.phase = PhaseCode::OFFER_SHEET;
                self.advance_turn()
            }
        }
    }

    /// Dismisses the technology report and continues the turn.
    pub fn acknowledge_technology_report(&mut self) -> TurnStop {
        assert!(
            matches!(self.continuation, TurnContinuation::TechnologyReport(_)),
            "technology report answer requires an active technology continuation"
        );
        self.continuation = TurnContinuation::None;
        if let Some(tech_id) = self.consume_interactive_technology_unlock() {
            self.continuation = TurnContinuation::TechnologyReport(tech_id);
            return TurnStop::TechnologyAdvance(tech_id);
        }
        self.turn.phase = PhaseCode::NEWSPAPER;
        self.advance_turn()
    }

    /// Dismisses the newspaper and returns to player orders.
    pub fn close_newspaper(&mut self) -> TurnStop {
        assert_eq!(self.turn.phase(), PhaseCode::NEWSPAPER);
        self.finish_newspaper_phase();
        TurnStop::PlayerOrders
    }

    pub fn current_diplomacy_offer(&self) -> Option<DiplomacyOfferPrompt> {
        let TurnContinuation::DiplomacyOffer { nation, index } = self.continuation else {
            return None;
        };
        let proposal = self.pending.nations[nation]
            .proposals
            .get(usize::from(index))?;
        Some(DiplomacyOfferPrompt {
            nation,
            index,
            source: proposal.source,
            policy: proposal.policy,
        })
    }

    pub fn current_diplomacy_war_join(&self) -> Option<DiplomacyWarJoinPrompt> {
        match self.continuation {
            TurnContinuation::DiplomacyWarJoin(prompt) => Some(prompt),
            _ => None,
        }
    }

    pub fn current_technology_report(&self) -> Option<TechnologyId> {
        match self.continuation {
            TurnContinuation::TechnologyReport(tech_id) => Some(tech_id),
            _ => None,
        }
    }

    pub(crate) fn advance_turn(&mut self) -> TurnStop {
        loop {
            match self.turn.phase() {
                PhaseCode::STRATEGIC_MAP => return TurnStop::PlayerOrders,
                PhaseCode::DIPLOMACY => match self.continuation {
                    TurnContinuation::DiplomacyOffer { .. } => {
                        return TurnStop::DiplomacyOffer(
                            self.current_diplomacy_offer()
                                .expect("diplomacy offer continuation"),
                        );
                    }
                    TurnContinuation::DiplomacyWarJoin(prompt) => {
                        return TurnStop::DiplomacyWarJoin(prompt);
                    }
                    _ => {
                        if let Some(stop) = self.stop_from_diplomacy(self.do_diplomacy()) {
                            return stop;
                        }
                        self.turn.phase = PhaseCode::TRADE;
                    }
                },
                PhaseCode::TRADE => {
                    if let Some(offer) = self.pending_trade_offer() {
                        return TurnStop::TradeOffer(offer);
                    }
                    match self.begin_trade_phase() {
                        TradeProgress::Offer(offer) => return TurnStop::TradeOffer(offer),
                        TradeProgress::Complete => {
                            self.turn.phase = PhaseCode::OFFER_SHEET;
                        }
                    }
                }
                PhaseCode::CITY_AND_TRANSPORT => {
                    self.do_city_and_transport();
                    self.turn.phase = PhaseCode::GREAT_POWER_PRESSURE;
                }
                PhaseCode::SEASON_ADVANCE => {
                    self.turn.advance_season();
                    self.turn.phase = PhaseCode::TECHNOLOGY_ADVANCES;
                }
                PhaseCode::TECHNOLOGY_ADVANCES => {
                    if let Some(stop) = self.run_technology_advances() {
                        return stop;
                    }
                    self.turn.phase = PhaseCode::NEWSPAPER;
                }
                PhaseCode::NEWSPAPER => return TurnStop::Newspaper,
                phase => return TurnStop::Unimplemented(phase),
            }
        }
    }

    fn stop_from_diplomacy(&self, result: DiplomacyPhaseResult) -> Option<TurnStop> {
        match result {
            DiplomacyPhaseResult::Resolved => None,
            DiplomacyPhaseResult::Offer(prompt) => Some(TurnStop::DiplomacyOffer(prompt)),
            DiplomacyPhaseResult::WarJoin(prompt) => Some(TurnStop::DiplomacyWarJoin(prompt)),
        }
    }

    fn run_technology_advances(&mut self) -> Option<TurnStop> {
        self.check_technology_advances();
        self.consume_non_interactive_technology_unlocks();
        let tech_id = self.consume_interactive_technology_unlock()?;
        self.continuation = TurnContinuation::TechnologyReport(tech_id);
        Some(TurnStop::TechnologyAdvance(tech_id))
    }

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
                major.economy.diplomacy_eligible,
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
    use crate::test_support::game_state;
    use crate::{
        DiplomacyPolicy, DiplomaticRelationship, MajorNationController, MajorNationId,
        TradeProgress,
    };

    #[test]
    fn reset_turn_flags_follows_diplomacy_eligibility_not_controller() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        {
            let economy = &mut state.nations.majors[nation].economy;
            economy.controller = MajorNationController::Human;
            economy.diplomacy_eligible = false;
            economy.turn_finished = true;
        }
        state.reset_turn_flags();
        assert!(
            state.nations.majors[nation].economy.turn_finished,
            "ineligible nations keep their finished flag"
        );

        state.nations.majors[nation].economy.diplomacy_eligible = true;
        state.reset_turn_flags();
        assert!(!state.nations.majors[nation].economy.turn_finished);
    }

    #[test]
    fn finish_player_orders_runs_until_an_unimplemented_or_interactive_stop() {
        let mut state = game_state();
        let stop = state.finish_player_orders();
        assert!(
            matches!(
                stop,
                crate::TurnStop::DiplomacyOffer(_)
                    | crate::TurnStop::DiplomacyWarJoin(_)
                    | crate::TurnStop::TradeOffer(_)
                    | crate::TurnStop::Unimplemented(_)
            ),
            "unexpected stop {stop:?}"
        );
        assert_ne!(state.turn.phase(), crate::PhaseCode::STRATEGIC_MAP);
    }

    #[test]
    fn answering_a_diplomacy_offer_uses_core_continuation_not_the_prompt() {
        let mut state = game_state();
        state.nations.majors[MajorNationId::new(1)].kind = crate::MajorNationKind::AutoGreatPower;
        state.nations.majors[MajorNationId::new(1)]
            .economy
            .controller = MajorNationController::Computer;
        state.nations.majors[MajorNationId::new(1)]
            .economy
            .diplomacy_policy_by_nation[crate::NationId::new(0)] =
            Some(crate::DiplomacyPolicy::Alliance);

        let crate::TurnStop::DiplomacyOffer(prompt) = state.finish_player_orders() else {
            panic!("expected a diplomacy offer stop");
        };
        assert_eq!(state.current_diplomacy_offer(), Some(prompt));
        let stop = state.answer_current_diplomacy_offer(true);
        assert!(state.current_diplomacy_offer().is_none());
        assert!(
            matches!(
                stop,
                crate::TurnStop::TradeOffer(_) | crate::TurnStop::Unimplemented(_)
            ),
            "unexpected stop {stop:?}"
        );
        assert_eq!(
            state.diplomacy.relationships[crate::NationId::new(0)][crate::NationId::new(1)],
            crate::DiplomaticRelationship::Alliance
        );
    }

    #[test]
    fn completing_trade_stops_at_unimplemented_offer_sheet_without_restarting() {
        let mut state = game_state();
        state.turn.phase = crate::PhaseCode::TRADE;
        let mut stop = state.advance_turn();
        while let crate::TurnStop::TradeOffer(_) = stop {
            stop = state.answer_trade_offer(0, false);
        }
        assert_eq!(
            stop,
            crate::TurnStop::Unimplemented(crate::PhaseCode::OFFER_SHEET)
        );
        assert_eq!(state.turn.phase(), crate::PhaseCode::OFFER_SHEET);
        assert!(state.pending_trade_offer().is_none());
    }

    #[test]
    fn semantic_state_round_trips_a_trade_continuation() {
        let mut state = game_state();
        let TradeProgress::Offer(_) = state.begin_trade_phase() else {
            return;
        };
        let encoded = serde_json::to_vec(&state).expect("serialize");
        let restored: crate::GameState = serde_json::from_slice(&encoded).expect("deserialize");
        assert_eq!(restored.pending_trade_offer(), state.pending_trade_offer());
    }
}
