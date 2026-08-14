use crate::{
    Difficulty, DiplomacyOfferPrompt, DiplomacyPhaseResult, DiplomacyWarJoinPrompt,
    EliminationOutcome, GameState, MajorNationId, NationId, QuarterGateResult, TechnologyId,
    TradeProgress,
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
    /// Process-local mask of turn alerts presented at the last stop. Not stored in `.imp`.
    #[serde(default)]
    pub(crate) turn_alert_mask: u8,
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
            turn_alert_mask: 0,
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
    pub const CIVILIANS: Self = Self(9);
    pub const MILITARY: Self = Self(10);
    pub const GREAT_POWER_PRESSURE: Self = Self(0x0b);
    pub const DEAL_BOOK: Self = Self(0x0c);
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

/// External interaction required before the core turn driver can continue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TurnStop {
    PlayerOrders,
    DiplomacyOffer,
    DiplomacyWarJoin,
    TradeOffer,
    LandBattle,
    DealBook,
    TechnologyAdvance,
    Newspaper,
    TurnAlerts,
}

/// Authoritative runtime resume state for an interruptible phase.
///
/// Included in semantic `GameState` serialization. The `.imp` writer omits it
/// because retail cannot save at these transient boundaries.
#[allow(clippy::large_enum_variant)]
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
    LandBattle(crate::CombatMovesContinuation),
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
        if self.show_turn_alerts() {
            return TurnStop::TurnAlerts;
        }
        self.turn.phase = PhaseCode::DIPLOMACY;
        self.advance_turn()
    }

    /// Dismisses turn alerts and re-enters player-order finish on the same phase.
    pub fn dismiss_turn_alerts(&mut self) -> TurnStop {
        assert_eq!(self.turn.phase(), PhaseCode::STRATEGIC_MAP);
        self.turn.turn_alert_mask = 0;
        self.finish_player_orders()
    }

    /// True while the driver is stopped on turn alerts that have not been dismissed.
    pub fn turn_alerts_pending(&self) -> bool {
        self.turn.phase() == PhaseCode::STRATEGIC_MAP
            && self.turn.turn_alert_mask != 0
            && self.turn.last_turn_alert_tick == self.turn.economic_turn
    }

    /// Accepts or rejects the diplomacy offer stored in the current continuation.
    pub fn answer_current_diplomacy_offer(&mut self, accept: bool) -> TurnStop {
        let result = self.resolve_diplomacy_offer(accept);
        if let Some(stop) = self.stop_from_diplomacy(result) {
            return stop;
        }
        self.advance_turn()
    }

    /// Accepts or rejects the war-join dialog stored in the current continuation.
    pub fn answer_current_diplomacy_war_join(&mut self, accept: bool) -> TurnStop {
        let result = self.resolve_diplomacy_war_join(accept);
        if let Some(stop) = self.stop_from_diplomacy(result) {
            return stop;
        }
        self.advance_turn()
    }

    /// Applies the Offer Sheet decision and resumes ranked trade deals.
    pub fn answer_trade_offer(&mut self, quantity: i16, stop_buying: bool) -> TurnStop {
        match self.reply_to_trade_offer(quantity, stop_buying) {
            TradeProgress::Offer(_) => TurnStop::TradeOffer,
            TradeProgress::Complete => self.advance_turn(),
        }
    }

    /// Closes the Deal Book opened by the turn driver and continues the turn.
    pub fn close_turn_deal_book(&mut self) -> TurnStop {
        assert_eq!(self.turn.phase(), PhaseCode::QUARTER_GATE);
        self.advance_turn()
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
            return TurnStop::TechnologyAdvance;
        }
        self.advance_turn()
    }

    /// Dismisses the newspaper and returns to player orders.
    pub fn close_newspaper(&mut self) -> TurnStop {
        assert_eq!(self.turn.phase(), PhaseCode::RETURN_TO_MAP);
        self.return_to_map();
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

    pub fn advance_turn(&mut self) -> TurnStop {
        loop {
            if let Some(stop) = self.continuation_stop() {
                return stop;
            }
            match self.turn.phase() {
                PhaseCode::STRATEGIC_MAP => return TurnStop::PlayerOrders,
                PhaseCode::CAPITAL_SELECTION => {
                    for nation in MajorNationId::all() {
                        self.finalize_home_city_setup(nation);
                    }
                    self.turn.phase = PhaseCode::SEASON_ADVANCE;
                }
                PhaseCode::DIPLOMACY => {
                    self.turn.phase = PhaseCode::TRADE;
                    let result = self.do_diplomacy();
                    if let Some(stop) = self.stop_from_diplomacy(result) {
                        return stop;
                    }
                }
                PhaseCode::TRADE => {
                    self.turn.phase = PhaseCode::CIVILIANS;
                    match self.begin_trade_phase() {
                        TradeProgress::Offer(_) => return TurnStop::TradeOffer,
                        TradeProgress::Complete => {}
                    }
                }
                PhaseCode::CIVILIANS => {
                    self.turn.phase = PhaseCode::MILITARY;
                    self.do_civilians();
                }
                PhaseCode::MILITARY => {
                    self.turn.phase = PhaseCode::COMBAT_MOVES;
                    self.do_military();
                }
                PhaseCode::COMBAT_MOVES => {
                    self.turn.phase = PhaseCode::MILITARY_CLEANUP;
                    if let Some(continuation) = self.do_combat_moves() {
                        self.continuation = TurnContinuation::LandBattle(continuation);
                        return TurnStop::LandBattle;
                    }
                }
                PhaseCode::MILITARY_CLEANUP => {
                    self.turn.phase = PhaseCode::DIPLOMACY_OFFER;
                    self.do_military_cleanup();
                }
                PhaseCode::CITY_AND_TRANSPORT => {
                    self.do_city_and_transport();
                    self.turn.phase = PhaseCode::GREAT_POWER_PRESSURE;
                }
                PhaseCode::GREAT_POWER_PRESSURE => {
                    self.turn.phase = PhaseCode::DEAL_BOOK;
                    if self.do_great_power_pressure_phase() {
                        panic!("great-power loss alert is not integrated");
                    }
                }
                PhaseCode::DEAL_BOOK => {
                    self.turn.phase = PhaseCode::QUARTER_GATE;
                    if self.event_eligible(self.turn.active_nation) {
                        return TurnStop::DealBook;
                    }
                }
                PhaseCode::DIPLOMACY_OFFER => {
                    self.turn.phase = PhaseCode::ELIMINATION;
                    if self.diplomacy_offer_gate() {
                        panic!("post-combat diplomacy UI is not integrated");
                    }
                }
                PhaseCode::ELIMINATION => {
                    self.turn.phase = PhaseCode::CITY_AND_TRANSPORT;
                    match self.do_elimination_phase() {
                        EliminationOutcome::Continue => {}
                        EliminationOutcome::PlayerEliminated => {
                            panic!("player-eliminated UI is not integrated")
                        }
                        EliminationOutcome::Victory => panic!("victory UI is not integrated"),
                    }
                }
                PhaseCode::QUARTER_GATE => {
                    if self.quarter_gate() == QuarterGateResult::DecadeCinematic {
                        panic!("decade cinematic is not integrated");
                    }
                }
                PhaseCode::SEASON_ADVANCE => {
                    self.advance_season_phase();
                }
                PhaseCode::TECHNOLOGY_ADVANCES => {
                    self.turn.phase = PhaseCode::NEWSPAPER;
                    if let Some(stop) = self.run_technology_advances() {
                        return stop;
                    }
                }
                PhaseCode::NEWSPAPER => {
                    self.mark_all_pending_status_flags_handled();
                    self.turn.phase = PhaseCode::RETURN_TO_MAP;
                    self.start_newspaper_phase();
                    self.mark_all_pending_status_flags_handled();
                    return TurnStop::Newspaper;
                }
                PhaseCode::RETURN_TO_MAP => {
                    self.return_to_map();
                }
                phase => panic!("unsupported internal turn phase {phase:?}"),
            }
        }
    }

    fn continuation_stop(&self) -> Option<TurnStop> {
        match self.continuation {
            TurnContinuation::None => None,
            TurnContinuation::DiplomacyOffer { .. } => Some(TurnStop::DiplomacyOffer),
            TurnContinuation::DiplomacyWarJoin(_) => Some(TurnStop::DiplomacyWarJoin),
            TurnContinuation::Trade(_) => Some(TurnStop::TradeOffer),
            TurnContinuation::LandBattle(_) => Some(TurnStop::LandBattle),
            TurnContinuation::TechnologyReport(_) => Some(TurnStop::TechnologyAdvance),
        }
    }

    fn stop_from_diplomacy(&self, result: DiplomacyPhaseResult) -> Option<TurnStop> {
        match result {
            DiplomacyPhaseResult::Resolved => None,
            DiplomacyPhaseResult::Offer(_) => Some(TurnStop::DiplomacyOffer),
            DiplomacyPhaseResult::WarJoin(_) => Some(TurnStop::DiplomacyWarJoin),
        }
    }

    fn run_technology_advances(&mut self) -> Option<TurnStop> {
        self.apply_technology_advances_phase();
        let tech_id = self.consume_interactive_technology_unlock()?;
        self.continuation = TurnContinuation::TechnologyReport(tech_id);
        Some(TurnStop::TechnologyAdvance)
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
        DiplomacyPolicy, DiplomaticRelationship, MajorNationController, MajorNationId, NationId,
        ResourceKind, ShipType, TileId, TileOwnerTag, TradeProgress,
    };

    fn seed_town_tiles(state: &mut crate::GameState) {
        for major_id in MajorNationId::all() {
            let tile = TileId::new(u16::from(major_id.get()) + 1);
            let nation = major_id.nation();
            let major = &mut state.nations.majors[major_id];
            major.towns[0].tile = tile;
            major.common.home_tile = Some(tile);
            state.nations.append_owned_region_during_construction(
                nation,
                crate::ProvinceId::new(u16::from(major_id.get())),
            );
            state.map[tile].owner_nation = Some(TileOwnerTag::from_nation(nation));
        }
    }

    fn pose_alliance_offer(state: &mut crate::GameState) {
        state.nations.majors[MajorNationId::new(1)].kind = crate::MajorNationKind::AutoGreatPower;
        state.nations.majors[MajorNationId::new(1)]
            .economy
            .controller = MajorNationController::Computer;
        state.nations.majors[MajorNationId::new(1)]
            .economy
            .diplomacy_policy_by_nation[NationId::new(0)] = Some(DiplomacyPolicy::Alliance);
    }

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
    fn city_and_transport_stops_at_deal_book_when_pressure_does_not_alert() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        state.turn.phase = crate::PhaseCode::CITY_AND_TRANSPORT;
        let stop = state.advance_turn();
        assert_eq!(stop, crate::TurnStop::DealBook);
        assert_eq!(state.turn.phase(), crate::PhaseCode::QUARTER_GATE);
    }

    #[test]
    fn closing_the_turn_deal_book_enters_the_quarter_gate() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        state.turn.phase = crate::PhaseCode::CITY_AND_TRANSPORT;
        assert_eq!(state.advance_turn(), crate::TurnStop::DealBook);
        let stop = state.close_turn_deal_book();
        assert!(
            matches!(
                stop,
                crate::TurnStop::TechnologyAdvance | crate::TurnStop::Newspaper
            ),
            "unexpected stop {stop:?}"
        );
        assert!(matches!(
            state.turn.phase(),
            crate::PhaseCode::NEWSPAPER | crate::PhaseCode::RETURN_TO_MAP
        ));
    }

    #[test]
    fn closing_the_deal_book_returns_to_player_orders_through_newspaper() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        state.turn.phase = crate::PhaseCode::CITY_AND_TRANSPORT;
        assert_eq!(state.advance_turn(), crate::TurnStop::DealBook);
        let start_turn = state.turn.economic_turn;
        let mut stop = state.close_turn_deal_book();
        while let crate::TurnStop::TechnologyAdvance = stop {
            stop = state.acknowledge_technology_report();
        }
        assert_eq!(stop, crate::TurnStop::Newspaper);
        assert_eq!(state.turn.phase(), crate::PhaseCode::RETURN_TO_MAP);
        assert_eq!(state.turn.economic_turn, start_turn + 1);
        assert_eq!(state.close_newspaper(), crate::TurnStop::PlayerOrders);
        assert_eq!(state.turn.phase(), crate::PhaseCode::STRATEGIC_MAP);
    }

    #[test]
    fn answering_a_diplomacy_offer_uses_core_continuation_not_the_prompt() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        pose_alliance_offer(&mut state);

        let crate::TurnStop::DiplomacyOffer = state.finish_player_orders() else {
            panic!("expected a diplomacy offer stop");
        };
        let prompt = state
            .current_diplomacy_offer()
            .expect("diplomacy offer continuation");
        assert_eq!(state.turn.phase(), crate::PhaseCode::TRADE);
        assert_eq!(state.current_diplomacy_offer(), Some(prompt));
        let stop = state.answer_current_diplomacy_offer(true);
        assert!(state.current_diplomacy_offer().is_none());
        assert!(
            matches!(
                stop,
                crate::TurnStop::TradeOffer | crate::TurnStop::DealBook
            ),
            "unexpected stop {stop:?}"
        );
        assert_eq!(
            state.diplomacy.relationships[NationId::new(0)][NationId::new(1)],
            DiplomaticRelationship::Alliance
        );
    }

    #[test]
    fn player_orders_resume_chain_reaches_deal_book() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        pose_alliance_offer(&mut state);

        let crate::TurnStop::DiplomacyOffer = state.finish_player_orders() else {
            panic!("expected a diplomacy offer stop");
        };
        let prompt = state
            .current_diplomacy_offer()
            .expect("diplomacy offer continuation");
        assert_eq!(state.turn.phase(), crate::PhaseCode::TRADE);
        assert_eq!(state.current_diplomacy_offer(), Some(prompt));

        let mut stop = state.answer_current_diplomacy_offer(true);
        if let crate::TurnStop::TradeOffer = stop {
            assert_eq!(state.turn.phase(), crate::PhaseCode::CIVILIANS);
            while let crate::TurnStop::TradeOffer = stop {
                stop = state.answer_trade_offer(0, false);
            }
        }
        assert_eq!(stop, crate::TurnStop::DealBook);
        assert_eq!(state.turn.phase(), crate::PhaseCode::QUARTER_GATE);
        assert!(state.pending_trade_offer().is_none());
        assert!(state.pending_land_battle().is_none());
    }

    #[test]
    fn completing_trade_continues_through_civilians_to_deal_book() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        state.turn.phase = crate::PhaseCode::TRADE;
        let mut stop = state.advance_turn();
        while let crate::TurnStop::TradeOffer = stop {
            stop = state.answer_trade_offer(0, false);
        }
        assert!(state.pending_trade_offer().is_none());
        assert_eq!(stop, crate::TurnStop::DealBook);
        assert_eq!(state.turn.phase(), crate::PhaseCode::QUARTER_GATE);
    }

    #[test]
    fn semantic_state_round_trips_a_trade_continuation() {
        let mut state = game_state();
        let buyer = MajorNationId::new(0);
        let seller = MajorNationId::new(1);
        for nation in MajorNationId::all() {
            state.nations.majors[nation].city.ship_order_count_by_type[ShipType::Trader] = 2;
            state.nations.majors[nation].city.ship_order_count_by_type[ShipType::Paddlewheeler] = 1;
            state.nations.majors[nation].city.ship_order_count_by_type[ShipType::Freighter] = 1;
            state.nations.majors[nation].city.stockpile[ResourceKind::Clothing] = 10;
            state.nations.majors[nation].city.stockpile[ResourceKind::Timber] = 12;
            state.nations.majors[nation].common.treasury = 20_000;
        }
        state.nations.majors[buyer]
            .economy
            .remembered_trade_offers_by_resource[ResourceKind::Clothing] = -1;
        state.nations.majors[buyer]
            .economy
            .remembered_trade_offers_by_resource[ResourceKind::Timber] = 5;
        state.nations.majors[seller]
            .economy
            .remembered_trade_offers_by_resource[ResourceKind::Clothing] = 4;
        let TradeProgress::Offer(_) = state.begin_trade_phase() else {
            panic!("game_state clothing-offer fixture must produce a pending trade offer");
        };
        let encoded = serde_json::to_vec(&state).expect("serialize");
        let restored: crate::GameState = serde_json::from_slice(&encoded).expect("deserialize");
        assert_eq!(restored.pending_trade_offer(), state.pending_trade_offer());
    }

    #[test]
    fn capital_selection_advances_season_and_builds_newspaper_before_stopping() {
        let mut state = game_state();
        state.turn.phase = crate::PhaseCode::CAPITAL_SELECTION;
        state.turn.economic_turn = 0;
        let stop = state.advance_turn();
        assert!(
            matches!(
                stop,
                crate::TurnStop::TechnologyAdvance | crate::TurnStop::Newspaper
            ),
            "unexpected stop {stop:?}"
        );
        assert_eq!(state.turn.economic_turn, 1);
        if stop == crate::TurnStop::Newspaper {
            assert_eq!(state.turn.phase(), crate::PhaseCode::RETURN_TO_MAP);
            assert!(state.pending.newspaper_events.is_empty());
        } else {
            assert_eq!(state.turn.phase(), crate::PhaseCode::NEWSPAPER);
        }
    }

    #[test]
    fn newspaper_stop_constructs_pages_before_returning() {
        let mut state = game_state();
        state.turn.phase = crate::PhaseCode::NEWSPAPER;
        state
            .pending
            .queue_newspaper_event(crate::PendingNewspaperEvent::Miscellaneous {
                audience: None,
                story_code: 3,
            });
        let mut story_ids = vec![1; crate::NEWS_TEMPLATE_COUNT];
        story_ids[0] = -1003;
        state.set_news_story_ids(&story_ids);
        let stop = state.advance_turn();
        assert_eq!(stop, crate::TurnStop::Newspaper);
        assert_eq!(state.turn.phase(), crate::PhaseCode::RETURN_TO_MAP);
        assert!(state.pending.newspaper_events.is_empty());
        assert!(state.news.pages[MajorNationId::new(0)].is_some());
    }

    #[test]
    fn newspaper_marks_queued_navy_growth_as_handled_reward_level() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        state.nations.majors[nation].economy.pending_actions
            [crate::PendingActionKind::NavyGrowthReward] =
            crate::PendingActionState::new(crate::PendingActionStatus::QUEUED, Some(1));
        state.turn.phase = crate::PhaseCode::NEWSPAPER;
        assert_eq!(state.advance_turn(), crate::TurnStop::Newspaper);
        assert_eq!(
            state.nations.majors[nation].economy.pending_actions
                [crate::PendingActionKind::NavyGrowthReward]
                .status(),
            crate::PendingActionStatus::from_retail(0x34)
        );
    }

    #[test]
    fn quiet_full_turn_stops_at_deal_book_then_returns_to_player_orders() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        let stop = state.finish_player_orders();
        assert_eq!(stop, crate::TurnStop::DealBook);
        assert_eq!(state.turn.phase(), crate::PhaseCode::QUARTER_GATE);
        let start_turn = state.turn.economic_turn;
        let mut stop = state.close_turn_deal_book();
        while let crate::TurnStop::TechnologyAdvance = stop {
            stop = state.acknowledge_technology_report();
        }
        assert_eq!(stop, crate::TurnStop::Newspaper);
        assert_eq!(state.close_newspaper(), crate::TurnStop::PlayerOrders);
        assert_eq!(state.turn.phase(), crate::PhaseCode::STRATEGIC_MAP);
        assert_eq!(state.turn.economic_turn, start_turn + 1);
    }
}
