use crate::trade_phase::TradeSession;
use crate::{
    Difficulty, DiplomacyOfferPrompt, DiplomacyWarJoinPrompt, EliminationOutcome, GameState,
    MajorNationId, NationId, PendingTradeOffer, QuarterGateResult, Technology,
};
use enum_map::{Enum, EnumMap};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CinematicKind {
    Vote,
    Win,
    Lose,
}

#[derive(Clone, Copy, Debug, Deserialize, Enum, Eq, PartialEq, Serialize)]
pub enum Decade {
    First,
    Second,
    Third,
    Fourth,
    Fifth,
    Sixth,
    Seventh,
    Eighth,
    Ninth,
    Tenth,
}

pub type DecadeTable<T> = EnumMap<Decade, T>;

impl Decade {
    pub const fn for_economic_turn(turn: i32) -> Option<Self> {
        match turn / 40 {
            0 => Some(Self::First),
            1 => Some(Self::Second),
            2 => Some(Self::Third),
            3 => Some(Self::Fourth),
            4 => Some(Self::Fifth),
            5 => Some(Self::Sixth),
            6 => Some(Self::Seventh),
            7 => Some(Self::Eighth),
            8 => Some(Self::Ninth),
            9 => Some(Self::Tenth),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TurnState {
    pub scenario_map: Option<ScenarioMapId>,
    pub economic_turn: i32,
    /// Raw persisted `TSimMgr` term consumed by diplomacy scaling.
    ///
    /// This is not the 1815-based display calendar.
    pub diplomacy_year_term_raw: i16,
    /// Retail `TSimMgr::field6a`, selecting the scenario flag/language asset set.
    pub selected_asset_set: i16,
    pub(crate) phase: PhaseCode,
    /// Persisted turn-flow status bits consumed by the alert and technology phases.
    pub turn_flow_status_flags: u32,
    /// Retail's twelve persisted decade/council state bytes.
    /// Zero skips the council gate; scenario scripts also use the distinct state 2.
    pub phase_state_by_decade: [u8; 12],
    pub difficulty: Difficulty,
    pub active_nation: NationId,
    /// Process-local last tick that showed turn alerts. Not stored in `.imp`.
    #[serde(default)]
    pub last_turn_alert_tick: i32,
    /// Retail `g_nTurnCooldownDeferCounter006A43C4`. Not stored in `.imp`.
    #[serde(default)]
    pub turn_cooldown_defer_counter: i16,
}

impl TurnState {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        scenario_map: Option<ScenarioMapId>,
        economic_turn: i32,
        diplomacy_year_term_raw: i16,
        selected_asset_set: i16,
        phase: PhaseCode,
        turn_flow_status_flags: u32,
        phase_state_by_decade: [u8; 12],
        difficulty: Difficulty,
        active_nation: NationId,
    ) -> Self {
        Self {
            scenario_map,
            economic_turn,
            diplomacy_year_term_raw,
            selected_asset_set,
            phase,
            turn_flow_status_flags,
            phase_state_by_decade,
            difficulty,
            active_nation,
            last_turn_alert_tick: 0,
            turn_cooldown_defer_counter: 0,
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

/// Authoritative runtime interrupt/resume state for the turn driver.
///
/// Included in semantic `GameState` serialization. The `.imp` writer omits it
/// because retail cannot save at these transient boundaries.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub enum TurnFlow {
    #[default]
    #[serde(rename = "None")]
    Running,
    AwaitingTradeOffer {
        session: Box<TradeSession>,
        offer: PendingTradeOffer,
    },
    DiplomacyOffer {
        nation: MajorNationId,
        index: u8,
    },
    DiplomacyWarJoin(DiplomacyWarJoinPrompt),
    LandBattle(crate::CombatMovesContinuation),
    NavalBattle(crate::NavyOrdersContinuation),
    TechnologyReport(Technology),
    GreatPowerLoss,
    PostCombatReports,
    DecadeCinematic,
    CouncilOfGovernors,
    PlayerEliminated,
    Victory,
    GameScore,
}

impl TurnFlow {
    pub(crate) fn debug_assert_phase_consistency(&self, phase: PhaseCode) {
        match self {
            Self::AwaitingTradeOffer { .. } => {
                debug_assert_eq!(phase, PhaseCode::TRADE, "trade offer requires phase TRADE");
            }
            Self::DiplomacyOffer { .. } | Self::DiplomacyWarJoin(_) => {
                debug_assert_eq!(
                    phase,
                    PhaseCode::DIPLOMACY,
                    "diplomacy interrupt requires phase DIPLOMACY"
                );
            }
            Self::NavalBattle(_) => {
                debug_assert_eq!(
                    phase,
                    PhaseCode::MILITARY,
                    "naval battle requires phase MILITARY"
                );
            }
            Self::LandBattle(_) => {
                debug_assert_eq!(
                    phase,
                    PhaseCode::COMBAT_MOVES,
                    "land battle requires phase COMBAT_MOVES"
                );
            }
            Self::TechnologyReport(_) => {
                debug_assert_eq!(
                    phase,
                    PhaseCode::TECHNOLOGY_ADVANCES,
                    "technology report requires phase TECHNOLOGY_ADVANCES"
                );
            }
            Self::GreatPowerLoss => {
                debug_assert_eq!(
                    phase,
                    PhaseCode::GREAT_POWER_PRESSURE,
                    "great-power loss requires phase GREAT_POWER_PRESSURE"
                );
            }
            Self::PostCombatReports => {
                debug_assert_eq!(
                    phase,
                    PhaseCode::DIPLOMACY_OFFER,
                    "post-combat reports require phase DIPLOMACY_OFFER"
                );
            }
            Self::DecadeCinematic => {
                debug_assert_eq!(
                    phase,
                    PhaseCode::QUARTER_GATE,
                    "decade cinematic requires phase QUARTER_GATE"
                );
            }
            Self::PlayerEliminated => {
                debug_assert!(
                    matches!(
                        phase,
                        PhaseCode::ELIMINATION | PhaseCode::OPENING_CINEMATIC
                    ),
                    "player-eliminated stop requires ELIMINATION or OPENING_CINEMATIC, got {phase:?}"
                );
            }
            Self::Victory => {
                debug_assert!(
                    matches!(phase, PhaseCode::ELIMINATION | PhaseCode::TOP_TEN_SCORES),
                    "victory stop requires ELIMINATION or TOP_TEN_SCORES, got {phase:?}"
                );
            }
            _ => {}
        }
    }
}

/// External interaction required before the core turn driver can continue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TurnStop {
    PlayerOrders,
    TownNaming,
    DiplomacyOffer,
    DiplomacyWarJoin,
    TradeOffer,
    LandBattle,
    NavalBattle,
    DealBook,
    TechnologyAdvance,
    Newspaper,
    TurnAlerts(Vec<crate::TurnAlert>),
    /// Turn-machine case `0x0b` after `SorryYouLose`. Distinct from elimination loss.
    GreatPowerLoss,
    /// Turn-machine case `0x0d` / `kTurnEventDiplomacyOffer` (0x0547) battle-report overview.
    PostCombatReports,
    /// Turn-machine case `0x0e` decade gate; movie is `"vote"` because `mode` is still `0x0e`.
    DecadeCinematic,
    /// Follow-up after the vote/win/lose movies (`kTurnEventCouncilOfGovernors` 0x07e0).
    CouncilOfGovernors,
    /// Turn-machine case `0x19` when the active nation is a protectorate.
    PlayerEliminated,
    /// Turn-machine case `0x19` when one eligible major remains.
    Victory,
    /// `kTurnEventGameScore` (0x05eb), after the elimination win movie.
    GameScore,
    /// Game Score `done` → `kTurnEventHighScores` (0x05e0).
    HighScores,
    /// After a lose movie, retail reinitializes to the main menu.
    SessionEnded,
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
    /// Retail `TSimMgr::ReadFrom` discards the serialized turn phase, enters phase 4,
    /// and immediately advances to the strategic map.
    pub fn resume_retail_save_on_strategic_map(&mut self) {
        self.turn.phase = PhaseCode::STRATEGIC_MAP;
    }

    /// Ends player orders on the strategic map and runs the turn until the next stop.
    pub fn finish_player_orders(&mut self, turn_alerts_enabled: bool) -> TurnStop {
        assert_eq!(self.turn.phase(), PhaseCode::STRATEGIC_MAP);
        let alerts = self.show_turn_alerts(turn_alerts_enabled);
        if !alerts.is_empty() {
            return TurnStop::TurnAlerts(alerts);
        }
        self.turn.phase = PhaseCode::DIPLOMACY;
        self.advance_turn()
    }

    /// Accepts or rejects the diplomacy offer stored in the current continuation.
    pub fn answer_current_diplomacy_offer(&mut self, accept: bool) -> TurnStop {
        self.resolve_diplomacy_offer(accept);
        self.advance_turn()
    }

    /// Accepts or rejects the war-join dialog stored in the current continuation.
    pub fn answer_current_diplomacy_war_join(&mut self, accept: bool) -> TurnStop {
        self.resolve_diplomacy_war_join(accept);
        self.advance_turn()
    }

    /// Applies the Offer Sheet decision and resumes ranked trade deals.
    pub fn answer_trade_offer(&mut self, quantity: i16, stop_buying: bool) -> TurnStop {
        self.reply_to_trade_offer(quantity, stop_buying);
        self.advance_turn()
    }

    /// Closes the Deal Book opened by the turn driver and continues the turn.
    pub fn close_turn_deal_book(&mut self) -> TurnStop {
        assert_eq!(self.turn.phase(), PhaseCode::DEAL_BOOK);
        self.turn.phase = PhaseCode::QUARTER_GATE;
        self.advance_turn()
    }

    /// Dismisses the technology report and continues the turn.
    pub fn acknowledge_technology_report(&mut self) -> TurnStop {
        assert!(
            matches!(self.turn_flow, TurnFlow::TechnologyReport(_)),
            "technology report answer requires an active technology continuation"
        );
        self.turn_flow = TurnFlow::Running;
        if let Some(tech_id) = self.consume_interactive_technology_unlock() {
            self.turn_flow = TurnFlow::TechnologyReport(tech_id);
            return TurnStop::TechnologyAdvance;
        }
        self.turn.phase = PhaseCode::NEWSPAPER;
        self.advance_turn()
    }

    /// Dismisses the newspaper and returns to player orders. Retail's map-entry
    /// music selection consumes the process-global CRT stream when music is enabled.
    pub fn close_newspaper(&mut self, music_enabled: bool) -> TurnStop {
        assert_eq!(self.turn.phase(), PhaseCode::RETURN_TO_MAP);
        self.return_to_map();
        if let Some((unit, _)) = self.first_idle_civilian(self.turn.active_nation) {
            self.activate_civilian_selection(unit);
        }
        if music_enabled && self.turn.turn_cooldown_defer_counter < 1 {
            self.rng.next_crt_rand();
        }
        TurnStop::PlayerOrders
    }

    /// Movie clip for `kTurnEventOpeningCinematic`. Switches on the entered mode, not
    /// the already-updated `turnStateCode` (`HandleTurnEventDialogFactorySlotF4`).
    pub fn opening_cinematic_movie(&self) -> CinematicKind {
        match self.turn_flow {
            TurnFlow::DecadeCinematic => CinematicKind::Vote,
            TurnFlow::Victory => CinematicKind::Win,
            TurnFlow::PlayerEliminated | TurnFlow::GreatPowerLoss => CinematicKind::Lose,
            _ => CinematicKind::Lose,
        }
    }

    /// Pressure-loss movie finished. Retail reinitializes; it does not continue to Deal Book.
    pub fn acknowledge_great_power_loss(&mut self) {
        assert!(
            matches!(self.turn_flow, TurnFlow::GreatPowerLoss),
            "great-power loss resume requires a great-power-loss continuation"
        );
        self.turn_flow = TurnFlow::Running;
    }

    /// Closes `TBattleReportView`. Reports stay until the next military phase's
    /// `CleanUpStacks`; phase remains `DIPLOMACY_OFFER` until dismissed.
    pub fn close_post_combat_reports(&mut self) -> TurnStop {
        assert!(
            matches!(self.turn_flow, TurnFlow::PostCombatReports),
            "post-combat report resume requires a post-combat continuation"
        );
        self.turn_flow = TurnFlow::Running;
        self.turn.phase = PhaseCode::ELIMINATION;
        self.advance_turn()
    }

    /// After the opening cinematic: vote/win/lose from 0x0e/0x16/0x17 go to council;
    /// elimination win goes to Game Score; elimination/pressure loss ends the session.
    pub fn close_opening_cinematic(&mut self) -> TurnStop {
        match &self.turn_flow {
            TurnFlow::DecadeCinematic => {
                // Retail writes the post-gate phase before the movie; we defer that write
                // until the interrupt clears so QUARTER_GATE stays honest while blocked.
                self.apply_phase_after_quarter_gate();
                self.turn_flow = TurnFlow::CouncilOfGovernors;
                TurnStop::CouncilOfGovernors
            }
            TurnFlow::Victory if self.turn.phase() == PhaseCode::TOP_TEN_SCORES => {
                self.turn_flow = TurnFlow::CouncilOfGovernors;
                TurnStop::CouncilOfGovernors
            }
            TurnFlow::Victory => {
                self.turn_flow = TurnFlow::GameScore;
                TurnStop::GameScore
            }
            TurnFlow::PlayerEliminated if self.turn.phase() == PhaseCode::OPENING_CINEMATIC => {
                self.turn_flow = TurnFlow::CouncilOfGovernors;
                TurnStop::CouncilOfGovernors
            }
            TurnFlow::PlayerEliminated | TurnFlow::GreatPowerLoss => {
                self.turn_flow = TurnFlow::Running;
                TurnStop::SessionEnded
            }
            other => {
                panic!("opening cinematic resume requires a cinematic continuation, got {other:?}")
            }
        }
    }

    /// Council of Governors closed. `StartNextPhase` uses the already-updated phase.
    pub fn close_council_of_governors(&mut self) -> TurnStop {
        assert!(
            matches!(self.turn_flow, TurnFlow::CouncilOfGovernors),
            "council resume requires a council continuation"
        );
        self.turn_flow = TurnFlow::Running;
        self.advance_turn()
    }

    /// Game Score `done` posts `kTurnEventHighScores` after reinitialize.
    pub fn close_game_score(&mut self) -> TurnStop {
        assert!(
            matches!(self.turn_flow, TurnFlow::GameScore),
            "game-score resume requires a game-score continuation"
        );
        self.turn_flow = TurnFlow::Running;
        TurnStop::HighScores
    }

    /// High-score table dismissed. Retail reinitializes to the main menu.
    pub fn close_high_scores(&mut self) -> TurnStop {
        self.turn_flow = TurnFlow::Running;
        TurnStop::SessionEnded
    }

    pub fn current_diplomacy_offer(&self) -> Option<DiplomacyOfferPrompt> {
        let TurnFlow::DiplomacyOffer { nation, index } = self.turn_flow else {
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
        match self.turn_flow {
            TurnFlow::DiplomacyWarJoin(prompt) => Some(prompt),
            _ => None,
        }
    }

    pub fn current_technology_report(&self) -> Option<Technology> {
        match self.turn_flow {
            TurnFlow::TechnologyReport(tech_id) => Some(tech_id),
            _ => None,
        }
    }

    pub fn advance_turn(&mut self) -> TurnStop {
        loop {
            if self.pending_town_naming().is_some() {
                return TurnStop::TownNaming;
            }
            if let Some(stop) = self.interrupt_stop() {
                return stop;
            }
            match self.turn.phase() {
                PhaseCode::STRATEGIC_MAP => return TurnStop::PlayerOrders,
                PhaseCode::CAPITAL_SELECTION => {
                    for nation in MajorNationId::all() {
                        self.finalize_home_city_setup(nation);
                    }
                    if let Some(active) = MajorNationId::from_nation(self.turn.active_nation) {
                        self.reset_diplomacy_need_scores_and_clear_aid_allocation_matrix(active);
                        self.reset_diplomacy_need_slots_7012_if_mode_gate_matches(active);
                    }
                    self.turn.phase = PhaseCode::SEASON_ADVANCE;
                }
                PhaseCode::DIPLOMACY => {
                    if matches!(
                        self.turn_flow,
                        TurnFlow::DiplomacyOffer { .. } | TurnFlow::DiplomacyWarJoin(_)
                    ) {
                        return self.interrupt_stop().expect("diplomacy flow is blocked");
                    }
                    if self.turn.phase() == PhaseCode::DIPLOMACY {
                        self.do_diplomacy();
                        if let Some(stop) = self.interrupt_stop() {
                            return stop;
                        }
                    }
                    debug_assert_ne!(self.turn.phase(), PhaseCode::DIPLOMACY);
                }
                PhaseCode::TRADE => {
                    if matches!(self.turn_flow, TurnFlow::AwaitingTradeOffer { .. }) {
                        return TurnStop::TradeOffer;
                    }
                    if self.turn.phase() == PhaseCode::TRADE {
                        self.begin_trade_phase();
                        if matches!(self.turn_flow, TurnFlow::AwaitingTradeOffer { .. }) {
                            return TurnStop::TradeOffer;
                        }
                    }
                    debug_assert_ne!(self.turn.phase(), PhaseCode::TRADE);
                }
                PhaseCode::CIVILIANS => {
                    self.turn.phase = PhaseCode::MILITARY;
                    self.do_civilians();
                }
                PhaseCode::MILITARY => {
                    if matches!(self.turn_flow, TurnFlow::NavalBattle(_)) {
                        return TurnStop::NavalBattle;
                    }
                    if self.turn.phase() == PhaseCode::MILITARY {
                        if let Some(continuation) = self.do_military() {
                            self.turn_flow = TurnFlow::NavalBattle(continuation);
                            return TurnStop::NavalBattle;
                        }
                        self.turn.phase = PhaseCode::COMBAT_MOVES;
                    }
                }
                PhaseCode::COMBAT_MOVES => {
                    if matches!(self.turn_flow, TurnFlow::LandBattle(_)) {
                        return TurnStop::LandBattle;
                    }
                    if self.turn.phase() == PhaseCode::COMBAT_MOVES {
                        if let Some(continuation) = self.do_combat_moves() {
                            self.turn_flow = TurnFlow::LandBattle(continuation);
                            return TurnStop::LandBattle;
                        }
                        self.turn.phase = PhaseCode::MILITARY_CLEANUP;
                    }
                }
                PhaseCode::MILITARY_CLEANUP => {
                    self.turn.phase = PhaseCode::DIPLOMACY_OFFER;
                    self.do_military_cleanup();
                }
                PhaseCode::CITY_AND_TRANSPORT => self.apply_city_and_transport_case(),
                PhaseCode::GREAT_POWER_PRESSURE => {
                    if matches!(self.turn_flow, TurnFlow::GreatPowerLoss) {
                        return TurnStop::GreatPowerLoss;
                    }
                    if self.turn.phase() == PhaseCode::GREAT_POWER_PRESSURE {
                        if self.do_great_power_pressure_phase() {
                            // `mode` is still `0x0b`; movie factory default is `"lose"`, then
                            // `ReinitializeGameFlow` — not the council path.
                            self.turn_flow = TurnFlow::GreatPowerLoss;
                            return TurnStop::GreatPowerLoss;
                        }
                        self.turn.phase = PhaseCode::DEAL_BOOK;
                    }
                }
                PhaseCode::DEAL_BOOK => {
                    if self.event_eligible(self.turn.active_nation) {
                        return TurnStop::DealBook;
                    }
                    self.turn.phase = PhaseCode::QUARTER_GATE;
                }
                PhaseCode::DIPLOMACY_OFFER => {
                    if matches!(self.turn_flow, TurnFlow::PostCombatReports) {
                        return TurnStop::PostCombatReports;
                    }
                    if self.turn.phase() == PhaseCode::DIPLOMACY_OFFER {
                        if self.diplomacy_offer_gate() {
                            self.turn_flow = TurnFlow::PostCombatReports;
                            return TurnStop::PostCombatReports;
                        }
                        self.turn.phase = PhaseCode::ELIMINATION;
                    }
                }
                PhaseCode::ELIMINATION => {
                    if matches!(
                        self.turn_flow,
                        TurnFlow::PlayerEliminated | TurnFlow::Victory
                    ) {
                        return self.interrupt_stop().expect("elimination flow is blocked");
                    }
                    if self.turn.phase() == PhaseCode::ELIMINATION {
                        match self.do_elimination_phase() {
                            EliminationOutcome::Continue => {
                                self.turn.phase = PhaseCode::CITY_AND_TRANSPORT;
                            }
                            EliminationOutcome::PlayerEliminated => {
                                self.turn_flow = TurnFlow::PlayerEliminated;
                                return TurnStop::PlayerEliminated;
                            }
                            EliminationOutcome::Victory => {
                                self.turn_flow = TurnFlow::Victory;
                                return TurnStop::Victory;
                            }
                        }
                    }
                }
                PhaseCode::QUARTER_GATE => {
                    if matches!(self.turn_flow, TurnFlow::DecadeCinematic) {
                        return TurnStop::DecadeCinematic;
                    }
                    if self.quarter_gate() == QuarterGateResult::DecadeCinematic {
                        self.turn_flow = TurnFlow::DecadeCinematic;
                        return TurnStop::DecadeCinematic;
                    }
                }
                PhaseCode::TOP_TEN_SCORES => {
                    // Case `0x16`: scores then `"win"` movie; follow-up is council.
                    self.turn_flow = TurnFlow::Victory;
                    return TurnStop::Victory;
                }
                PhaseCode::OPENING_CINEMATIC => {
                    // Case `0x17`: `"lose"` movie; follow-up is council.
                    self.turn_flow = TurnFlow::PlayerEliminated;
                    return TurnStop::PlayerEliminated;
                }
                PhaseCode::SEASON_ADVANCE => {
                    self.advance_season_phase();
                }
                PhaseCode::TECHNOLOGY_ADVANCES => {
                    if matches!(self.turn_flow, TurnFlow::TechnologyReport(_)) {
                        return TurnStop::TechnologyAdvance;
                    }
                    if self.turn.phase() == PhaseCode::TECHNOLOGY_ADVANCES {
                        self.apply_technology_advances_phase();
                        if let Some(tech_id) = self.consume_interactive_technology_unlock() {
                            self.turn_flow = TurnFlow::TechnologyReport(tech_id);
                            return TurnStop::TechnologyAdvance;
                        }
                        self.turn.phase = PhaseCode::NEWSPAPER;
                    }
                }
                PhaseCode::NEWSPAPER => {
                    self.turn.phase = PhaseCode::RETURN_TO_MAP;
                    self.construct_newspaper_pages();
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

    fn interrupt_stop(&self) -> Option<TurnStop> {
        match self.turn_flow {
            TurnFlow::Running => None,
            TurnFlow::AwaitingTradeOffer { .. } => Some(TurnStop::TradeOffer),
            TurnFlow::DiplomacyOffer { .. } => Some(TurnStop::DiplomacyOffer),
            TurnFlow::DiplomacyWarJoin(_) => Some(TurnStop::DiplomacyWarJoin),
            TurnFlow::LandBattle(_) => Some(TurnStop::LandBattle),
            TurnFlow::NavalBattle(_) => Some(TurnStop::NavalBattle),
            TurnFlow::TechnologyReport(_) => Some(TurnStop::TechnologyAdvance),
            TurnFlow::GreatPowerLoss => Some(TurnStop::GreatPowerLoss),
            TurnFlow::PostCombatReports => Some(TurnStop::PostCombatReports),
            TurnFlow::DecadeCinematic => Some(TurnStop::DecadeCinematic),
            TurnFlow::CouncilOfGovernors => Some(TurnStop::CouncilOfGovernors),
            TurnFlow::PlayerEliminated => Some(TurnStop::PlayerEliminated),
            TurnFlow::Victory => Some(TurnStop::Victory),
            TurnFlow::GameScore => Some(TurnStop::GameScore),
        }
    }

    /// Retail case 8 body: write the resume phase, then `DoCityAndTransport`.
    pub fn apply_city_and_transport_case(&mut self) {
        self.turn.phase = PhaseCode::GREAT_POWER_PRESSURE;
        self.do_city_and_transport();
    }

    /// Mirrors `TSimMgr::AllHumansFinished` across all live major nations.
    pub fn all_humans_finished(&self) -> bool {
        MajorNationId::all()
            .filter(|&nation| self.nations.major_is_present(nation))
            .all(|nation| self.nations.majors[&nation].economy.turn_finished)
    }

    /// Mirrors `TSimMgr::ResetTurnFlags`: only diplomacy-eligible live major nations
    /// have their completion flag cleared.
    pub fn reset_turn_flags(&mut self) {
        for nation in MajorNationId::all() {
            if !self.nations.major_is_present(nation) {
                continue;
            }
            let major = &mut self.nations.majors[&nation];
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
        AutoGreatPowerState, BattleReport, BattleReportKind, BattleReportLocation,
        BattleReportSide, BattleReportSideSlot, BattleReportSideTable, DiplomacyPolicy,
        DiplomaticRelationship, MajorNationId, NationId, ProvinceId, ResourceKind, ShipType,
        TileId, TileOwnerTag,
    };

    fn seed_town_tiles(state: &mut crate::GameState) {
        for major_id in MajorNationId::all() {
            let tile = TileId::new(u16::from(major_id.get()) + 1);
            let nation = major_id.nation();
            let major = &mut state.nations.majors[&major_id];
            let old_tile = major
                .towns
                .keys()
                .next()
                .copied()
                .expect("test major has its FrogCity marker");
            let (_, town) = major
                .towns
                .shift_remove_entry(&old_tile)
                .expect("test major has its FrogCity marker");
            major.towns.insert(tile, town);
            major.common.home_tile = Some(tile);
            state.nations.append_owned_region_during_construction(
                nation,
                crate::ProvinceId::new(u16::from(major_id.get())),
            );
            state.map.provinces[crate::ProvinceId::new(u16::from(major_id.get()))].region_class =
                Some(0);
            state.map[tile].owner_nation = Some(TileOwnerTag::from_nation(nation));
        }
    }

    fn pose_alliance_offer(state: &mut crate::GameState) {
        state.nations.majors[&MajorNationId::new(1)].auto = Some(AutoGreatPowerState::default());
        state.nations.majors[&MajorNationId::new(1)]
            .economy
            .diplomacy_policy_by_nation[NationId::new(0)] = Some(DiplomacyPolicy::Alliance);
    }

    #[test]
    fn reset_turn_flags_follows_diplomacy_eligibility_not_controller() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        {
            let economy = &mut state.nations.majors[&nation].economy;
            economy.diplomacy_eligible = false;
            economy.turn_finished = true;
        }
        state.reset_turn_flags();
        assert!(
            state.nations.majors[&nation].economy.turn_finished,
            "ineligible nations keep their finished flag"
        );

        state.nations.majors[&nation].economy.diplomacy_eligible = true;
        state.reset_turn_flags();
        assert!(!state.nations.majors[&nation].economy.turn_finished);
    }

    #[test]
    fn city_and_transport_stops_at_deal_book_when_pressure_does_not_alert() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        state.turn.phase = crate::PhaseCode::CITY_AND_TRANSPORT;
        let stop = state.advance_turn();
        assert_eq!(stop, crate::TurnStop::DealBook);
        assert_eq!(state.turn.phase(), crate::PhaseCode::DEAL_BOOK);
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
        assert_eq!(state.close_newspaper(false), crate::TurnStop::PlayerOrders);
        assert_eq!(state.turn.phase(), crate::PhaseCode::STRATEGIC_MAP);
    }

    #[test]
    fn answering_a_diplomacy_offer_uses_core_continuation_not_the_prompt() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        pose_alliance_offer(&mut state);

        let crate::TurnStop::DiplomacyOffer = state.finish_player_orders(true) else {
            panic!("expected a diplomacy offer stop");
        };
        let prompt = state
            .current_diplomacy_offer()
            .expect("diplomacy offer continuation");
        assert_eq!(state.turn.phase(), crate::PhaseCode::DIPLOMACY);
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

        let crate::TurnStop::DiplomacyOffer = state.finish_player_orders(true) else {
            panic!("expected a diplomacy offer stop");
        };
        let prompt = state
            .current_diplomacy_offer()
            .expect("diplomacy offer continuation");
        assert_eq!(state.turn.phase(), crate::PhaseCode::DIPLOMACY);
        assert_eq!(state.current_diplomacy_offer(), Some(prompt));

        let mut stop = state.answer_current_diplomacy_offer(true);
        if let crate::TurnStop::TradeOffer = stop {
            assert_eq!(state.turn.phase(), crate::PhaseCode::TRADE);
            while let crate::TurnStop::TradeOffer = stop {
                stop = state.answer_trade_offer(0, false);
            }
        }
        assert_eq!(stop, crate::TurnStop::DealBook);
        assert_eq!(state.turn.phase(), crate::PhaseCode::DEAL_BOOK);
        assert!(state.pending_trade_offer().is_none());
        assert!(state.pending_land_battle().is_none());
    }

    fn human_clothing_offer_state() -> crate::GameState {
        let mut state = game_state();
        let buyer = MajorNationId::new(0);
        let seller = MajorNationId::new(1);
        for nation in MajorNationId::all() {
            let major = &mut state.nations.majors[&nation];
            major.city.ship_order_count_by_type[ShipType::Trader] = 2;
            major.city.ship_order_count_by_type[ShipType::Paddlewheeler] = 1;
            major.city.ship_order_count_by_type[ShipType::Freighter] = 1;
            major.city.stockpile[ResourceKind::Clothing] = 10;
            major.city.stockpile[ResourceKind::Timber] = 12;
            major.common.treasury = 20_000;
        }
        state.nations.majors[&buyer]
            .economy
            .remembered_trade_offers_by_resource[ResourceKind::Clothing] = -1;
        state.nations.majors[&buyer]
            .economy
            .remembered_trade_offers_by_resource[ResourceKind::Timber] = 5;
        state.nations.majors[&seller]
            .economy
            .remembered_trade_offers_by_resource[ResourceKind::Clothing] = 4;
        state.turn.phase = crate::PhaseCode::TRADE;
        state
    }

    #[test]
    fn answer_trade_offer_does_not_immediately_restart_trade() {
        let mut state = human_clothing_offer_state();
        seed_town_tiles(&mut state);
        assert_eq!(state.advance_turn(), crate::TurnStop::TradeOffer);
        let stop = state.answer_trade_offer(0, false);
        assert_ne!(state.turn.phase(), crate::PhaseCode::TRADE);
        assert_ne!(stop, crate::TurnStop::TradeOffer);
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
        assert_eq!(state.turn.phase(), crate::PhaseCode::DEAL_BOOK);
    }

    #[test]
    fn semantic_state_round_trips_a_trade_flow() {
        let mut state = game_state();
        let buyer = MajorNationId::new(0);
        let seller = MajorNationId::new(1);
        for nation in MajorNationId::all() {
            state.nations.majors[&nation].city.ship_order_count_by_type[ShipType::Trader] = 2;
            state.nations.majors[&nation].city.ship_order_count_by_type[ShipType::Paddlewheeler] =
                1;
            state.nations.majors[&nation].city.ship_order_count_by_type[ShipType::Freighter] = 1;
            state.nations.majors[&nation].city.stockpile[ResourceKind::Clothing] = 10;
            state.nations.majors[&nation].city.stockpile[ResourceKind::Timber] = 12;
            state.nations.majors[&nation].common.treasury = 20_000;
        }
        state.nations.majors[&buyer]
            .economy
            .remembered_trade_offers_by_resource[ResourceKind::Clothing] = -1;
        state.nations.majors[&buyer]
            .economy
            .remembered_trade_offers_by_resource[ResourceKind::Timber] = 5;
        state.nations.majors[&seller]
            .economy
            .remembered_trade_offers_by_resource[ResourceKind::Clothing] = 4;
        state.turn.phase = crate::PhaseCode::TRADE;
        state.begin_trade_phase();
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
        state.set_game_data(crate::GameData::from_news_story_ids(story_ids));
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
        state.nations.majors[&nation].economy.pending_actions
            [crate::PendingActionKind::NavyGrowthReward] =
            crate::PendingActionState::new(crate::PendingActionStatus::QUEUED, Some(1));
        state.turn.phase = crate::PhaseCode::NEWSPAPER;
        assert_eq!(state.advance_turn(), crate::TurnStop::Newspaper);
        assert_eq!(
            state.nations.majors[&nation].economy.pending_actions
                [crate::PendingActionKind::NavyGrowthReward]
                .status(),
            crate::PendingActionStatus::from_retail(0x34)
        );
    }

    #[test]
    fn post_combat_diplomacy_is_an_explicit_turn_stop() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        state.append_battle_report(BattleReport {
            participant: Some(BattleReportSideSlot::Left),
            displayed_side: BattleReportSideSlot::Left,
            kind: BattleReportKind::LandBattle,
            location: BattleReportLocation::Province(ProvinceId::new(0)),
            sides: BattleReportSideTable::from_array([
                BattleReportSide {
                    nation: NationId::new(0),
                    children: Vec::new(),
                    task_force_order: None,
                },
                BattleReportSide {
                    nation: NationId::new(1),
                    children: Vec::new(),
                    task_force_order: None,
                },
            ]),
        });
        state.turn.phase = crate::PhaseCode::DIPLOMACY_OFFER;
        assert_eq!(state.advance_turn(), crate::TurnStop::PostCombatReports);
        assert_eq!(state.turn.phase(), crate::PhaseCode::DIPLOMACY_OFFER);
    }

    #[test]
    fn elimination_outcomes_are_explicit_turn_stops() {
        let mut eliminated = game_state();
        seed_town_tiles(&mut eliminated);
        eliminated.nations.set_country_status(
            eliminated.turn.active_nation,
            crate::CountryStatus::ProtectorateOf(NationId::new(1)),
        );
        eliminated.turn.phase = crate::PhaseCode::ELIMINATION;
        assert_eq!(eliminated.advance_turn(), crate::TurnStop::PlayerEliminated);
        assert_eq!(
            eliminated.turn.phase(),
            crate::PhaseCode::ELIMINATION
        );

        let mut victory = game_state();
        let survivor = MajorNationId::new(0);
        victory.turn.active_nation = survivor.nation();
        victory
            .nations
            .append_owned_region_during_construction(survivor.nation(), crate::ProvinceId::new(0));
        victory.turn.phase = crate::PhaseCode::ELIMINATION;
        assert_eq!(victory.advance_turn(), crate::TurnStop::Victory);
        assert_eq!(victory.turn.phase(), crate::PhaseCode::ELIMINATION);
    }

    #[test]
    fn decade_cinematic_is_an_explicit_turn_stop() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        state.turn.economic_turn = 40;
        state.turn.phase_state_by_decade[crate::Decade::Second as usize] = 1;
        state.turn.phase = crate::PhaseCode::QUARTER_GATE;
        assert_eq!(state.advance_turn(), crate::TurnStop::DecadeCinematic);
        assert_eq!(state.turn.phase(), crate::PhaseCode::QUARTER_GATE);
    }

    #[test]
    fn quiet_full_turn_stops_at_deal_book_then_returns_to_player_orders() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        let stop = state.finish_player_orders(true);
        assert_eq!(stop, crate::TurnStop::DealBook);
        assert_eq!(state.turn.phase(), crate::PhaseCode::DEAL_BOOK);
        let start_turn = state.turn.economic_turn;
        let mut stop = state.close_turn_deal_book();
        while let crate::TurnStop::TechnologyAdvance = stop {
            stop = state.acknowledge_technology_report();
        }
        assert_eq!(stop, crate::TurnStop::Newspaper);
        assert_eq!(state.close_newspaper(false), crate::TurnStop::PlayerOrders);
        assert_eq!(state.turn.phase(), crate::PhaseCode::STRATEGIC_MAP);
        assert_eq!(state.turn.economic_turn, start_turn + 1);
    }

    #[test]
    fn turn_alert_outcome_requires_a_fresh_finish_player_orders() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        state.turn.economic_turn = 3;
        state.turn.turn_flow_status_flags = 0x1010;
        state.diplomacy.last_diplomatic_effort_turn = 0;

        assert_eq!(
            state.finish_player_orders(true),
            crate::TurnStop::TurnAlerts(vec![
                crate::TurnAlert::Treasury { prompt_code: 0x25 },
                crate::TurnAlert::Starvation,
            ])
        );
        assert_eq!(state.turn.phase(), crate::PhaseCode::STRATEGIC_MAP);

        assert!(!matches!(
            state.finish_player_orders(true),
            crate::TurnStop::TurnAlerts(_)
        ));
        assert_ne!(state.turn.phase(), crate::PhaseCode::STRATEGIC_MAP);
    }

    #[test]
    fn opening_cinematic_movie_follows_entered_mode() {
        let mut state = game_state();
        state.turn_flow = crate::TurnFlow::DecadeCinematic;
        assert_eq!(state.opening_cinematic_movie(), crate::CinematicKind::Vote);
        state.turn_flow = crate::TurnFlow::Victory;
        assert_eq!(state.opening_cinematic_movie(), crate::CinematicKind::Win);
        state.turn_flow = crate::TurnFlow::PlayerEliminated;
        assert_eq!(state.opening_cinematic_movie(), crate::CinematicKind::Lose);
        state.turn_flow = crate::TurnFlow::GreatPowerLoss;
        assert_eq!(state.opening_cinematic_movie(), crate::CinematicKind::Lose);
    }

    #[test]
    fn decade_cinematic_close_enters_council() {
        let mut state = game_state();
        state.turn.phase = crate::PhaseCode::QUARTER_GATE;
        state.turn_flow = crate::TurnFlow::DecadeCinematic;
        assert_eq!(
            state.close_opening_cinematic(),
            crate::TurnStop::CouncilOfGovernors
        );
        assert!(matches!(
            state.turn_flow,
            crate::TurnFlow::CouncilOfGovernors
        ));
        assert_eq!(state.turn.phase(), crate::PhaseCode::SEASON_ADVANCE);
    }

    #[test]
    fn elimination_win_close_enters_game_score() {
        let mut state = game_state();
        state.turn_flow = crate::TurnFlow::Victory;
        assert_eq!(state.close_opening_cinematic(), crate::TurnStop::GameScore);
        assert_eq!(state.close_game_score(), crate::TurnStop::HighScores);
        assert_eq!(state.close_high_scores(), crate::TurnStop::SessionEnded);
    }

    #[test]
    fn pressure_loss_close_ends_the_session() {
        let mut state = game_state();
        state.turn_flow = crate::TurnFlow::GreatPowerLoss;
        assert_eq!(
            state.close_opening_cinematic(),
            crate::TurnStop::SessionEnded
        );
    }

    #[test]
    fn reports_pending_follows_the_battle_report_collection() {
        let mut state = game_state();
        assert!(!state.battle_reports_pending());
        state.append_battle_report(BattleReport {
            participant: Some(BattleReportSideSlot::Left),
            displayed_side: BattleReportSideSlot::Left,
            kind: BattleReportKind::LandBattle,
            location: BattleReportLocation::Province(ProvinceId::new(0)),
            sides: BattleReportSideTable::from_array([
                BattleReportSide {
                    nation: NationId::new(0),
                    children: Vec::new(),
                    task_force_order: None,
                },
                BattleReportSide {
                    nation: NationId::new(1),
                    children: Vec::new(),
                    task_force_order: None,
                },
            ]),
        });
        assert!(state.battle_reports_pending());
    }
}
