use crate::trade_phase::TradeSession;
use crate::{
    CombatMovesContinuation, Difficulty, DiplomacyOfferPrompt, DiplomacyWarJoinPrompt,
    EliminationOutcome, GameState, MajorNationId, NationId, NavyOrdersContinuation,
    PendingTradeOffer, QuarterGateResult, Technology,
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
            turn_flow_status_flags,
            phase_state_by_decade,
            difficulty,
            active_nation,
            last_turn_alert_tick: 0,
            turn_cooldown_defer_counter: 0,
        }
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

/// Retail `TSimMgr::turnStateCode` value, the persisted projection of [`TurnFlow`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct PhaseCode(i32);
impl PhaseCode {
    /// `ReinitializeGameFlow` bootstrap code, written once a session is over.
    pub const REINITIALIZED: Self = Self(1);
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

/// Authoritative turn control: the phase the driver is in and what it waits on.
///
/// Included in semantic `GameState` serialization. The `.imp` writer stores only the
/// [`PhaseCode`] projection because retail cannot save at an interrupt boundary.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum TurnFlow {
    /// Case `2`: name capitals and reset the active nation's diplomacy needs.
    CapitalSelection,
    /// Case `5`: waiting for player orders on the strategic map.
    StrategicMap,
    Diplomacy(DiplomacyFlow),
    Trade(TradeFlow),
    /// Case `9`.
    Civilians,
    Military(MilitaryFlow),
    CombatMoves(CombatMovesFlow),
    /// Case `0x15`.
    MilitaryCleanup,
    DiplomacyOfferGate(DiplomacyOfferGateFlow),
    Elimination(EliminationFlow),
    /// Case `8`.
    CityAndTransport,
    GreatPowerPressure(GreatPowerPressureFlow),
    DealBook(DealBookFlow),
    QuarterGate(QuarterGateFlow),
    /// Case `0x10`.
    SeasonAdvance,
    TechnologyAdvances(TechnologyFlow),
    Newspaper(NewspaperFlow),
    /// Case `0x12`.
    ReturnToMap,
    /// Case `0x16`: top-ten scores, then the `"win"` movie.
    TopTenScores,
    /// Case `0x17`: the `"lose"` movie.
    OpeningCinematicLose,
    /// `kTurnEventCouncilOfGovernors` (0x07e0) with the phase the gate already chose.
    CouncilOfGovernors(PostQuarterGate),
    /// `kTurnEventGameScore` (0x05eb), after the elimination win movie.
    GameScore,
    /// Game Score `done` posted `kTurnEventHighScores` (0x05e0).
    HighScores,
    /// Retail reinitialized to the main menu; this session cannot advance again.
    SessionEnded,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DiplomacyFlow {
    Running,
    /// Human reply pending for proposal `index` posted to `nation`.
    Offer { nation: MajorNationId, index: u8 },
    WarJoin(DiplomacyWarJoinPrompt),
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum TradeFlow {
    Running,
    /// Offer Sheet posed for `offer`; `session` resumes `TTradeMgr::NextTradeDeal`.
    AwaitingOffer {
        session: Box<TradeSession>,
        offer: PendingTradeOffer,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum MilitaryFlow {
    Running,
    /// Tactical naval battle owns the retained `CarryOutOrders` scan.
    NavalBattle(NavyOrdersContinuation),
}

#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub enum CombatMovesFlow {
    Running,
    /// Land battle owns the retained `ResolveNextMove` stack cursor.
    LandBattle(CombatMovesContinuation),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum GreatPowerPressureFlow {
    Running,
    /// `SorryYouLose` movie; retail reinitializes instead of reaching the Deal Book.
    Loss,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DealBookFlow {
    Running,
    /// The Deal Book is on screen and holds the turn until the player closes it.
    Open,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum DiplomacyOfferGateFlow {
    Running,
    /// `TBattleReportView` overview posed by `kTurnEventDiplomacyOffer` (0x0547).
    PostCombatReports,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum EliminationFlow {
    Running,
    /// The active nation became a protectorate; the `"lose"` movie is showing.
    PlayerEliminated,
    /// One eligible major remains; the `"win"` movie is showing.
    Victory,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum QuarterGateFlow {
    Running,
    /// Decade `"vote"` movie, holding the phase the gate already selected.
    DecadeCinematic(PostQuarterGate),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TechnologyFlow {
    Running,
    /// Technology advance dialog for one interactive unlock.
    Report(Technology),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum NewspaperFlow {
    Running,
    /// Pages are built and the paper is open; the body must not run again.
    Reading,
}

/// Phase the case `0x0e` gate selects before the cinematic and council path.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PostQuarterGate {
    SeasonAdvance,
    TopTenScores,
    OpeningCinematicLose,
}

impl PostQuarterGate {
    const fn flow(self) -> TurnFlow {
        match self {
            Self::SeasonAdvance => TurnFlow::SeasonAdvance,
            Self::TopTenScores => TurnFlow::TopTenScores,
            Self::OpeningCinematicLose => TurnFlow::OpeningCinematicLose,
        }
    }

    const fn retail_phase(self) -> PhaseCode {
        match self {
            Self::SeasonAdvance => PhaseCode::SEASON_ADVANCE,
            Self::TopTenScores => PhaseCode::TOP_TEN_SCORES,
            Self::OpeningCinematicLose => PhaseCode::OPENING_CINEMATIC,
        }
    }
}

impl TurnFlow {
    /// Retail `turnStateCode` for this flow.
    ///
    /// `AdvanceGlobalTurnStateMachine` writes the *next* code at the top of almost every
    /// case, before the body that can pose a dialog. A flow waiting at an interrupt
    /// therefore projects onto the code retail already advanced to, which is why several
    /// flows share a code and the projection has no inverse.
    pub const fn retail_phase(&self) -> PhaseCode {
        match self {
            Self::CapitalSelection => PhaseCode::CAPITAL_SELECTION,
            Self::StrategicMap => PhaseCode::STRATEGIC_MAP,
            Self::Diplomacy(DiplomacyFlow::Running) => PhaseCode::DIPLOMACY,
            // Case 6 wrote 7 before `ReplyToDiplomacyOffers` posed the dialog.
            Self::Diplomacy(_) | Self::Trade(TradeFlow::Running) => PhaseCode::TRADE,
            // Case 7 wrote 9 before `DoTrade` posed the Offer Sheet.
            Self::Trade(_) | Self::Civilians => PhaseCode::CIVILIANS,
            Self::Military(MilitaryFlow::Running) => PhaseCode::MILITARY,
            // Case 10 wrote 0x14 before `DoMilitary` reached the naval encounter.
            Self::Military(_) | Self::CombatMoves(CombatMovesFlow::Running) => {
                PhaseCode::COMBAT_MOVES
            }
            // Case 0x14 wrote 0x15 before `ResolveNextMove` reached the land battle.
            Self::CombatMoves(_) | Self::MilitaryCleanup => PhaseCode::MILITARY_CLEANUP,
            Self::DiplomacyOfferGate(DiplomacyOfferGateFlow::Running) => {
                PhaseCode::DIPLOMACY_OFFER
            }
            // Case 0x0d wrote 0x19 before posing `TBattleReportView`.
            Self::DiplomacyOfferGate(_) | Self::Elimination(EliminationFlow::Running) => {
                PhaseCode::ELIMINATION
            }
            // Case 0x19 wrote 8 before the win/lose movie, and the Game Score dialog
            // the win movie posts leaves the code alone.
            Self::Elimination(_) | Self::GameScore | Self::CityAndTransport => {
                PhaseCode::CITY_AND_TRANSPORT
            }
            Self::GreatPowerPressure(GreatPowerPressureFlow::Running) => {
                PhaseCode::GREAT_POWER_PRESSURE
            }
            // Case 0x0b wrote 0x0c before `SorryYouLose`.
            Self::GreatPowerPressure(_) | Self::DealBook(DealBookFlow::Running) => {
                PhaseCode::DEAL_BOOK
            }
            // Case 0x0c wrote 0x0e before posing the Deal Book.
            Self::DealBook(_) | Self::QuarterGate(QuarterGateFlow::Running) => {
                PhaseCode::QUARTER_GATE
            }
            // Case 0x0e wrote the post-gate code before the decade `"vote"` movie, and
            // `kTurnEventCouncilOfGovernors` leaves it alone.
            Self::QuarterGate(QuarterGateFlow::DecadeCinematic(next))
            | Self::CouncilOfGovernors(next) => next.retail_phase(),
            Self::SeasonAdvance => PhaseCode::SEASON_ADVANCE,
            Self::TechnologyAdvances(TechnologyFlow::Running) => PhaseCode::TECHNOLOGY_ADVANCES,
            // Case 0x11 wrote 0x0f before posing the technology report.
            Self::TechnologyAdvances(_) | Self::Newspaper(NewspaperFlow::Running) => {
                PhaseCode::NEWSPAPER
            }
            // Case 0x0f wrote 0x12 before opening the newspaper.
            Self::Newspaper(_) | Self::ReturnToMap => PhaseCode::RETURN_TO_MAP,
            Self::TopTenScores => PhaseCode::TOP_TEN_SCORES,
            Self::OpeningCinematicLose => PhaseCode::OPENING_CINEMATIC,
            Self::HighScores | Self::SessionEnded => PhaseCode::REINITIALIZED,
        }
    }

    /// Turn control for a `turnStateCode` restored from a save or the native oracle.
    ///
    /// This inverts [`Self::retail_phase`] only for the running form of each case,
    /// because retail's code cannot say which interrupt the phase stopped at.
    /// `TSimMgr::ReadFrom` discards the pre-map codes and resumes on the strategic map.
    pub const fn from_retail_phase(phase: PhaseCode) -> Self {
        match phase {
            PhaseCode::REINITIALIZED => Self::SessionEnded,
            PhaseCode::CAPITAL_SELECTION => Self::CapitalSelection,
            PhaseCode::PRE_MAP | PhaseCode::HOME_PLACEMENT | PhaseCode::STRATEGIC_MAP => {
                Self::StrategicMap
            }
            PhaseCode::DIPLOMACY => Self::Diplomacy(DiplomacyFlow::Running),
            PhaseCode::TRADE => Self::Trade(TradeFlow::Running),
            PhaseCode::CITY_AND_TRANSPORT => Self::CityAndTransport,
            PhaseCode::CIVILIANS => Self::Civilians,
            PhaseCode::MILITARY => Self::Military(MilitaryFlow::Running),
            PhaseCode::GREAT_POWER_PRESSURE => {
                Self::GreatPowerPressure(GreatPowerPressureFlow::Running)
            }
            PhaseCode::DEAL_BOOK => Self::DealBook(DealBookFlow::Running),
            PhaseCode::DIPLOMACY_OFFER => Self::DiplomacyOfferGate(DiplomacyOfferGateFlow::Running),
            PhaseCode::QUARTER_GATE => Self::QuarterGate(QuarterGateFlow::Running),
            PhaseCode::NEWSPAPER => Self::Newspaper(NewspaperFlow::Running),
            PhaseCode::SEASON_ADVANCE => Self::SeasonAdvance,
            PhaseCode::TECHNOLOGY_ADVANCES => Self::TechnologyAdvances(TechnologyFlow::Running),
            PhaseCode::RETURN_TO_MAP => Self::ReturnToMap,
            PhaseCode::COMBAT_MOVES => Self::CombatMoves(CombatMovesFlow::Running),
            PhaseCode::MILITARY_CLEANUP => Self::MilitaryCleanup,
            PhaseCode::TOP_TEN_SCORES => Self::TopTenScores,
            PhaseCode::OPENING_CINEMATIC => Self::OpeningCinematicLose,
            PhaseCode::ELIMINATION => Self::Elimination(EliminationFlow::Running),
            _ => panic!("unsupported retail turn phase"),
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
}

impl GameState {
    /// Retail `turnStateCode` for the authoritative turn flow.
    pub const fn phase(&self) -> PhaseCode {
        self.turn_flow.retail_phase()
    }

    /// Retail `TSimMgr::ReadFrom` discards the serialized turn phase, enters phase 4,
    /// and immediately advances to the strategic map.
    pub fn resume_retail_save_on_strategic_map(&mut self) {
        self.turn_flow = TurnFlow::StrategicMap;
    }

    /// Ends player orders on the strategic map and runs the turn until the next stop.
    pub fn finish_player_orders(&mut self, turn_alerts_enabled: bool) -> TurnStop {
        assert_eq!(self.turn_flow, TurnFlow::StrategicMap);
        let alerts = self.show_turn_alerts(turn_alerts_enabled);
        if !alerts.is_empty() {
            return TurnStop::TurnAlerts(alerts);
        }
        self.turn_flow = TurnFlow::Diplomacy(DiplomacyFlow::Running);
        self.advance_turn()
    }

    /// Accepts or rejects the diplomacy offer stored in the current flow.
    pub fn answer_current_diplomacy_offer(&mut self, accept: bool) -> TurnStop {
        self.resolve_diplomacy_offer(accept);
        self.advance_turn()
    }

    /// Accepts or rejects the war-join dialog stored in the current flow.
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
        assert_eq!(self.turn_flow, TurnFlow::DealBook(DealBookFlow::Open));
        self.turn_flow = TurnFlow::QuarterGate(QuarterGateFlow::Running);
        self.advance_turn()
    }

    /// Dismisses the technology report and continues the turn.
    pub fn acknowledge_technology_report(&mut self) -> TurnStop {
        assert!(
            matches!(
                self.turn_flow,
                TurnFlow::TechnologyAdvances(TechnologyFlow::Report(_))
            ),
            "technology report answer requires an open technology report"
        );
        self.turn_flow = match self.consume_interactive_technology_unlock() {
            Some(tech_id) => TurnFlow::TechnologyAdvances(TechnologyFlow::Report(tech_id)),
            None => TurnFlow::Newspaper(NewspaperFlow::Running),
        };
        self.advance_turn()
    }

    /// Dismisses the newspaper and returns to player orders. Retail's map-entry
    /// music selection consumes the process-global CRT stream when music is enabled.
    pub fn close_newspaper(&mut self, music_enabled: bool) -> TurnStop {
        assert_eq!(self.turn_flow, TurnFlow::Newspaper(NewspaperFlow::Reading));
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
            TurnFlow::QuarterGate(QuarterGateFlow::DecadeCinematic(_)) => CinematicKind::Vote,
            TurnFlow::TopTenScores | TurnFlow::Elimination(EliminationFlow::Victory) => {
                CinematicKind::Win
            }
            _ => CinematicKind::Lose,
        }
    }

    /// Pressure-loss movie finished. Retail reinitializes; it does not continue to Deal Book.
    pub fn acknowledge_great_power_loss(&mut self) {
        assert_eq!(
            self.turn_flow,
            TurnFlow::GreatPowerPressure(GreatPowerPressureFlow::Loss)
        );
        self.turn_flow = TurnFlow::SessionEnded;
    }

    /// Closes `TBattleReportView`. Reports stay until the next military phase's
    /// `CleanUpStacks`; the offer gate holds the turn until they are dismissed.
    pub fn close_post_combat_reports(&mut self) -> TurnStop {
        assert_eq!(
            self.turn_flow,
            TurnFlow::DiplomacyOfferGate(DiplomacyOfferGateFlow::PostCombatReports)
        );
        self.turn_flow = TurnFlow::Elimination(EliminationFlow::Running);
        self.advance_turn()
    }

    /// After the opening cinematic: vote/win/lose from 0x0e/0x16/0x17 go to council;
    /// elimination win goes to Game Score; elimination/pressure loss ends the session.
    pub fn close_opening_cinematic(&mut self) -> TurnStop {
        self.turn_flow = match self.turn_flow {
            TurnFlow::QuarterGate(QuarterGateFlow::DecadeCinematic(next)) => {
                TurnFlow::CouncilOfGovernors(next)
            }
            TurnFlow::TopTenScores => TurnFlow::CouncilOfGovernors(PostQuarterGate::TopTenScores),
            TurnFlow::OpeningCinematicLose => {
                TurnFlow::CouncilOfGovernors(PostQuarterGate::OpeningCinematicLose)
            }
            TurnFlow::Elimination(EliminationFlow::Victory) => TurnFlow::GameScore,
            TurnFlow::Elimination(EliminationFlow::PlayerEliminated)
            | TurnFlow::GreatPowerPressure(GreatPowerPressureFlow::Loss) => TurnFlow::SessionEnded,
            _ => panic!(
                "opening cinematic resume requires a cinematic flow, got {:?}",
                self.turn_flow
            ),
        };
        self.interrupt_stop()
            .expect("every cinematic follow-up waits for the player")
    }

    /// Council of Governors closed. `StartNextPhase` uses the phase the gate chose.
    pub fn close_council_of_governors(&mut self) -> TurnStop {
        let TurnFlow::CouncilOfGovernors(next) = self.turn_flow else {
            panic!("council resume requires an open council");
        };
        self.turn_flow = next.flow();
        self.advance_turn()
    }

    /// Game Score `done` posts `kTurnEventHighScores` after reinitialize.
    pub fn close_game_score(&mut self) -> TurnStop {
        assert_eq!(self.turn_flow, TurnFlow::GameScore);
        self.turn_flow = TurnFlow::HighScores;
        TurnStop::HighScores
    }

    /// High-score table dismissed. Retail reinitializes to the main menu.
    pub fn close_high_scores(&mut self) -> TurnStop {
        self.turn_flow = TurnFlow::SessionEnded;
        TurnStop::SessionEnded
    }

    pub fn current_diplomacy_offer(&self) -> Option<DiplomacyOfferPrompt> {
        let TurnFlow::Diplomacy(DiplomacyFlow::Offer { nation, index }) = self.turn_flow else {
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
            TurnFlow::Diplomacy(DiplomacyFlow::WarJoin(prompt)) => Some(prompt),
            _ => None,
        }
    }

    pub fn current_technology_report(&self) -> Option<Technology> {
        match self.turn_flow {
            TurnFlow::TechnologyAdvances(TechnologyFlow::Report(tech_id)) => Some(tech_id),
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
            match self.turn_flow {
                TurnFlow::StrategicMap => return TurnStop::PlayerOrders,
                TurnFlow::CapitalSelection => {
                    for nation in MajorNationId::all() {
                        self.finalize_home_city_setup(nation);
                    }
                    if let Some(active) = MajorNationId::from_nation(self.turn.active_nation) {
                        self.reset_diplomacy_need_scores_and_clear_aid_allocation_matrix(active);
                        self.reset_diplomacy_need_slots_7012_if_mode_gate_matches(active);
                    }
                    self.turn_flow = TurnFlow::SeasonAdvance;
                }
                TurnFlow::Diplomacy(DiplomacyFlow::Running) => self.do_diplomacy(),
                TurnFlow::Trade(TradeFlow::Running) => self.begin_trade_phase(),
                TurnFlow::Civilians => {
                    self.turn_flow = TurnFlow::Military(MilitaryFlow::Running);
                    self.do_civilians();
                }
                TurnFlow::Military(MilitaryFlow::Running) => {
                    self.turn_flow = match self.do_military() {
                        Some(continuation) => {
                            TurnFlow::Military(MilitaryFlow::NavalBattle(continuation))
                        }
                        None => TurnFlow::CombatMoves(CombatMovesFlow::Running),
                    };
                }
                TurnFlow::CombatMoves(CombatMovesFlow::Running) => {
                    self.turn_flow = match self.do_combat_moves() {
                        Some(continuation) => {
                            TurnFlow::CombatMoves(CombatMovesFlow::LandBattle(continuation))
                        }
                        None => TurnFlow::MilitaryCleanup,
                    };
                }
                TurnFlow::MilitaryCleanup => {
                    self.turn_flow = TurnFlow::DiplomacyOfferGate(DiplomacyOfferGateFlow::Running);
                    self.do_military_cleanup();
                }
                TurnFlow::DiplomacyOfferGate(DiplomacyOfferGateFlow::Running) => {
                    self.turn_flow = if self.diplomacy_offer_gate() {
                        TurnFlow::DiplomacyOfferGate(DiplomacyOfferGateFlow::PostCombatReports)
                    } else {
                        TurnFlow::Elimination(EliminationFlow::Running)
                    };
                }
                TurnFlow::Elimination(EliminationFlow::Running) => {
                    self.turn_flow = match self.do_elimination_phase() {
                        EliminationOutcome::Continue => TurnFlow::CityAndTransport,
                        EliminationOutcome::PlayerEliminated => {
                            TurnFlow::Elimination(EliminationFlow::PlayerEliminated)
                        }
                        EliminationOutcome::Victory => {
                            TurnFlow::Elimination(EliminationFlow::Victory)
                        }
                    };
                }
                TurnFlow::CityAndTransport => self.apply_city_and_transport_case(),
                TurnFlow::GreatPowerPressure(GreatPowerPressureFlow::Running) => {
                    self.turn_flow = if self.do_great_power_pressure_phase() {
                        // `mode` is still `0x0b`; movie factory default is `"lose"`, then
                        // `ReinitializeGameFlow` — not the council path.
                        TurnFlow::GreatPowerPressure(GreatPowerPressureFlow::Loss)
                    } else {
                        TurnFlow::DealBook(DealBookFlow::Running)
                    };
                }
                TurnFlow::DealBook(DealBookFlow::Running) => {
                    self.turn_flow = if self.event_eligible(self.turn.active_nation) {
                        TurnFlow::DealBook(DealBookFlow::Open)
                    } else {
                        TurnFlow::QuarterGate(QuarterGateFlow::Running)
                    };
                }
                TurnFlow::QuarterGate(QuarterGateFlow::Running) => {
                    let next = self.post_quarter_gate();
                    self.turn_flow = match self.quarter_gate() {
                        QuarterGateResult::Continue => next.flow(),
                        QuarterGateResult::DecadeCinematic => {
                            TurnFlow::QuarterGate(QuarterGateFlow::DecadeCinematic(next))
                        }
                    };
                }
                TurnFlow::SeasonAdvance => self.advance_season_phase(),
                TurnFlow::TechnologyAdvances(TechnologyFlow::Running) => {
                    self.apply_technology_advances_phase();
                    self.turn_flow = match self.consume_interactive_technology_unlock() {
                        Some(tech_id) => {
                            TurnFlow::TechnologyAdvances(TechnologyFlow::Report(tech_id))
                        }
                        None => TurnFlow::Newspaper(NewspaperFlow::Running),
                    };
                }
                TurnFlow::Newspaper(NewspaperFlow::Running) => {
                    self.construct_newspaper_pages();
                    self.mark_all_pending_status_flags_handled();
                    self.turn_flow = TurnFlow::Newspaper(NewspaperFlow::Reading);
                }
                TurnFlow::ReturnToMap => self.return_to_map(),
                _ => unreachable!("interrupt_stop answers every waiting turn flow"),
            }
        }
    }

    /// Stop the current flow waits on, or `None` when the driver can run it.
    fn interrupt_stop(&self) -> Option<TurnStop> {
        match &self.turn_flow {
            TurnFlow::Diplomacy(DiplomacyFlow::Offer { .. }) => Some(TurnStop::DiplomacyOffer),
            TurnFlow::Diplomacy(DiplomacyFlow::WarJoin(_)) => Some(TurnStop::DiplomacyWarJoin),
            TurnFlow::Trade(TradeFlow::AwaitingOffer { .. }) => Some(TurnStop::TradeOffer),
            TurnFlow::Military(MilitaryFlow::NavalBattle(_)) => Some(TurnStop::NavalBattle),
            TurnFlow::CombatMoves(CombatMovesFlow::LandBattle(_)) => Some(TurnStop::LandBattle),
            TurnFlow::DiplomacyOfferGate(DiplomacyOfferGateFlow::PostCombatReports) => {
                Some(TurnStop::PostCombatReports)
            }
            TurnFlow::Elimination(EliminationFlow::PlayerEliminated) => {
                Some(TurnStop::PlayerEliminated)
            }
            TurnFlow::Elimination(EliminationFlow::Victory) => Some(TurnStop::Victory),
            TurnFlow::GreatPowerPressure(GreatPowerPressureFlow::Loss) => {
                Some(TurnStop::GreatPowerLoss)
            }
            TurnFlow::QuarterGate(QuarterGateFlow::DecadeCinematic(_)) => {
                Some(TurnStop::DecadeCinematic)
            }
            TurnFlow::TechnologyAdvances(TechnologyFlow::Report(_)) => {
                Some(TurnStop::TechnologyAdvance)
            }
            TurnFlow::Newspaper(NewspaperFlow::Reading) => Some(TurnStop::Newspaper),
            TurnFlow::DealBook(DealBookFlow::Open) => Some(TurnStop::DealBook),
            TurnFlow::TopTenScores => Some(TurnStop::Victory),
            TurnFlow::OpeningCinematicLose => Some(TurnStop::PlayerEliminated),
            TurnFlow::CouncilOfGovernors(_) => Some(TurnStop::CouncilOfGovernors),
            TurnFlow::GameScore => Some(TurnStop::GameScore),
            TurnFlow::HighScores => Some(TurnStop::HighScores),
            TurnFlow::SessionEnded => Some(TurnStop::SessionEnded),
            TurnFlow::CapitalSelection
            | TurnFlow::StrategicMap
            | TurnFlow::Diplomacy(DiplomacyFlow::Running)
            | TurnFlow::Trade(TradeFlow::Running)
            | TurnFlow::Civilians
            | TurnFlow::Military(MilitaryFlow::Running)
            | TurnFlow::CombatMoves(CombatMovesFlow::Running)
            | TurnFlow::MilitaryCleanup
            | TurnFlow::DiplomacyOfferGate(DiplomacyOfferGateFlow::Running)
            | TurnFlow::Elimination(EliminationFlow::Running)
            | TurnFlow::CityAndTransport
            | TurnFlow::GreatPowerPressure(GreatPowerPressureFlow::Running)
            | TurnFlow::DealBook(DealBookFlow::Running)
            | TurnFlow::QuarterGate(QuarterGateFlow::Running)
            | TurnFlow::SeasonAdvance
            | TurnFlow::TechnologyAdvances(TechnologyFlow::Running)
            | TurnFlow::Newspaper(NewspaperFlow::Running)
            | TurnFlow::ReturnToMap => None,
        }
    }

    /// Retail case 8 body: write the resume phase, then `DoCityAndTransport`.
    pub fn apply_city_and_transport_case(&mut self) {
        self.turn_flow = TurnFlow::GreatPowerPressure(GreatPowerPressureFlow::Running);
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
    use super::{
        DealBookFlow, DiplomacyOfferGateFlow, EliminationFlow, GreatPowerPressureFlow,
        NewspaperFlow, PostQuarterGate, QuarterGateFlow, TechnologyFlow, TradeFlow, TurnFlow,
    };
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
        state.turn_flow = TurnFlow::CityAndTransport;
        let stop = state.advance_turn();
        assert_eq!(stop, crate::TurnStop::DealBook);
        assert_eq!(state.turn_flow, TurnFlow::DealBook(DealBookFlow::Open));
        assert_eq!(state.phase(), crate::PhaseCode::DEAL_BOOK);
    }

    #[test]
    fn closing_the_turn_deal_book_enters_the_quarter_gate() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        state.turn_flow = TurnFlow::CityAndTransport;
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
            state.turn_flow,
            TurnFlow::TechnologyAdvances(TechnologyFlow::Report(_))
                | TurnFlow::Newspaper(NewspaperFlow::Reading)
        ));
    }

    #[test]
    fn closing_the_deal_book_returns_to_player_orders_through_newspaper() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        state.turn_flow = TurnFlow::CityAndTransport;
        assert_eq!(state.advance_turn(), crate::TurnStop::DealBook);
        let start_turn = state.turn.economic_turn;
        let mut stop = state.close_turn_deal_book();
        while let crate::TurnStop::TechnologyAdvance = stop {
            stop = state.acknowledge_technology_report();
        }
        assert_eq!(stop, crate::TurnStop::Newspaper);
        assert_eq!(state.turn_flow, TurnFlow::Newspaper(NewspaperFlow::Reading));
        assert_eq!(state.turn.economic_turn, start_turn + 1);
        assert_eq!(state.close_newspaper(false), crate::TurnStop::PlayerOrders);
        assert_eq!(state.turn_flow, TurnFlow::StrategicMap);
    }

    #[test]
    fn answering_a_diplomacy_offer_uses_core_flow_not_the_prompt() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        pose_alliance_offer(&mut state);

        let crate::TurnStop::DiplomacyOffer = state.finish_player_orders(true) else {
            panic!("expected a diplomacy offer stop");
        };
        let prompt = state
            .current_diplomacy_offer()
            .expect("diplomacy offer flow");
        assert_eq!(state.phase(), crate::PhaseCode::DIPLOMACY);
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
            .expect("diplomacy offer flow");
        assert_eq!(state.phase(), crate::PhaseCode::DIPLOMACY);
        assert_eq!(state.current_diplomacy_offer(), Some(prompt));

        let mut stop = state.answer_current_diplomacy_offer(true);
        if let crate::TurnStop::TradeOffer = stop {
            assert!(matches!(
                state.turn_flow,
                TurnFlow::Trade(TradeFlow::AwaitingOffer { .. })
            ));
            while let crate::TurnStop::TradeOffer = stop {
                stop = state.answer_trade_offer(0, false);
            }
        }
        assert_eq!(stop, crate::TurnStop::DealBook);
        assert_eq!(state.turn_flow, TurnFlow::DealBook(DealBookFlow::Open));
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
        state.turn_flow = TurnFlow::Trade(TradeFlow::Running);
        state
    }

    #[test]
    fn answer_trade_offer_does_not_immediately_restart_trade() {
        let mut state = human_clothing_offer_state();
        seed_town_tiles(&mut state);
        assert_eq!(state.advance_turn(), crate::TurnStop::TradeOffer);
        let stop = state.answer_trade_offer(0, false);
        assert!(!matches!(state.turn_flow, TurnFlow::Trade(_)));
        assert_ne!(stop, crate::TurnStop::TradeOffer);
    }

    #[test]
    fn completing_trade_continues_through_civilians_to_deal_book() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        state.turn_flow = TurnFlow::Trade(TradeFlow::Running);
        let mut stop = state.advance_turn();
        while let crate::TurnStop::TradeOffer = stop {
            stop = state.answer_trade_offer(0, false);
        }
        assert!(state.pending_trade_offer().is_none());
        assert_eq!(stop, crate::TurnStop::DealBook);
        assert_eq!(state.turn_flow, TurnFlow::DealBook(DealBookFlow::Open));
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
        state.turn_flow = TurnFlow::Trade(TradeFlow::Running);
        state.begin_trade_phase();
        let encoded = serde_json::to_vec(&state).expect("serialize");
        let restored: crate::GameState = serde_json::from_slice(&encoded).expect("deserialize");
        assert_eq!(restored.pending_trade_offer(), state.pending_trade_offer());
        assert_eq!(restored.turn_flow, state.turn_flow);
    }

    #[test]
    fn capital_selection_advances_season_and_builds_newspaper_before_stopping() {
        let mut state = game_state();
        state.turn_flow = TurnFlow::CapitalSelection;
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
            assert_eq!(state.turn_flow, TurnFlow::Newspaper(NewspaperFlow::Reading));
            assert!(state.pending.newspaper_events.is_empty());
        } else {
            assert!(matches!(
                state.turn_flow,
                TurnFlow::TechnologyAdvances(TechnologyFlow::Report(_))
            ));
        }
    }

    #[test]
    fn newspaper_stop_constructs_pages_before_returning() {
        let mut state = game_state();
        state.turn_flow = TurnFlow::Newspaper(NewspaperFlow::Running);
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
        assert_eq!(state.turn_flow, TurnFlow::Newspaper(NewspaperFlow::Reading));
        assert!(state.pending.newspaper_events.is_empty());
        assert!(state.news.pages[MajorNationId::new(0)].is_some());
    }

    #[test]
    fn the_open_newspaper_does_not_rebuild_its_pages() {
        let mut state = game_state();
        state.turn_flow = TurnFlow::Newspaper(NewspaperFlow::Running);
        assert_eq!(state.advance_turn(), crate::TurnStop::Newspaper);
        let pages = state.news.pages.clone();
        assert_eq!(state.advance_turn(), crate::TurnStop::Newspaper);
        assert_eq!(state.news.pages, pages);
    }

    #[test]
    fn newspaper_marks_queued_navy_growth_as_handled_reward_level() {
        let mut state = game_state();
        let nation = MajorNationId::new(0);
        state.nations.majors[&nation].economy.pending_actions
            [crate::PendingActionKind::NavyGrowthReward] =
            crate::PendingActionState::new(crate::PendingActionStatus::QUEUED, Some(1));
        state.turn_flow = TurnFlow::Newspaper(NewspaperFlow::Running);
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
        state.turn_flow = TurnFlow::DiplomacyOfferGate(DiplomacyOfferGateFlow::Running);
        assert_eq!(state.advance_turn(), crate::TurnStop::PostCombatReports);
        assert_eq!(
            state.turn_flow,
            TurnFlow::DiplomacyOfferGate(DiplomacyOfferGateFlow::PostCombatReports)
        );
        assert_eq!(state.phase(), crate::PhaseCode::DIPLOMACY_OFFER);
    }

    #[test]
    fn elimination_outcomes_are_explicit_turn_stops() {
        let mut eliminated = game_state();
        seed_town_tiles(&mut eliminated);
        eliminated.nations.set_country_status(
            eliminated.turn.active_nation,
            crate::CountryStatus::ProtectorateOf(NationId::new(1)),
        );
        eliminated.turn_flow = TurnFlow::Elimination(EliminationFlow::Running);
        assert_eq!(eliminated.advance_turn(), crate::TurnStop::PlayerEliminated);
        assert_eq!(
            eliminated.turn_flow,
            TurnFlow::Elimination(EliminationFlow::PlayerEliminated)
        );

        let mut victory = game_state();
        let survivor = MajorNationId::new(0);
        victory.turn.active_nation = survivor.nation();
        victory
            .nations
            .append_owned_region_during_construction(survivor.nation(), crate::ProvinceId::new(0));
        victory.turn_flow = TurnFlow::Elimination(EliminationFlow::Running);
        assert_eq!(victory.advance_turn(), crate::TurnStop::Victory);
        assert_eq!(
            victory.turn_flow,
            TurnFlow::Elimination(EliminationFlow::Victory)
        );
    }

    #[test]
    fn decade_cinematic_is_an_explicit_turn_stop() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        state.turn.economic_turn = 40;
        state.turn.phase_state_by_decade[crate::Decade::Second as usize] = 1;
        state.turn_flow = TurnFlow::QuarterGate(QuarterGateFlow::Running);
        assert_eq!(state.advance_turn(), crate::TurnStop::DecadeCinematic);
        assert_eq!(
            state.turn_flow,
            TurnFlow::QuarterGate(QuarterGateFlow::DecadeCinematic(
                PostQuarterGate::SeasonAdvance
            ))
        );
        assert_eq!(state.phase(), crate::PhaseCode::QUARTER_GATE);
    }

    #[test]
    fn quiet_full_turn_stops_at_deal_book_then_returns_to_player_orders() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        let stop = state.finish_player_orders(true);
        assert_eq!(stop, crate::TurnStop::DealBook);
        assert_eq!(state.turn_flow, TurnFlow::DealBook(DealBookFlow::Open));
        let start_turn = state.turn.economic_turn;
        let mut stop = state.close_turn_deal_book();
        while let crate::TurnStop::TechnologyAdvance = stop {
            stop = state.acknowledge_technology_report();
        }
        assert_eq!(stop, crate::TurnStop::Newspaper);
        assert_eq!(state.close_newspaper(false), crate::TurnStop::PlayerOrders);
        assert_eq!(state.turn_flow, TurnFlow::StrategicMap);
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
        assert_eq!(state.turn_flow, TurnFlow::StrategicMap);

        assert!(!matches!(
            state.finish_player_orders(true),
            crate::TurnStop::TurnAlerts(_)
        ));
        assert_ne!(state.turn_flow, TurnFlow::StrategicMap);
    }

    #[test]
    fn opening_cinematic_movie_follows_entered_mode() {
        let mut state = game_state();
        state.turn_flow = TurnFlow::QuarterGate(QuarterGateFlow::DecadeCinematic(
            PostQuarterGate::SeasonAdvance,
        ));
        assert_eq!(state.opening_cinematic_movie(), crate::CinematicKind::Vote);
        state.turn_flow = TurnFlow::TopTenScores;
        assert_eq!(state.opening_cinematic_movie(), crate::CinematicKind::Win);
        state.turn_flow = TurnFlow::Elimination(EliminationFlow::Victory);
        assert_eq!(state.opening_cinematic_movie(), crate::CinematicKind::Win);
        state.turn_flow = TurnFlow::OpeningCinematicLose;
        assert_eq!(state.opening_cinematic_movie(), crate::CinematicKind::Lose);
        state.turn_flow = TurnFlow::Elimination(EliminationFlow::PlayerEliminated);
        assert_eq!(state.opening_cinematic_movie(), crate::CinematicKind::Lose);
        state.turn_flow = TurnFlow::GreatPowerPressure(GreatPowerPressureFlow::Loss);
        assert_eq!(state.opening_cinematic_movie(), crate::CinematicKind::Lose);
    }

    #[test]
    fn decade_cinematic_close_enters_council_with_the_chosen_phase() {
        let mut state = game_state();
        state.turn_flow = TurnFlow::QuarterGate(QuarterGateFlow::DecadeCinematic(
            PostQuarterGate::SeasonAdvance,
        ));
        assert_eq!(
            state.close_opening_cinematic(),
            crate::TurnStop::CouncilOfGovernors
        );
        assert_eq!(
            state.turn_flow,
            TurnFlow::CouncilOfGovernors(PostQuarterGate::SeasonAdvance)
        );
        assert_eq!(state.phase(), crate::PhaseCode::SEASON_ADVANCE);
    }

    #[test]
    fn top_ten_scores_win_movie_closes_into_council() {
        let mut state = game_state();
        state.turn_flow = TurnFlow::TopTenScores;
        assert_eq!(state.advance_turn(), crate::TurnStop::Victory);
        assert_eq!(
            state.close_opening_cinematic(),
            crate::TurnStop::CouncilOfGovernors
        );
        assert_eq!(
            state.turn_flow,
            TurnFlow::CouncilOfGovernors(PostQuarterGate::TopTenScores)
        );
    }

    #[test]
    fn elimination_win_close_enters_game_score() {
        let mut state = game_state();
        state.turn_flow = TurnFlow::Elimination(EliminationFlow::Victory);
        assert_eq!(state.close_opening_cinematic(), crate::TurnStop::GameScore);
        assert_eq!(state.close_game_score(), crate::TurnStop::HighScores);
        assert_eq!(state.close_high_scores(), crate::TurnStop::SessionEnded);
        assert_eq!(state.turn_flow, TurnFlow::SessionEnded);
    }

    #[test]
    fn pressure_loss_close_ends_the_session() {
        let mut state = game_state();
        state.turn_flow = TurnFlow::GreatPowerPressure(GreatPowerPressureFlow::Loss);
        assert_eq!(
            state.close_opening_cinematic(),
            crate::TurnStop::SessionEnded
        );
        assert_eq!(state.turn_flow, TurnFlow::SessionEnded);
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
