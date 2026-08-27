use crate::{
    Difficulty, DiplomacyOfferPrompt, DiplomacyWarJoinPrompt, EliminationOutcome, GameState,
    MajorNationId, NationId, QuarterGateResult, Technology, TradeProgress,
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

/// One completed human depot/port that still needs the retail `TNewTownView`
/// naming interaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PendingTownNaming {
    pub nation: MajorNationId,
    pub tile: crate::TileId,
}

/// Why simulation is currently blocked. [`GameState::stop`] is the only copy.
///
/// A turn operation mutates [`GameState`] until it reaches another stop. It
/// does not also return that stop. Resume methods `take` the stored stop,
/// run, and `halt` when blocked again. Stored stops join semantic `GameState`
/// serialization; the `.imp` writer omits them because retail cannot save at
/// these boundaries.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub enum TurnStop {
    /// Strategic map: the pending interaction is player orders.
    #[default]
    PlayerOrders,
    /// Outstanding human depot/port namings, head first.
    TownNaming {
        current: PendingTownNaming,
        remaining: Vec<PendingTownNaming>,
    },
    DiplomacyOffer {
        nation: MajorNationId,
        index: u8,
    },
    DiplomacyWarJoin(DiplomacyWarJoinPrompt),
    Trade(crate::TradeSession),
    LandBattle(crate::CombatMovesContinuation),
    NavalBattle(crate::NavyOrdersContinuation),
    TechnologyReport(Technology),
    DealBook,
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
    /// Stores the blocking interaction. The driver must not already be halted.
    pub(crate) fn halt(&mut self, stop: TurnStop) {
        assert!(
            self.stop.is_none(),
            "halt requires a running driver; consume the previous stop first"
        );
        self.stop = Some(stop);
    }

    fn continue_after_phase_body(&mut self) -> bool {
        if self.stop.is_some() {
            return true;
        }
        false
    }

    pub(crate) fn halt_town_namings(&mut self, mut namings: Vec<PendingTownNaming>) -> bool {
        if namings.is_empty() {
            return false;
        }
        let current = namings.remove(0);
        self.halt(TurnStop::TownNaming {
            current,
            remaining: namings,
        });
        true
    }

    /// Retail `TSimMgr::ReadFrom` discards the serialized turn phase, enters phase 4,
    /// and immediately advances to the strategic map.
    pub fn resume_retail_save_on_strategic_map(&mut self) {
        self.turn.phase = PhaseCode::STRATEGIC_MAP;
        if self.stop.is_none() {
            self.halt(TurnStop::PlayerOrders);
        }
    }

    /// Ends player orders on the strategic map and runs the turn until the next stop.
    pub fn finish_player_orders(&mut self, turn_alerts_enabled: bool) {
        assert_eq!(self.turn.phase(), PhaseCode::STRATEGIC_MAP);
        match self.stop.take() {
            Some(TurnStop::PlayerOrders | TurnStop::TurnAlerts(_)) => {}
            other => panic!(
                "player-order finish requires a player-orders or turn-alert stop, got {other:?}"
            ),
        }
        let alerts = self.show_turn_alerts(turn_alerts_enabled);
        if !alerts.is_empty() {
            self.halt(TurnStop::TurnAlerts(alerts));
            return;
        }
        self.turn.phase = PhaseCode::DIPLOMACY;
        self.advance_turn();
    }

    /// Accepts or rejects the diplomacy offer stored in the current stop.
    pub fn answer_current_diplomacy_offer(&mut self, accept: bool) {
        if matches!(
            self.resolve_diplomacy_offer(accept),
            crate::DiplomacyPhaseResult::Resolved
        ) {
            self.advance_turn();
        }
    }

    /// Accepts or rejects the war-join dialog stored in the current stop.
    pub fn answer_current_diplomacy_war_join(&mut self, accept: bool) {
        if matches!(
            self.resolve_diplomacy_war_join(accept),
            crate::DiplomacyPhaseResult::Resolved
        ) {
            self.advance_turn();
        }
    }

    /// Applies the Offer Sheet decision and resumes ranked trade deals.
    pub fn answer_trade_offer(&mut self, quantity: i16, stop_buying: bool) {
        if matches!(
            self.reply_to_trade_offer(quantity, stop_buying),
            TradeProgress::Complete
        ) {
            self.advance_turn();
        }
    }

    /// Closes the Deal Book opened by the turn driver and continues the turn.
    pub fn close_turn_deal_book(&mut self) {
        assert_eq!(self.turn.phase(), PhaseCode::QUARTER_GATE);
        let Some(TurnStop::DealBook) = self.stop.take() else {
            panic!("deal-book close requires an active deal-book stop");
        };
        self.advance_turn();
    }

    /// Dismisses the technology report and continues the turn.
    pub fn acknowledge_technology_report(&mut self) {
        let Some(TurnStop::TechnologyReport(_)) = self.stop.take() else {
            panic!("technology report answer requires an active technology stop");
        };
        if let Some(tech_id) = self.consume_interactive_technology_unlock() {
            self.halt(TurnStop::TechnologyReport(tech_id));
            return;
        }
        self.advance_turn();
    }

    /// Dismisses the newspaper and returns to player orders. Retail's map-entry
    /// music selection consumes the process-global CRT stream when music is enabled.
    pub fn close_newspaper(&mut self, music_enabled: bool) {
        assert_eq!(self.turn.phase(), PhaseCode::RETURN_TO_MAP);
        let Some(TurnStop::Newspaper) = self.stop.take() else {
            panic!("newspaper close requires an active newspaper stop");
        };
        self.return_to_map();
        if let Some((unit, _)) = self.first_idle_civilian(self.turn.active_nation) {
            self.activate_civilian_selection(unit);
        }
        if music_enabled && self.turn.turn_cooldown_defer_counter < 1 {
            self.rng.next_crt_rand();
        }
        self.halt(TurnStop::PlayerOrders);
    }

    /// Movie clip for `kTurnEventOpeningCinematic`. Switches on the entered mode, not
    /// the already-updated `turnStateCode` (`HandleTurnEventDialogFactorySlotF4`).
    pub fn opening_cinematic_movie(&self) -> CinematicKind {
        match self.stop.as_ref() {
            Some(TurnStop::DecadeCinematic) => CinematicKind::Vote,
            Some(TurnStop::Victory) => CinematicKind::Win,
            Some(TurnStop::PlayerEliminated | TurnStop::GreatPowerLoss) => CinematicKind::Lose,
            _ => CinematicKind::Lose,
        }
    }

    /// Pressure-loss movie finished. Retail reinitializes; it does not continue to Deal Book.
    pub fn acknowledge_great_power_loss(&mut self) {
        let Some(TurnStop::GreatPowerLoss) = self.stop.take() else {
            panic!("great-power loss resume requires a great-power-loss stop");
        };
        self.halt(TurnStop::SessionEnded);
    }

    /// Closes `TBattleReportView`. Reports stay until the next military phase's
    /// `CleanUpStacks`; phase is already `ELIMINATION`.
    pub fn close_post_combat_reports(&mut self) {
        let Some(TurnStop::PostCombatReports) = self.stop.take() else {
            panic!("post-combat report resume requires a post-combat stop");
        };
        self.advance_turn();
    }

    /// After the opening cinematic: vote/win/lose from 0x0e/0x16/0x17 go to council;
    /// elimination win goes to Game Score; elimination/pressure loss ends the session.
    pub fn close_opening_cinematic(&mut self) {
        match self.stop.take() {
            Some(TurnStop::DecadeCinematic) => self.halt(TurnStop::CouncilOfGovernors),
            Some(TurnStop::Victory) if self.turn.phase() == PhaseCode::TOP_TEN_SCORES => {
                self.halt(TurnStop::CouncilOfGovernors)
            }
            Some(TurnStop::Victory) => self.halt(TurnStop::GameScore),
            Some(TurnStop::PlayerEliminated)
                if self.turn.phase() == PhaseCode::OPENING_CINEMATIC =>
            {
                self.halt(TurnStop::CouncilOfGovernors)
            }
            Some(TurnStop::PlayerEliminated | TurnStop::GreatPowerLoss) => {
                self.halt(TurnStop::SessionEnded)
            }
            other => panic!("opening cinematic resume requires a cinematic stop, got {other:?}"),
        }
    }

    /// Council of Governors closed. `StartNextPhase` uses the already-updated phase.
    pub fn close_council_of_governors(&mut self) {
        let Some(TurnStop::CouncilOfGovernors) = self.stop.take() else {
            panic!("council resume requires a council stop");
        };
        self.advance_turn();
    }

    /// Game Score `done` posts `kTurnEventHighScores` after reinitialize.
    pub fn close_game_score(&mut self) {
        let Some(TurnStop::GameScore) = self.stop.take() else {
            panic!("game-score resume requires a game-score stop");
        };
        self.halt(TurnStop::HighScores);
    }

    /// High-score table dismissed. Retail reinitializes to the main menu.
    pub fn close_high_scores(&mut self) {
        let Some(TurnStop::HighScores) = self.stop.take() else {
            panic!("high-scores close requires an active high-scores stop");
        };
        self.halt(TurnStop::SessionEnded);
    }

    pub fn current_diplomacy_offer(&self) -> Option<DiplomacyOfferPrompt> {
        let Some(TurnStop::DiplomacyOffer { nation, index }) = self.stop else {
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
        match self.stop {
            Some(TurnStop::DiplomacyWarJoin(prompt)) => Some(prompt),
            _ => None,
        }
    }

    pub fn current_technology_report(&self) -> Option<Technology> {
        match self.stop {
            Some(TurnStop::TechnologyReport(tech_id)) => Some(tech_id),
            _ => None,
        }
    }

    /// Runs the turn driver until the next halt. The game must not already be stopped.
    pub fn advance_turn(&mut self) {
        assert!(
            self.stop.is_none(),
            "advance_turn requires a running driver; consume the current stop first"
        );
        loop {
            match self.turn.phase() {
                PhaseCode::STRATEGIC_MAP => {
                    self.halt(TurnStop::PlayerOrders);
                    return;
                }
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
                    self.turn.phase = PhaseCode::TRADE;
                    self.do_diplomacy();
                    if self.continue_after_phase_body() {
                        return;
                    }
                }
                PhaseCode::TRADE => {
                    self.turn.phase = PhaseCode::CIVILIANS;
                    self.begin_trade_phase();
                    if self.continue_after_phase_body() {
                        return;
                    }
                }
                PhaseCode::CIVILIANS => {
                    self.turn.phase = PhaseCode::MILITARY;
                    let namings = self.do_civilians();
                    if self.halt_town_namings(namings) {
                        return;
                    }
                }
                PhaseCode::MILITARY => {
                    self.turn.phase = PhaseCode::COMBAT_MOVES;
                    if let Some(continuation) = self.do_military() {
                        self.halt(TurnStop::NavalBattle(continuation));
                        return;
                    }
                }
                PhaseCode::COMBAT_MOVES => {
                    self.turn.phase = PhaseCode::MILITARY_CLEANUP;
                    if let Some(continuation) = self.do_combat_moves() {
                        self.halt(TurnStop::LandBattle(continuation));
                        return;
                    }
                }
                PhaseCode::MILITARY_CLEANUP => {
                    self.turn.phase = PhaseCode::DIPLOMACY_OFFER;
                    self.do_military_cleanup();
                }
                PhaseCode::CITY_AND_TRANSPORT => self.apply_city_and_transport_case(),
                PhaseCode::GREAT_POWER_PRESSURE => {
                    self.turn.phase = PhaseCode::DEAL_BOOK;
                    if self.do_great_power_pressure_phase() {
                        // `mode` is still `0x0b`; movie factory default is `"lose"`, then
                        // `ReinitializeGameFlow` — not the council path.
                        self.halt(TurnStop::GreatPowerLoss);
                        return;
                    }
                }
                PhaseCode::DEAL_BOOK => {
                    self.turn.phase = PhaseCode::QUARTER_GATE;
                    if self.event_eligible(self.turn.active_nation) {
                        self.halt(TurnStop::DealBook);
                        return;
                    }
                }
                PhaseCode::DIPLOMACY_OFFER => {
                    self.turn.phase = PhaseCode::ELIMINATION;
                    if self.diplomacy_offer_gate() {
                        self.halt(TurnStop::PostCombatReports);
                        return;
                    }
                }
                PhaseCode::ELIMINATION => {
                    self.turn.phase = PhaseCode::CITY_AND_TRANSPORT;
                    match self.do_elimination_phase() {
                        EliminationOutcome::Continue => {}
                        EliminationOutcome::PlayerEliminated => {
                            self.halt(TurnStop::PlayerEliminated);
                            return;
                        }
                        EliminationOutcome::Victory => {
                            self.halt(TurnStop::Victory);
                            return;
                        }
                    }
                }
                PhaseCode::QUARTER_GATE => {
                    if self.quarter_gate() == QuarterGateResult::DecadeCinematic {
                        self.halt(TurnStop::DecadeCinematic);
                        return;
                    }
                }
                PhaseCode::TOP_TEN_SCORES => {
                    // Case `0x16`: scores then `"win"` movie; follow-up is council.
                    self.halt(TurnStop::Victory);
                    return;
                }
                PhaseCode::OPENING_CINEMATIC => {
                    // Case `0x17`: `"lose"` movie; follow-up is council.
                    self.halt(TurnStop::PlayerEliminated);
                    return;
                }
                PhaseCode::SEASON_ADVANCE => {
                    self.advance_season_phase();
                }
                PhaseCode::TECHNOLOGY_ADVANCES => {
                    self.turn.phase = PhaseCode::NEWSPAPER;
                    if let Some(tech_id) = self.run_technology_advances() {
                        self.halt(TurnStop::TechnologyReport(tech_id));
                        return;
                    }
                }
                PhaseCode::NEWSPAPER => {
                    self.turn.phase = PhaseCode::RETURN_TO_MAP;
                    self.construct_newspaper_pages();
                    self.mark_all_pending_status_flags_handled();
                    self.halt(TurnStop::Newspaper);
                    return;
                }
                PhaseCode::RETURN_TO_MAP => {
                    self.return_to_map();
                }
                phase => panic!("unsupported internal turn phase {phase:?}"),
            }
        }
    }

    fn run_technology_advances(&mut self) -> Option<Technology> {
        self.apply_technology_advances_phase();
        self.consume_interactive_technology_unlock()
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
        DiplomaticRelationship, GameState, MajorNationId, NationId, ProvinceId, ResourceKind,
        ShipType, TileId, TileOwnerTag, TradeProgress,
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

    fn start_driver_at(state: &mut GameState, phase: crate::PhaseCode) {
        state.stop = None;
        state.turn.phase = phase;
        state.advance_turn();
    }

    fn dismiss_technology_reports(state: &mut GameState) {
        while matches!(state.stop(), crate::TurnStop::TechnologyReport(_)) {
            state.acknowledge_technology_report();
        }
    }

    fn complete_trade_offers(state: &mut GameState) {
        while matches!(state.stop(), crate::TurnStop::Trade(_)) {
            state.answer_trade_offer(0, false);
        }
    }

    #[test]
    fn city_and_transport_stops_at_deal_book_when_pressure_does_not_alert() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        start_driver_at(&mut state, crate::PhaseCode::CITY_AND_TRANSPORT);
        assert!(matches!(state.stop(), crate::TurnStop::DealBook));
        assert_eq!(state.turn.phase(), crate::PhaseCode::QUARTER_GATE);
    }

    #[test]
    fn closing_the_turn_deal_book_enters_the_quarter_gate() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        start_driver_at(&mut state, crate::PhaseCode::CITY_AND_TRANSPORT);
        assert!(matches!(state.stop(), crate::TurnStop::DealBook));
        state.close_turn_deal_book();
        assert!(
            matches!(
                state.stop(),
                crate::TurnStop::TechnologyReport(_) | crate::TurnStop::Newspaper
            ),
            "unexpected stop {:?}",
            state.stop()
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
        start_driver_at(&mut state, crate::PhaseCode::CITY_AND_TRANSPORT);
        assert!(matches!(state.stop(), crate::TurnStop::DealBook));
        let start_turn = state.turn.economic_turn;
        state.close_turn_deal_book();
        dismiss_technology_reports(&mut state);
        assert!(matches!(state.stop(), crate::TurnStop::Newspaper));
        assert_eq!(state.turn.phase(), crate::PhaseCode::RETURN_TO_MAP);
        assert_eq!(state.turn.economic_turn, start_turn + 1);
        state.close_newspaper(false);
        assert!(matches!(state.stop(), crate::TurnStop::PlayerOrders));
        assert_eq!(state.turn.phase(), crate::PhaseCode::STRATEGIC_MAP);
    }

    #[test]
    fn answering_a_diplomacy_offer_uses_the_core_stop_not_the_prompt() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        pose_alliance_offer(&mut state);

        state.finish_player_orders(true);
        let crate::TurnStop::DiplomacyOffer { .. } = state.stop() else {
            panic!("expected a diplomacy offer stop");
        };
        let prompt = state
            .current_diplomacy_offer()
            .expect("diplomacy offer stop");
        assert_eq!(state.turn.phase(), crate::PhaseCode::TRADE);
        assert_eq!(state.current_diplomacy_offer(), Some(prompt));
        state.answer_current_diplomacy_offer(true);
        assert!(state.current_diplomacy_offer().is_none());
        assert!(
            matches!(
                state.stop(),
                crate::TurnStop::Trade(_) | crate::TurnStop::DealBook
            ),
            "unexpected stop {:?}",
            state.stop()
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

        state.finish_player_orders(true);
        let crate::TurnStop::DiplomacyOffer { .. } = state.stop() else {
            panic!("expected a diplomacy offer stop");
        };
        let prompt = state
            .current_diplomacy_offer()
            .expect("diplomacy offer stop");
        assert_eq!(state.turn.phase(), crate::PhaseCode::TRADE);
        assert_eq!(state.current_diplomacy_offer(), Some(prompt));

        state.answer_current_diplomacy_offer(true);
        if matches!(state.stop(), crate::TurnStop::Trade(_)) {
            assert_eq!(state.turn.phase(), crate::PhaseCode::CIVILIANS);
            complete_trade_offers(&mut state);
        }
        assert!(matches!(state.stop(), crate::TurnStop::DealBook));
        assert_eq!(state.turn.phase(), crate::PhaseCode::QUARTER_GATE);
        assert!(state.pending_trade_offer().is_none());
        assert!(state.pending_land_battle().is_none());
    }

    #[test]
    fn completing_trade_continues_through_civilians_to_deal_book() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        start_driver_at(&mut state, crate::PhaseCode::TRADE);
        complete_trade_offers(&mut state);
        assert!(state.pending_trade_offer().is_none());
        assert!(matches!(state.stop(), crate::TurnStop::DealBook));
        assert_eq!(state.turn.phase(), crate::PhaseCode::QUARTER_GATE);
    }

    #[test]
    fn semantic_state_round_trips_a_trade_stop() {
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
        state.stop = None;
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
        state.turn.economic_turn = 0;
        start_driver_at(&mut state, crate::PhaseCode::CAPITAL_SELECTION);
        assert!(
            matches!(
                state.stop(),
                crate::TurnStop::TechnologyReport(_) | crate::TurnStop::Newspaper
            ),
            "unexpected stop {:?}",
            state.stop()
        );
        assert_eq!(state.turn.economic_turn, 1);
        if matches!(state.stop(), crate::TurnStop::Newspaper) {
            assert_eq!(state.turn.phase(), crate::PhaseCode::RETURN_TO_MAP);
            assert!(state.pending.newspaper_events.is_empty());
        } else {
            assert_eq!(state.turn.phase(), crate::PhaseCode::NEWSPAPER);
        }
    }

    #[test]
    fn newspaper_stop_constructs_pages_before_returning() {
        let mut state = game_state();
        state
            .pending
            .queue_newspaper_event(crate::PendingNewspaperEvent::Miscellaneous {
                audience: None,
                story_code: 3,
            });
        let mut story_ids = vec![1; crate::NEWS_TEMPLATE_COUNT];
        story_ids[0] = -1003;
        state.set_game_data(crate::GameData::from_news_story_ids(story_ids));
        start_driver_at(&mut state, crate::PhaseCode::NEWSPAPER);
        assert!(matches!(state.stop(), crate::TurnStop::Newspaper));
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
        start_driver_at(&mut state, crate::PhaseCode::NEWSPAPER);
        assert!(matches!(state.stop(), crate::TurnStop::Newspaper));
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
        start_driver_at(&mut state, crate::PhaseCode::DIPLOMACY_OFFER);
        assert!(matches!(state.stop(), crate::TurnStop::PostCombatReports));
        assert_eq!(state.turn.phase(), crate::PhaseCode::ELIMINATION);
    }

    #[test]
    fn elimination_outcomes_are_explicit_turn_stops() {
        let mut eliminated = game_state();
        seed_town_tiles(&mut eliminated);
        eliminated.nations.set_country_status(
            eliminated.turn.active_nation,
            crate::CountryStatus::ProtectorateOf(NationId::new(1)),
        );
        start_driver_at(&mut eliminated, crate::PhaseCode::ELIMINATION);
        assert!(matches!(
            eliminated.stop(),
            crate::TurnStop::PlayerEliminated
        ));
        assert_eq!(
            eliminated.turn.phase(),
            crate::PhaseCode::CITY_AND_TRANSPORT
        );

        let mut victory = game_state();
        let survivor = MajorNationId::new(0);
        victory.turn.active_nation = survivor.nation();
        victory
            .nations
            .append_owned_region_during_construction(survivor.nation(), crate::ProvinceId::new(0));
        start_driver_at(&mut victory, crate::PhaseCode::ELIMINATION);
        assert!(matches!(victory.stop(), crate::TurnStop::Victory));
        assert_eq!(victory.turn.phase(), crate::PhaseCode::CITY_AND_TRANSPORT);
    }

    #[test]
    fn decade_cinematic_is_an_explicit_turn_stop() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        state.turn.economic_turn = 40;
        state.turn.phase_state_by_decade[crate::Decade::Second as usize] = 1;
        start_driver_at(&mut state, crate::PhaseCode::QUARTER_GATE);
        assert!(matches!(state.stop(), crate::TurnStop::DecadeCinematic));
        assert_eq!(state.turn.phase(), crate::PhaseCode::SEASON_ADVANCE);
    }

    #[test]
    fn quiet_full_turn_stops_at_deal_book_then_returns_to_player_orders() {
        let mut state = game_state();
        seed_town_tiles(&mut state);
        state.finish_player_orders(true);
        assert!(matches!(state.stop(), crate::TurnStop::DealBook));
        assert_eq!(state.turn.phase(), crate::PhaseCode::QUARTER_GATE);
        let start_turn = state.turn.economic_turn;
        state.close_turn_deal_book();
        dismiss_technology_reports(&mut state);
        assert!(matches!(state.stop(), crate::TurnStop::Newspaper));
        state.close_newspaper(false);
        assert!(matches!(state.stop(), crate::TurnStop::PlayerOrders));
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

        state.finish_player_orders(true);
        let crate::TurnStop::TurnAlerts(alerts) = state.stop() else {
            panic!("expected turn alerts, got {:?}", state.stop());
        };
        assert_eq!(
            alerts,
            &vec![
                crate::TurnAlert::Treasury { prompt_code: 0x25 },
                crate::TurnAlert::Starvation,
            ]
        );
        assert_eq!(state.turn.phase(), crate::PhaseCode::STRATEGIC_MAP);

        state.finish_player_orders(true);
        assert!(!matches!(state.stop(), crate::TurnStop::TurnAlerts(_)));
        assert_ne!(state.turn.phase(), crate::PhaseCode::STRATEGIC_MAP);
    }

    #[test]
    fn opening_cinematic_movie_follows_entered_mode() {
        let mut state = game_state();
        state.stop = Some(crate::TurnStop::DecadeCinematic);
        assert_eq!(state.opening_cinematic_movie(), crate::CinematicKind::Vote);
        state.stop = Some(crate::TurnStop::Victory);
        assert_eq!(state.opening_cinematic_movie(), crate::CinematicKind::Win);
        state.stop = Some(crate::TurnStop::PlayerEliminated);
        assert_eq!(state.opening_cinematic_movie(), crate::CinematicKind::Lose);
        state.stop = Some(crate::TurnStop::GreatPowerLoss);
        assert_eq!(state.opening_cinematic_movie(), crate::CinematicKind::Lose);
    }

    #[test]
    fn decade_cinematic_close_enters_council() {
        let mut state = game_state();
        state.stop = Some(crate::TurnStop::DecadeCinematic);
        state.close_opening_cinematic();
        assert!(matches!(state.stop(), crate::TurnStop::CouncilOfGovernors));
    }

    #[test]
    fn elimination_win_close_enters_game_score() {
        let mut state = game_state();
        state.stop = Some(crate::TurnStop::Victory);
        state.close_opening_cinematic();
        assert!(matches!(state.stop(), crate::TurnStop::GameScore));
        state.close_game_score();
        assert!(matches!(state.stop(), crate::TurnStop::HighScores));
        state.close_high_scores();
        assert!(matches!(state.stop(), crate::TurnStop::SessionEnded));
    }

    #[test]
    fn pressure_loss_close_ends_the_session() {
        let mut state = game_state();
        state.stop = Some(crate::TurnStop::GreatPowerLoss);
        state.close_opening_cinematic();
        assert!(matches!(state.stop(), crate::TurnStop::SessionEnded));
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
