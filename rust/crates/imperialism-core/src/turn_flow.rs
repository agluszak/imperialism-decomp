use crate::{Difficulty, GameState, NationId};
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

    /// Retail `TSimMgr::StartNextPhase` as a compact loop: keep applying one
    /// `AdvanceGlobalTurnStateMachine` case while that case would post another
    /// command-100 continue.
    pub fn start_next_phase(&mut self) -> Option<u8> {
        while self.advance_phase() {}
        if self.turn.phase == PhaseCode::TECHNOLOGY_ADVANCES {
            self.consume_opening_technology_unlock()
        } else {
            None
        }
    }

    /// One `TSimMgr::AdvanceGlobalTurnStateMachine` case. `true` means retail
    /// would post `StartNextPhase` and continue immediately.
    pub fn advance_phase(&mut self) -> bool {
        match self.turn.phase {
            PhaseCode::CAPITAL_SELECTION => {
                self.turn.phase = PhaseCode::SEASON_ADVANCE;
                true
            }
            PhaseCode::SEASON_ADVANCE => {
                self.advance_season_phase();
                true
            }
            PhaseCode::TECHNOLOGY_ADVANCES => {
                // Retail writes newspaper (0xf) first, then maybe continues.
                // Opening-turn consumers stop on the technology UI, so this
                // case keeps `TECHNOLOGY_ADVANCES` and does the tech work here.
                self.apply_technology_advances_phase();
                false
            }
            PhaseCode::CITY_AND_TRANSPORT => {
                self.turn.phase = PhaseCode::GREAT_POWER_PRESSURE;
                self.do_city_and_transport();
                true
            }
            PhaseCode::OFFER_SHEET => {
                self.turn.phase = PhaseCode::MILITARY;
                self.do_civilians();
                true
            }
            _ => false,
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
    use crate::{MajorNationController, MajorNationId, NationId, TileId, TileOwnerTag};

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
    fn start_next_phase_from_capital_selection_advances_season_and_stops_on_technology() {
        let mut state = game_state();
        state.turn.phase = crate::PhaseCode::CAPITAL_SELECTION;
        state.turn.economic_turn = 0;
        state.start_next_phase();
        assert_eq!(state.turn.phase, crate::PhaseCode::TECHNOLOGY_ADVANCES);
        assert_eq!(state.turn.economic_turn, 1);
    }

    #[test]
    fn city_and_transport_phase_case_runs_the_retail_operation_and_continues() {
        let mut state = game_state();
        for index in 0..MajorNationId::COUNT {
            let tile = TileId::new(index as u16 + 1);
            let major = &mut state.nations.majors[MajorNationId::new(index)];
            major.towns[0].tile = tile;
            major.common.home_tile = Some(tile);
        }
        for index in 0..MajorNationId::COUNT {
            let tile = TileId::new(index as u16 + 1);
            state.map[tile].owner_nation = Some(TileOwnerTag::from_nation(NationId::new(index)));
        }
        state.turn.phase = crate::PhaseCode::CITY_AND_TRANSPORT;
        assert!(state.advance_phase());
        assert_eq!(state.turn.phase, crate::PhaseCode::GREAT_POWER_PRESSURE);
    }
}
