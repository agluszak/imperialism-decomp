use crate::{GameEvent, GameState, MajorNationId, StepOutcome, TurnState};

const MAJOR_NATION_COUNT: usize = 7;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum TurnFlowError {
    #[error("major nation slot {slot} is not active")]
    MissingMajorNation { slot: usize },
}

impl TurnState {
    /// Mirrors `TSimMgr::AdvanceSeason`: increment the original signed short with
    /// retail wrapping behavior.
    pub fn advance_season(&mut self) {
        self.economic_turn = self.economic_turn.wrapping_add(1);
    }

    /// Mirrors `TSimMgr::InLinearPhase` exactly, including unknown phase codes.
    pub const fn in_linear_phase(self) -> bool {
        self.phase_code <= 3 || self.phase_code >= 6
    }
}

impl GameState {
    /// Replaces the original posted Windows command with explicit deterministic
    /// domain output. The caller decides when to invoke the phase worker.
    pub fn request_next_phase(&self) -> StepOutcome {
        StepOutcome {
            events: vec![GameEvent::PhaseAdvanceRequested],
        }
    }

    /// Mirrors `TSimMgr::SetFlags`.
    pub fn set_turn_flow_flags(&mut self, flags: u32) {
        self.pending.turn_flow_status_flags |= flags;
    }

    /// Mirrors `TSimMgr::TestTurnFlowStatusFlagMask`.
    pub const fn has_turn_flow_flags(&self, mask: u32) -> bool {
        self.pending.turn_flow_status_flags & mask != 0
    }

    /// Mirrors `TSimMgr::AllHumansFinished`. The C++ routine assumes all seven
    /// major slots exist; Rust reports that violated phase invariant explicitly.
    pub fn all_humans_finished(&self) -> Result<bool, TurnFlowError> {
        all_major_flags_finished((0..MAJOR_NATION_COUNT).map(|slot| {
            self.nations
                .get(MajorNationId::new(slot as u8).nation())
                .and_then(Option::as_ref)
                .and_then(|nation| nation.major())
                .map(|major| major.turn_finished)
        }))
    }

    /// Mirrors `TSimMgr::ResetTurnFlags`: only diplomacy-eligible major nations
    /// have their completion flag cleared.
    pub fn reset_turn_flags(&mut self) -> Result<(), TurnFlowError> {
        for slot in 0..MAJOR_NATION_COUNT {
            let present = self
                .nations
                .get(MajorNationId::new(slot as u8).nation())
                .and_then(Option::as_ref)
                .and_then(|nation| nation.major())
                .is_some();
            if !present {
                return Err(TurnFlowError::MissingMajorNation { slot });
            }
        }
        for nation in self.nations.iter_mut().take(MAJOR_NATION_COUNT) {
            let major = nation
                .as_mut()
                .and_then(|nation| nation.major_mut())
                .expect("major-nation presence was checked above");
            reset_finished_flag(major.diplomacy_eligible, &mut major.turn_finished);
        }
        Ok(())
    }
}

fn all_major_flags_finished(
    flags: impl IntoIterator<Item = Option<bool>>,
) -> Result<bool, TurnFlowError> {
    for (slot, finished) in flags.into_iter().enumerate() {
        match finished {
            Some(true) => {}
            Some(false) => return Ok(false),
            None => return Err(TurnFlowError::MissingMajorNation { slot }),
        }
    }
    Ok(true)
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
    fn advances_the_retail_short_and_classifies_linear_phases() {
        let mut turn = TurnState {
            scenario_map_index_plus_one: 0,
            economic_turn: i16::MAX,
            phase_code: 4,
            difficulty: 1,
            active_nation: 6,
            selected_nation: 6,
        };
        turn.advance_season();
        assert_eq!(turn.economic_turn, i16::MIN);
        assert!(!turn.in_linear_phase());
        turn.phase_code = 3;
        assert!(turn.in_linear_phase());
        turn.phase_code = 6;
        assert!(turn.in_linear_phase());
    }

    #[test]
    fn requires_all_seven_major_turn_flags() {
        assert_eq!(
            all_major_flags_finished([Some(true); MAJOR_NATION_COUNT]),
            Ok(true)
        );
        assert_eq!(
            all_major_flags_finished([
                Some(true),
                Some(true),
                Some(false),
                Some(true),
                Some(true),
                Some(true),
                Some(true),
            ]),
            Ok(false)
        );
        assert_eq!(
            all_major_flags_finished([Some(true), None]),
            Err(TurnFlowError::MissingMajorNation { slot: 1 })
        );
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
