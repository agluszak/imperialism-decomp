//! First-turn zero-stack combat movement (`TSimMgr` phase `0x14`).

use crate::*;

const SLEEP_ORDER: MilitaryOrderCode = MilitaryOrderCode::from_retail(2);

impl GameState {
    /// Whether combat movement is the recovered targetless Easy first-turn branch.
    pub(crate) fn supports_first_turn_no_combat_movement_phase(&self) -> bool {
        self.turn.economic_turn == 1
            && self.turn.difficulty == Difficulty::Easy
            && self.military_units.iter().all(supports_targetless_unit)
    }

    /// Runs retail's zero-stack `TArmyMgr::DoCombatMoves` path.
    ///
    /// Phase advancement remains the turn driver's responsibility. Every unit is
    /// validated before mutation so movement, removal, or battle cannot leave a
    /// partially advanced state.
    pub(crate) fn run_first_turn_no_combat_movement_phase(&mut self) {
        assert!(
            self.supports_first_turn_no_combat_movement_phase(),
            "combat movement contains an unrecovered unit branch"
        );

        let computer_majors = MajorNationTable::from_fn(|nation| {
            !self.nations.majors[nation].economy.controller.is_human()
        });

        for unit in &mut self.military_units {
            unit.strength = if unit.strength < 401 {
                unit.strength + 100
            } else {
                500
            };

            let computer_major = MajorNationId::from_nation(unit.nation)
                .is_some_and(|nation| computer_majors[nation]);
            continue_targetless_order(&mut unit.order, computer_major);
        }
    }
}

fn supports_targetless_unit(unit: &MilitaryUnitState) -> bool {
    unit.registered
        && unit.stationed_province.is_some()
        && unit.strength > 0
        && unit.battle_flags == 0
        && unit.nation == unit.owner_nation
        && primary_target(&unit.order).is_none()
}

fn primary_target(order: &MilitaryOrder) -> Option<ProvinceId> {
    match order {
        MilitaryOrder::Idle { .. } => None,
        MilitaryOrder::Retail { target, .. } => *target,
    }
}

fn continue_targetless_order(order: &mut MilitaryOrder, computer_major: bool) {
    let (code, targets, target_mirrors) = match order {
        MilitaryOrder::Idle {
            targets,
            target_mirrors,
        } => (None, *targets, *target_mirrors),
        MilitaryOrder::Retail {
            code,
            targets,
            target_mirrors,
            ..
        } => (Some(*code), *targets, *target_mirrors),
    };

    if computer_major {
        *order = MilitaryOrder::retail(SLEEP_ORDER, None, targets, target_mirrors);
    } else if code.is_some_and(|code| code != SLEEP_ORDER) {
        *order = MilitaryOrder::idle(targets, target_mirrors);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(id: i32, nation: NationId, strength: i16, order: MilitaryOrder) -> MilitaryUnitState {
        MilitaryUnitState::new(
            MilitaryUnitId::new(id),
            nation,
            MilitaryUnitKind::Infantry,
            Some(ProvinceId::new(0)),
            order,
            nation,
            id as i16,
            true,
            String::new(),
            strength,
            0,
            0,
            0,
        )
    }

    #[test]
    fn targetless_pass_heals_and_finishes_orders_without_rng() {
        let mut state = crate::test_support::game_state();
        state.turn.phase = PhaseCode::COMBAT_MOVES;
        state.nations.majors[MajorNationId::new(0)]
            .economy
            .controller = MajorNationController::Computer;
        let targets = [Some(ProvinceId::new(0)); 3];
        state.military_units = vec![
            unit(
                1,
                NationId::new(0),
                400,
                MilitaryOrder::retail(MilitaryOrderCode::from_retail(1), None, targets, targets),
            ),
            unit(
                2,
                NationId::new(6),
                401,
                MilitaryOrder::retail(MilitaryOrderCode::from_retail(1), None, targets, targets),
            ),
        ];
        let rng_before = state.rng;

        assert_eq!(
            state.advance_turn_step(),
            AdvanceTurnOutcome::Continues {
                from: PhaseCode::COMBAT_MOVES,
                to: PhaseCode::MILITARY_CLEANUP,
                effects: Vec::new(),
            }
        );

        assert_eq!(state.turn.phase, PhaseCode::MILITARY_CLEANUP);
        assert_eq!(state.rng, rng_before);
        assert_eq!(state.military_units[0].strength, 500);
        assert_eq!(
            state.military_units[0].order,
            MilitaryOrder::retail(SLEEP_ORDER, None, targets, targets)
        );
        assert_eq!(state.military_units[1].strength, 500);
        assert_eq!(
            state.military_units[1].order,
            MilitaryOrder::idle(targets, targets)
        );
    }

    #[test]
    fn targeted_unit_blocks_before_mutation() {
        let mut state = crate::test_support::game_state();
        state.turn.phase = PhaseCode::COMBAT_MOVES;
        let targets = [Some(ProvinceId::new(0)); 3];
        state.military_units.push(unit(
            1,
            NationId::new(0),
            500,
            MilitaryOrder::retail(SLEEP_ORDER, Some(ProvinceId::new(1)), targets, targets),
        ));
        let before = state.clone();

        assert_eq!(
            state.advance_turn_step(),
            AdvanceTurnOutcome::Blocked {
                phase: PhaseCode::COMBAT_MOVES,
                block: TurnBlock::Unsupported {
                    phase: PhaseCode::COMBAT_MOVES,
                },
                effects: Vec::new(),
            }
        );
        assert_eq!(state, before);
    }
}
