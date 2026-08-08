use crate::{GameCommand, GameState, RuleError, StepOutcome};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Simulation {
    state: GameState,
}

impl Simulation {
    pub const fn new(state: GameState) -> Self {
        Self { state }
    }

    pub const fn state(&self) -> &GameState {
        &self.state
    }

    pub fn into_state(self) -> GameState {
        self.state
    }

    pub fn apply(&mut self, command: GameCommand) -> Result<StepOutcome, RuleError> {
        self.state.apply_command(command)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NationId, PendingWorkState, ResourceKind, RngState, TurnState, WorldState};

    fn state() -> GameState {
        GameState {
            turn: TurnState {
                scenario_map_index_plus_one: 0,
                economic_turn: 0,
                phase_code: 3,
                difficulty: 0,
                active_nation: -1,
                selected_nation: -1,
            },
            persistent_unit_id_counter: 0,
            world: WorldState {
                width: 0,
                height: 0,
                wraps_horizontally: false,
                tiles: Vec::new(),
            },
            rng: RngState {
                crt_rand: 1,
                map_generation: 0,
                zone_status: 0,
            },
            nations: crate::NationTable::default(),
            cities: crate::MajorNationTable::default(),
            military_units: Vec::new(),
            civilian_units: Vec::new(),
            ships: Vec::new(),
            task_forces: Vec::new(),
            missions: Vec::new(),
            pending: PendingWorkState {
                turn_flow_status_flags: 0,
                nations: crate::MajorNationTable::from_fn(|nation| crate::NationPendingWork {
                    nation: nation.nation(),
                    turn_events: Vec::new(),
                    proposals: Vec::new(),
                    turn_summary: Vec::new(),
                    turn_start_events: Vec::new(),
                }),
                war_transitions: Vec::new(),
            },
        }
    }

    #[test]
    fn active_game_commands_have_a_stable_serialized_shape() {
        let command = GameCommand::PurchaseItem {
            nation: NationId::new(6),
            resource: ResourceKind::Fabric,
            amount: 3,
            price: 7,
        };
        let json = serde_json::to_string(&command).unwrap();
        assert_eq!(
            json,
            r#"{"type":"purchase_item","nation":6,"resource":"fabric","amount":3,"price":7}"#
        );
        assert_eq!(serde_json::from_str::<GameCommand>(&json).unwrap(), command);
    }

    #[test]
    fn delegates_active_game_commands_to_game_state() {
        let command = GameCommand::PlaceTradeBid {
            nation: NationId::new(6),
            resource: ResourceKind::Fabric,
            amount: 3,
        };
        let mut simulation = Simulation::new(state());
        let mut expected = simulation.state().clone();

        assert_eq!(
            simulation.apply(command.clone()),
            expected.apply_command(command)
        );
        assert_eq!(simulation.state(), &expected);
    }
}
