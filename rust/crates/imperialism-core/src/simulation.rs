use crate::{
    GameCommand, GameState, RandomGameSetupModel, RandomGameSetupState,
    RandomGameSetupValidationError, RestoredRandomGameSetupInputs, RuleError, StepOutcome,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Simulation {
    state: GameState,
    random_game_setup: Option<RandomGameSetupState>,
}

impl Simulation {
    pub const fn new(state: GameState) -> Self {
        Self {
            state,
            random_game_setup: None,
        }
    }

    /// Restores a complete oracle/test boundary without consuming CRT RNG.
    /// Normal gameplay must use `GameCommand::BeginRandomGameSetup` instead.
    pub fn with_restored_random_game_setup(
        state: GameState,
        setup: RestoredRandomGameSetupInputs,
    ) -> Result<Self, RandomGameSetupValidationError> {
        Ok(Self {
            state,
            random_game_setup: Some(RandomGameSetupState::try_from_restored_inputs(setup)?),
        })
    }

    pub const fn state(&self) -> &GameState {
        &self.state
    }

    pub fn into_state(self) -> GameState {
        self.state
    }

    pub fn into_parts(self) -> (GameState, Option<RandomGameSetupState>) {
        (self.state, self.random_game_setup)
    }

    pub fn random_game_setup_model(&self) -> Option<RandomGameSetupModel> {
        self.random_game_setup
            .as_ref()
            .map(RandomGameSetupState::query)
    }

    pub fn apply(&mut self, command: GameCommand) -> Result<StepOutcome, CommandError> {
        match command {
            command @ GameCommand::PlaceTradeBid { .. }
            | command @ GameCommand::PurchaseItem { .. } => self
                .state
                .apply_command(command)
                .map_err(CommandError::Trade),
            GameCommand::BeginRandomGameSetup { setup } => {
                RandomGameSetupState::validate_begin_inputs(&setup)
                    .map_err(CommandError::RandomGameSetup)?;
                let selected_nation_slot = (self.state.rng.next_crt_rand() % 7) as i16;
                self.random_game_setup = Some(RandomGameSetupState::from_validated_begin_inputs(
                    setup,
                    selected_nation_slot,
                ));
                Ok(StepOutcome::default())
            }
            GameCommand::SetRandomGamePlanet {
                planet_seed,
                retail_topology,
            } => {
                self.random_game_setup_mut()?
                    .set_planet(planet_seed, retail_topology);
                Ok(StepOutcome::default())
            }
            GameCommand::SelectRandomGameNation { nation_slot } => {
                self.random_game_setup_mut()?
                    .set_selected_nation_slot(nation_slot)
                    .map_err(CommandError::RandomGameSetup)?;
                Ok(StepOutcome::default())
            }
            GameCommand::SetRandomGameCountryName { country_name } => {
                self.random_game_setup_mut()?.set_country_name(country_name);
                Ok(StepOutcome::default())
            }
            GameCommand::SetRandomGameDifficulty { difficulty } => {
                self.random_game_setup_mut()?
                    .set_difficulty(difficulty)
                    .map_err(CommandError::RandomGameSetup)?;
                Ok(StepOutcome::default())
            }
            GameCommand::SetRandomGameNameMode {
                use_localized_name_tables,
            } => {
                self.random_game_setup_mut()?
                    .set_use_localized_name_tables(use_localized_name_tables);
                Ok(StepOutcome::default())
            }
        }
    }

    fn random_game_setup_mut(&mut self) -> Result<&mut RandomGameSetupState, CommandError> {
        self.random_game_setup
            .as_mut()
            .ok_or(CommandError::RandomGameSetupNotInitialized)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CommandError {
    #[error(transparent)]
    Trade(#[from] RuleError),
    #[error(transparent)]
    RandomGameSetup(#[from] RandomGameSetupValidationError),
    #[error("random-game setup has not been initialized")]
    RandomGameSetupNotInitialized,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        BeginRandomGameSetupInputs, NationId, PendingWorkState, ResourceKind, RetailTopologyByte,
        RngState, TurnState, WorldState,
    };

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

    fn restored_setup() -> RestoredRandomGameSetupInputs {
        RestoredRandomGameSetupInputs {
            planet_seed: "earth".to_owned(),
            retail_topology: RetailTopologyByte::from_retail_byte(0),
            selected_nation_slot: 2,
            country_name: "Republic".to_owned(),
            difficulty: 1,
            use_localized_name_tables: true,
        }
    }

    fn begin_setup() -> BeginRandomGameSetupInputs {
        BeginRandomGameSetupInputs {
            planet_seed: "earth".to_owned(),
            retail_topology: RetailTopologyByte::from_retail_byte(0),
            country_name: "Republic".to_owned(),
            difficulty: 1,
            use_localized_name_tables: true,
        }
    }

    #[test]
    fn command_log_entries_have_a_stable_serialized_shape() {
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
    fn setup_command_log_entries_have_a_stable_serialized_shape() {
        let command = GameCommand::BeginRandomGameSetup {
            setup: begin_setup(),
        };
        let json = serde_json::to_string(&command).unwrap();
        assert_eq!(
            json,
            r#"{"type":"begin_random_game_setup","setup":{"planet_seed":"earth","retail_topology":0,"country_name":"Republic","difficulty":1,"use_localized_name_tables":true}}"#
        );
        assert_eq!(serde_json::from_str::<GameCommand>(&json).unwrap(), command);
    }

    #[test]
    fn setup_commands_update_the_authoritative_draft() {
        let mut simulation = Simulation::new(state());
        simulation
            .apply(GameCommand::BeginRandomGameSetup {
                setup: begin_setup(),
            })
            .unwrap();
        simulation
            .apply(GameCommand::SetRandomGamePlanet {
                planet_seed: "mars".to_owned(),
                retail_topology: RetailTopologyByte::from_retail_byte(1),
            })
            .unwrap();
        simulation
            .apply(GameCommand::SelectRandomGameNation { nation_slot: 6 })
            .unwrap();
        simulation
            .apply(GameCommand::SetRandomGameCountryName {
                country_name: "Union".to_owned(),
            })
            .unwrap();
        simulation
            .apply(GameCommand::SetRandomGameDifficulty { difficulty: 4 })
            .unwrap();
        simulation
            .apply(GameCommand::SetRandomGameNameMode {
                use_localized_name_tables: false,
            })
            .unwrap();

        assert_eq!(
            simulation.random_game_setup_model(),
            Some(RandomGameSetupModel {
                planet_seed: "mars".to_owned(),
                retail_topology_byte: 1,
                wraps_horizontally: false,
                selected_nation_slot: 6,
                country_name: "Union".to_owned(),
                difficulty: 4,
                use_localized_name_tables: false,
            })
        );
    }

    #[test]
    fn begin_setup_consumes_exactly_one_seed_one_crt_draw() {
        let mut simulation = Simulation::new(state());
        simulation
            .apply(GameCommand::BeginRandomGameSetup {
                setup: begin_setup(),
            })
            .unwrap();

        assert_eq!(simulation.state().rng.crt_rand, 2_745_024);
        assert_eq!(simulation.state().rng.map_generation, 0);
        assert_eq!(simulation.state().rng.zone_status, 0);
        assert_eq!(
            simulation
                .random_game_setup_model()
                .unwrap()
                .selected_nation_slot,
            6
        );
    }

    #[test]
    fn invalid_setup_commands_leave_the_draft_unchanged() {
        let mut simulation =
            Simulation::with_restored_random_game_setup(state(), restored_setup()).unwrap();
        let before = simulation.clone();
        assert_eq!(
            simulation.apply(GameCommand::SelectRandomGameNation { nation_slot: -1 }),
            Err(CommandError::RandomGameSetup(
                RandomGameSetupValidationError::InvalidNationSlot { actual: -1 }
            ))
        );
        assert_eq!(simulation, before);

        assert_eq!(
            simulation.apply(GameCommand::SetRandomGameDifficulty { difficulty: 5 }),
            Err(CommandError::RandomGameSetup(
                RandomGameSetupValidationError::InvalidDifficulty { actual: 5 }
            ))
        );
        assert_eq!(simulation, before);

        let mut invalid_begin = begin_setup();
        invalid_begin.difficulty = 5;
        assert_eq!(
            simulation.apply(GameCommand::BeginRandomGameSetup {
                setup: invalid_begin,
            }),
            Err(CommandError::RandomGameSetup(
                RandomGameSetupValidationError::InvalidDifficulty { actual: 5 }
            ))
        );
        assert_eq!(simulation, before);
    }

    #[test]
    fn setup_mutation_requires_explicit_initialization() {
        let mut simulation = Simulation::new(state());
        let before = simulation.clone();
        assert_eq!(
            simulation.apply(GameCommand::SetRandomGameCountryName {
                country_name: "Union".to_owned(),
            }),
            Err(CommandError::RandomGameSetupNotInitialized)
        );
        assert_eq!(simulation, before);
    }
}
