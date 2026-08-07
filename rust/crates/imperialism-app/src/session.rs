use bevy::prelude::*;
use imperialism_core::{CommandError, GameCommand, GameEvent, GameState, Simulation};

#[derive(Resource)]
pub struct GameSession {
    simulation: Option<Simulation>,
    revision: u64,
    command_log: Vec<GameCommand>,
}

impl GameSession {
    pub fn new(state: GameState) -> Self {
        Self {
            simulation: Some(Simulation::new(state)),
            revision: 0,
            command_log: Vec::new(),
        }
    }

    pub const fn pre_game() -> Self {
        Self {
            simulation: None,
            revision: 0,
            command_log: Vec::new(),
        }
    }

    pub fn simulation(&self) -> &Simulation {
        self.simulation
            .as_ref()
            .expect("an active game simulation is required")
    }

    pub const fn active_simulation(&self) -> Option<&Simulation> {
        self.simulation.as_ref()
    }

    pub const fn is_pre_game(&self) -> bool {
        self.simulation.is_none()
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub fn command_log(&self) -> &[GameCommand] {
        &self.command_log
    }
}

#[derive(Message, Clone, Debug, Eq, PartialEq)]
pub struct SubmitCommand(pub GameCommand);

#[derive(Message, Clone, Debug, Eq, PartialEq)]
pub struct DomainEventMessage(pub GameEvent);

#[derive(Message, Clone, Debug, Eq, PartialEq)]
pub struct CommandRejectedMessage {
    pub command: GameCommand,
    pub error: SessionCommandError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SessionCommandError {
    #[error("no game simulation is active")]
    NoActiveGame,
    #[error(transparent)]
    Command(#[from] CommandError),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, SystemSet)]
pub enum GameLoopSet {
    CollectInput,
    TranslateUiIntents,
    ApplyGameCommands,
    UpdatePresentation,
    Animate,
}

pub struct SessionPlugin;

impl Plugin for SessionPlugin {
    fn build(&self, app: &mut App) {
        app.add_message::<SubmitCommand>()
            .add_message::<DomainEventMessage>()
            .add_message::<CommandRejectedMessage>()
            .configure_sets(
                Update,
                (
                    GameLoopSet::CollectInput,
                    GameLoopSet::TranslateUiIntents,
                    GameLoopSet::ApplyGameCommands,
                    GameLoopSet::UpdatePresentation,
                    GameLoopSet::Animate,
                )
                    .chain(),
            )
            .add_systems(
                Update,
                apply_game_commands.in_set(GameLoopSet::ApplyGameCommands),
            );
    }
}

fn apply_game_commands(
    mut submitted: MessageReader<SubmitCommand>,
    mut events: MessageWriter<DomainEventMessage>,
    mut rejected: MessageWriter<CommandRejectedMessage>,
    mut session: ResMut<GameSession>,
) {
    for SubmitCommand(command) in submitted.read() {
        let Some(simulation) = session.simulation.as_mut() else {
            rejected.write(CommandRejectedMessage {
                command: command.clone(),
                error: SessionCommandError::NoActiveGame,
            });
            continue;
        };
        match simulation.apply(command.clone()) {
            Ok(outcome) => {
                session.revision = session.revision.wrapping_add(1);
                session.command_log.push(command.clone());
                for event in outcome.events {
                    events.write(DomainEventMessage(event));
                }
            }
            Err(error) => {
                rejected.write(CommandRejectedMessage {
                    command: command.clone(),
                    error: SessionCommandError::Command(error),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperialism_core::{
        MajorNationState, MajorNationTable, NationId, NationKind, NationPendingWork, NationState,
        NationTable, PendingActionTable, PendingWorkState, ResourceKind, ResourceTable, RngState,
        TurnState, WorldState,
    };

    fn game() -> GameState {
        let nation = NationId::new(6);
        let mut nations = vec![None; 7];
        nations[6] = Some(NationState {
            id: nation,
            kind: NationKind::Major,
            encoded_nation_slot: 6,
            owner_nation: 6,
            treasury: 1_000,
            home_tile: 0,
            need_level_by_nation: NationTable::default(),
            major: Some(MajorNationState {
                diplomacy_eligible: true,
                capacities: [10; 4],
                grant_total_cost: 0,
                unfilled_trade_offer_count: 0,
                diplomacy_policy_by_nation: NationTable::default(),
                diplomacy_grant_by_nation: NationTable::default(),
                need_current_by_type: ResourceTable::default(),
                need_target_by_type: ResourceTable::default(),
                relation_delta_current: ResourceTable::default(),
                purchased_items_by_resource: ResourceTable::default(),
                item_potentials: ResourceTable::default(),
                unfilled_trade_turns_by_resource: ResourceTable::default(),
                transported_items_by_resource: ResourceTable::default(),
                remembered_trade_offers_by_resource: ResourceTable::default(),
                aid_allocation_matrix: vec![0; 23],
                budget_pool_base: 200,
                budget_pool_delta: 100,
                special_resource_trade_balance: 30,
                candidate_nation_flags: vec![0; 23],
                scenario_initialized: true,
                turn_finished: false,
                pending_action_status: PendingActionTable::default(),
                pending_action_payload_by_action: PendingActionTable::default(),
                diplomacy_budget_base: 0,
                escalation_counter: 0,
                pending_commitment_cost: 0,
                pressure_counter: 0,
                aid_allocation_total: 0,
                colony_boycott_flags: vec![0; 23],
                military_expenses: 0,
            }),
        });
        GameState {
            turn: TurnState {
                scenario_map_index_plus_one: 0,
                economic_turn: 1,
                phase_code: 5,
                difficulty: 1,
                active_nation: 6,
                selected_nation: 6,
            },
            persistent_unit_id_counter: 0,
            world: WorldState {
                width: 0,
                height: 0,
                wraps_horizontally: false,
                tiles: vec![],
            },
            rng: RngState {
                crt_rand: 1,
                map_generation: 1,
                zone_status: 1,
            },
            nations,
            cities: vec![],
            military_units: vec![],
            civilian_units: vec![],
            ships: vec![],
            task_forces: vec![],
            missions: vec![],
            pending: PendingWorkState {
                turn_flow_status_flags: 0,
                nations: MajorNationTable::from_fn(|nation_index| NationPendingWork {
                    nation: NationId::new(nation_index as u8),
                    turn_events: vec![],
                    proposals: vec![],
                    turn_summary: vec![],
                    turn_start_events: vec![],
                }),
                war_transitions: vec![],
            },
        }
    }

    fn purchase(nation: NationId) -> SubmitCommand {
        SubmitCommand(GameCommand::PurchaseItem {
            nation,
            resource: ResourceKind::Fabric,
            amount: 3,
            price: 7,
        })
    }

    #[test]
    fn the_session_is_the_single_ordered_command_writer() {
        let mut app = App::new();
        app.insert_resource(GameSession::new(game()))
            .add_plugins(SessionPlugin);
        app.world_mut()
            .write_message(purchase(NationId::new(6)))
            .unwrap();
        app.update();

        let session = app.world().resource::<GameSession>();
        assert_eq!(session.revision(), 1);
        assert_eq!(session.command_log(), &[purchase(NationId::new(6)).0]);
        assert_eq!(
            session.simulation().state().nations[6]
                .as_ref()
                .unwrap()
                .treasury,
            979
        );
    }

    #[test]
    fn a_rejected_command_changes_neither_revision_log_nor_state() {
        let initial = game();
        let mut app = App::new();
        app.insert_resource(GameSession::new(initial.clone()))
            .add_plugins(SessionPlugin);
        app.world_mut()
            .write_message(purchase(NationId::new(5)))
            .unwrap();
        app.update();

        let session = app.world().resource::<GameSession>();
        assert_eq!(session.revision(), 0);
        assert!(session.command_log().is_empty());
        assert_eq!(session.simulation().state(), &initial);
    }

    #[test]
    fn pre_game_session_rejects_commands_without_inventing_simulation_state() {
        let mut app = App::new();
        app.insert_resource(GameSession::pre_game())
            .add_plugins(SessionPlugin);
        app.world_mut()
            .write_message(purchase(NationId::new(6)))
            .unwrap();
        app.update();

        let session = app.world().resource::<GameSession>();
        assert!(session.is_pre_game());
        assert!(session.active_simulation().is_none());
        assert_eq!(session.revision(), 0);
        assert!(session.command_log().is_empty());
        assert_eq!(
            app.world()
                .resource::<Messages<CommandRejectedMessage>>()
                .len(),
            1
        );
    }
}
