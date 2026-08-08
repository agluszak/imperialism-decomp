use bevy::prelude::*;
#[cfg(test)]
use imperialism_core::GameState;
use imperialism_core::{GameCommand, GameEvent, Simulation};

#[derive(Resource)]
pub(crate) struct GameSession(Simulation);

impl GameSession {
    #[cfg(test)]
    pub(crate) fn new(state: GameState) -> Self {
        Self(Simulation::new(state))
    }

    #[cfg(test)]
    pub(crate) fn simulation(&self) -> &Simulation {
        &self.0
    }
}

#[derive(Message, Clone, Debug, Eq, PartialEq)]
pub(crate) struct SubmitCommand(pub(crate) GameCommand);

#[derive(Message, Clone, Debug, Eq, PartialEq)]
pub(crate) struct DomainEventMessage(pub(crate) GameEvent);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, SystemSet)]
pub(crate) enum GameLoopSet {
    TranslateUiIntents,
    ApplyGameCommands,
    UpdatePresentation,
}

pub(crate) struct SessionPlugin;

impl Plugin for SessionPlugin {
    fn build(&self, app: &mut App) {
        app.add_message::<SubmitCommand>()
            .add_message::<DomainEventMessage>()
            .configure_sets(
                Update,
                (
                    GameLoopSet::TranslateUiIntents,
                    GameLoopSet::ApplyGameCommands,
                    GameLoopSet::UpdatePresentation,
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
    session: Option<ResMut<GameSession>>,
) {
    let Some(mut session) = session else {
        let _ = submitted.read().count();
        return;
    };
    for SubmitCommand(command) in submitted.read() {
        if let Ok(outcome) = session.0.apply(command.clone()) {
            for event in outcome.events {
                events.write(DomainEventMessage(event));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperialism_core::{
        AidAllocationTable, GameState, MajorNationState, MajorNationTable, NationCommonState,
        NationData, NationId, NationPendingWork, NationState, NationTable, PendingActionTable,
        PendingWorkState, ResourceKind, ResourceTable, RngState, TurnState, WorldState,
    };

    fn game() -> GameState {
        let nation = NationId::new(6);
        let mut nations = NationTable::default();
        nations[nation] = Some(NationState {
            id: nation,
            common: NationCommonState {
                encoded_nation_slot: 6,
                owner_nation: 6,
                treasury: 1_000,
                home_tile: 0,
                need_level_by_nation: NationTable::default(),
            },
            data: NationData::Major(MajorNationState {
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
                aid_allocation_matrix: AidAllocationTable::default(),
                budget_pool_base: 200,
                budget_pool_delta: 100,
                special_resource_trade_balance: 30,
                candidate_nation_flags: NationTable::default(),
                scenario_initialized: true,
                turn_finished: false,
                pending_action_status: PendingActionTable::default(),
                pending_action_payload_by_action: PendingActionTable::default(),
                diplomacy_budget_base: 0,
                escalation_counter: 0,
                pending_commitment_cost: 0,
                pressure_counter: 0,
                aid_allocation_total: 0,
                colony_boycott_flags: NationTable::default(),
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
            cities: MajorNationTable::default(),
            military_units: vec![],
            civilian_units: vec![],
            ships: vec![],
            task_forces: vec![],
            missions: vec![],
            pending: PendingWorkState {
                turn_flow_status_flags: 0,
                nations: MajorNationTable::from_fn(|nation_index| NationPendingWork {
                    nation: nation_index.nation(),
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
    fn active_session_applies_commands_and_emits_domain_events() {
        let mut app = App::new();
        app.insert_resource(GameSession::new(game()))
            .add_plugins(SessionPlugin);
        app.world_mut()
            .write_message(purchase(NationId::new(6)))
            .unwrap();
        app.update();

        let session = app.world().resource::<GameSession>();
        assert_eq!(
            session.simulation().state().nations[NationId::new(6)]
                .as_ref()
                .unwrap()
                .common
                .treasury,
            979
        );
        let events = app
            .world_mut()
            .resource_mut::<Messages<DomainEventMessage>>()
            .drain()
            .collect::<Vec<_>>();
        assert_eq!(
            events,
            vec![DomainEventMessage(GameEvent::TradeSettled {
                nation: NationId::new(6),
                resource: ResourceKind::Fabric,
                amount: 3,
                price: 7,
            })]
        );
    }

    #[test]
    fn rejected_active_command_leaves_state_unchanged() {
        let initial = game();
        let mut app = App::new();
        app.insert_resource(GameSession::new(initial.clone()))
            .add_plugins(SessionPlugin);
        app.world_mut()
            .write_message(purchase(NationId::new(5)))
            .unwrap();
        app.update();

        let session = app.world().resource::<GameSession>();
        assert_eq!(session.simulation().state(), &initial);
        assert_eq!(
            app.world().resource::<Messages<DomainEventMessage>>().len(),
            0
        );
    }

    #[test]
    fn commands_are_ignored_when_no_active_session_exists() {
        let mut app = App::new();
        app.add_plugins(SessionPlugin);
        app.world_mut()
            .write_message(purchase(NationId::new(6)))
            .unwrap();
        app.update();

        assert!(!app.world().contains_resource::<GameSession>());
        assert_eq!(
            app.world().resource::<Messages<DomainEventMessage>>().len(),
            0
        );

        let initial = game();
        app.insert_resource(GameSession::new(initial.clone()));
        app.update();

        assert_eq!(
            app.world().resource::<GameSession>().simulation().state(),
            &initial
        );
    }
}
