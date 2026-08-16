use super::generated;
use super::retail::RetailTree;
use super::session::{GameSession, apply_turn_stop};
use crate::AppState;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::*;
use imperialism_formats::fourcc;

#[derive(Component)]
struct LandBattleRoot;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum LandBattleAction {
    Auto,
    Retreat,
}

#[derive(Component)]
struct LandBattleCaption;

pub(crate) struct LandBattlePlugin;

impl Plugin for LandBattlePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::LandBattle),
            (spawn_land_battle, bind_land_battle).chain(),
        )
        .add_systems(
            Update,
            project_land_battle
                .run_if(in_state(AppState::LandBattle).and_then(resource_exists::<GameSession>)),
        );
    }
}

fn spawn_land_battle(mut commands: Commands) {
    let root = commands.spawn_scene(generated::tactical_3800()).id();
    commands
        .entity(root)
        .insert((LandBattleRoot, DespawnOnExit(AppState::LandBattle)));
}

fn bind_land_battle(
    mut commands: Commands,
    root: Single<Entity, Added<LandBattleRoot>>,
    tree: RetailTree,
) {
    bind_land_battle_controls(&mut commands, *root, &tree);
}

fn bind_land_battle_controls(commands: &mut Commands, root: Entity, tree: &RetailTree) {
    commands.entity(tree.find(root, fourcc!("curs"))).insert((
        LandBattleCaption,
        Text::default(),
        TextColor(Color::WHITE),
    ));
    commands
        .entity(tree.find(root, fourcc!("auto")))
        .insert((LandBattleAction::Auto, ActivateOnPress))
        .observe(on_land_battle_activate)
        .remove::<InteractionDisabled>();
    commands
        .entity(tree.find(root, fourcc!("retr")))
        .insert((LandBattleAction::Retreat, ActivateOnPress))
        .observe(on_land_battle_activate)
        .remove::<InteractionDisabled>();
}

fn project_land_battle(
    session: Res<GameSession>,
    added: Query<(), Added<LandBattleCaption>>,
    mut captions: Query<&mut Text, With<LandBattleCaption>>,
) {
    if super::projection_idle(&session, !added.is_empty()) {
        return;
    }
    let Some(battle) = session.game.pending_land_battle() else {
        return;
    };
    let caption = land_battle_caption(&session.game, battle);
    for mut text in &mut captions {
        text.0.clone_from(&caption);
    }
}

fn land_battle_caption(state: &GameState, battle: &PendingLandBattle) -> String {
    let attacker = state
        .nations()
        .display_name(battle.attacker_nation)
        .unwrap_or("");
    let defender = state
        .nations()
        .display_name(battle.defender_nation)
        .unwrap_or("");
    let province = state.map().provinces[battle.province].name.as_str();
    format!("{attacker} attacks {defender} in {province}")
}

fn on_land_battle_activate(
    activate: On<Activate>,
    actions: Query<&LandBattleAction>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    assets: Option<Res<crate::RetailAssetsResource>>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    match *action {
        LandBattleAction::Auto => match session
            .game
            .auto_resolve_land_battle(super::session::news_story_ids(assets.as_deref()))
        {
            TurnStop::LandBattle => {}
            stop => apply_turn_stop(stop, &mut next_state),
        },
        LandBattleAction::Retreat => {
            session.game.resolve_land_battle(false);
            match session
                .game
                .resume_after_land_battle(super::session::news_story_ids(assets.as_deref()))
            {
                TurnStop::LandBattle => {}
                stop => apply_turn_stop(stop, &mut next_state),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::retail::RetailTag;
    use super::*;
    use crate::ui::test_support::beginning_of_game_parts;
    use bevy::state::app::StatesPlugin;

    fn fixture_parts() -> GameStateParts {
        beginning_of_game_parts()
    }

    fn idle_unit(unit: &MilitaryUnitState) -> MilitaryUnitState {
        let stationed = unit.stationed_province();
        MilitaryUnitState::new(
            unit.id(),
            unit.nation(),
            unit.unit_type(),
            stationed,
            MilitaryOrder::idle([stationed; 3], [stationed; 3]),
            unit.owner_nation(),
            unit.roster_id(),
            unit.registered(),
            unit.name().to_string(),
            unit.strength(),
            unit.era(),
            unit.experience(),
            unit.battle_flags(),
        )
    }

    fn redeploy_unit(
        id: MilitaryUnitId,
        nation: NationId,
        kind: MilitaryUnitKind,
        from: ProvinceId,
        to: ProvinceId,
        strength: i16,
    ) -> MilitaryUnitState {
        MilitaryUnitState::new(
            id,
            nation,
            kind,
            Some(from),
            MilitaryOrder::retail(
                MilitaryOrderCode::Redeploy,
                Some(to),
                [Some(to); 3],
                [Some(to); 3],
            ),
            nation,
            0,
            true,
            String::new(),
            strength,
            0,
            0,
            0,
        )
    }

    fn garrison_unit(
        id: MilitaryUnitId,
        nation: NationId,
        kind: MilitaryUnitKind,
        province: ProvinceId,
        strength: i16,
    ) -> MilitaryUnitState {
        MilitaryUnitState::new(
            id,
            nation,
            kind,
            Some(province),
            MilitaryOrder::idle([Some(province); 3], [Some(province); 3]),
            nation,
            0,
            true,
            String::new(),
            strength,
            0,
            0,
            0,
        )
    }

    fn adjacent_major_frontiers(map: &MapMgr) -> Vec<(ProvinceId, ProvinceId, NationId, NationId)> {
        let mut pairs = Vec::new();
        for province in ProvinceId::all() {
            let Some(owner) = map.provinces[province].owner() else {
                continue;
            };
            if MajorNationId::from_nation(owner).is_none() {
                continue;
            }
            for &neighbor in map.provinces[province].adjacency() {
                if neighbor.get() <= province.get() {
                    continue;
                }
                let Some(other) = map.provinces[neighbor].owner() else {
                    continue;
                };
                if other == owner || MajorNationId::from_nation(other).is_none() {
                    continue;
                }
                pairs.push((province, neighbor, owner, other));
            }
        }
        pairs
    }

    fn two_land_battles_state() -> GameState {
        let mut parts = fixture_parts();
        let frontiers = adjacent_major_frontiers(&parts.map);
        let first = frontiers
            .first()
            .copied()
            .expect("beginning-of-game map has a major-power border");
        let second = frontiers
            .iter()
            .copied()
            .find(|&(from, to, ..)| {
                from != first.0 && from != first.1 && to != first.0 && to != first.1
            })
            .expect("beginning-of-game map has two distinct major-power borders");

        parts.military_units = parts.military_units.iter().map(idle_unit).collect();
        parts.diplomacy.relationships[first.2][first.3] = DiplomaticRelationship::War;
        parts.diplomacy.relationships[first.3][first.2] = DiplomaticRelationship::War;
        parts.diplomacy.relationships[second.2][second.3] = DiplomaticRelationship::War;
        parts.diplomacy.relationships[second.3][second.2] = DiplomaticRelationship::War;
        parts.diplomacy.relationship_turns[first.2][first.3] = None;
        parts.diplomacy.relationship_turns[first.3][first.2] = None;
        parts.diplomacy.relationship_turns[second.2][second.3] = None;
        parts.diplomacy.relationship_turns[second.3][second.2] = None;

        let next = parts.unit_ids.current();
        parts.unit_ids = UnitIdAllocator::from_retail(next + 4);
        parts.military_units.push(redeploy_unit(
            MilitaryUnitId::from_serialized(next + 1),
            first.2,
            MilitaryUnitKind::Regulars,
            first.0,
            first.1,
            500,
        ));
        parts.military_units.push(garrison_unit(
            MilitaryUnitId::from_serialized(next + 2),
            first.3,
            MilitaryUnitKind::Militia,
            first.1,
            100,
        ));
        parts.military_units.push(redeploy_unit(
            MilitaryUnitId::from_serialized(next + 3),
            second.2,
            MilitaryUnitKind::Regulars,
            second.0,
            second.1,
            500,
        ));
        parts.military_units.push(garrison_unit(
            MilitaryUnitId::from_serialized(next + 4),
            second.3,
            MilitaryUnitKind::Militia,
            second.1,
            100,
        ));

        parts.turn = TurnState::new(
            parts.turn.scenario_map,
            parts.turn.economic_turn,
            parts.turn.diplomacy_year_term_raw,
            PhaseCode::COMBAT_MOVES,
            parts.turn.turn_flow_status_flags,
            parts.turn.quarter_gate_by_decade,
            parts.turn.difficulty,
            parts.turn.active_nation,
            parts.turn.selected_nation,
        );

        let mut state = GameState::from_parts(parts);
        assert_eq!(state.advance_turn(&[]), TurnStop::LandBattle);
        assert!(state.pending_land_battle().is_some());
        state
    }

    fn test_app(state: GameState) -> App {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(StatesPlugin)
            .insert_resource(GameSession { game: state })
            .insert_state(AppState::LandBattle)
            .add_systems(
                OnEnter(AppState::LandBattle),
                (spawn_test_land_battle, bind_test_land_battle).chain(),
            )
            .add_systems(
                Update,
                project_land_battle.run_if(
                    in_state(AppState::LandBattle).and_then(resource_exists::<GameSession>),
                ),
            );
        app
    }

    fn spawn_test_land_battle(mut commands: Commands) {
        let root = commands
            .spawn((
                LandBattleRoot,
                Node::default(),
                DespawnOnExit(AppState::LandBattle),
            ))
            .id();
        commands.spawn((RetailTag(fourcc!("curs")), Node::default(), ChildOf(root)));
        commands.spawn((RetailTag(fourcc!("auto")), Node::default(), ChildOf(root)));
        commands.spawn((RetailTag(fourcc!("retr")), Node::default(), ChildOf(root)));
    }

    fn bind_test_land_battle(
        mut commands: Commands,
        root: Option<Single<Entity, Added<LandBattleRoot>>>,
        tree: RetailTree,
    ) {
        let Some(root) = root else {
            return;
        };
        bind_land_battle_controls(&mut commands, *root, &tree);
    }

    fn action_entity(app: &mut App, action: LandBattleAction) -> Entity {
        app.world_mut()
            .query::<(Entity, &LandBattleAction)>()
            .iter(app.world())
            .find_map(|(entity, bound)| (*bound == action).then_some(entity))
            .expect("land-battle action is bound")
    }

    fn caption(app: &mut App) -> String {
        app.world_mut()
            .query::<&Text>()
            .iter(app.world())
            .next()
            .map(|text| text.0.clone())
            .expect("land-battle caption is bound")
    }

    #[test]
    fn auto_resolves_the_first_battle_and_stays_for_the_second() {
        let state = two_land_battles_state();
        let first = state
            .pending_land_battle()
            .cloned()
            .expect("combat moves stop on the first battle");
        let expected = land_battle_caption(&state, &first);

        let mut app = test_app(state);
        app.update();
        app.update();
        assert_eq!(caption(&mut app), expected);
        assert_eq!(
            *app.world().resource::<State<AppState>>().get(),
            AppState::LandBattle
        );

        let auto = action_entity(&mut app, LandBattleAction::Auto);
        app.world_mut()
            .commands()
            .trigger(Activate { entity: auto });
        app.world_mut().flush();
        app.update();

        assert_eq!(
            *app.world().resource::<State<AppState>>().get(),
            AppState::LandBattle
        );
        let (second_province, expected_second) = {
            let session = app.world().resource::<GameSession>();
            let second = session
                .game
                .pending_land_battle()
                .cloned()
                .expect("remaining hostile stack keeps the land-battle stop");
            (second.province, land_battle_caption(&session.game, &second))
        };
        assert_ne!(second_province, first.province);
        assert_eq!(caption(&mut app), expected_second);
    }
}
