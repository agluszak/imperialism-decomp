use super::generated;
use super::retail::RetailTree;
use super::session::{GameSession, apply_turn_stop};
use super::tactical_viewport::{
    BATTLEFIELD_HEIGHT_PX, TACTICAL_TILE_ROW_HEIGHT_PX, TacticalViewport, battlefield_cursor_pixel,
    rect_xywh,
};
#[cfg(test)]
use super::tactical_viewport::{BATTLEFIELD_WIDTH_PX, TACTICAL_TILE_WIDTH_PX};
use crate::AppState;
use crate::media::MusicDirector;
use bevy::picking::events::{Click, Pointer};
use bevy::picking::pointer::PointerButton;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui::RelativeCursorPosition;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use bevy::window::PrimaryWindow;
use imperialism_core::*;
use imperialism_formats::{MusicTrack, fourcc};

#[derive(Component)]
struct NavalBattleRoot;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NavalBattleAction {
    Done,
    Auto,
    Retreat,
}

#[derive(Component)]
struct NavalBattleView {
    caption: Entity,
    field: Entity,
}

#[derive(Component)]
struct NavalBattlefield {
    battle: Option<PendingNavalBattle>,
    view_origin_x: i32,
    view_origin_y: i32,
    centered_ship: Option<ShipId>,
}

#[derive(Component, Clone, Copy)]
#[allow(dead_code)]
struct NavalBattleUnit(ShipId);

#[derive(Component, Clone, Copy)]
#[allow(dead_code)]
struct NavalBattleReachable(i32);

fn navy_viewport(origin_x: i32, origin_y: i32) -> TacticalViewport {
    TacticalViewport::navy(IVec2::new(origin_x, origin_y))
}

fn navy_row_column(tile: i32) -> (i32, i32) {
    let stride = NavyBattle::tile_stride();
    (tile / stride, tile % stride)
}

fn navy_tile_xywh(viewport: &TacticalViewport, tile: i32) -> (i32, i32, i32, i32) {
    let (row, column) = navy_row_column(tile);
    rect_xywh(viewport.cell_rect(row, column))
}

fn navy_unit_xywh(viewport: &TacticalViewport, tile: i32) -> (i32, i32, i32, i32) {
    let (row, column) = navy_row_column(tile);
    rect_xywh(viewport.unit_rect(row, column))
}

fn navy_tile_at_pixel(viewport: &TacticalViewport, x: i32, y: i32) -> Option<i32> {
    viewport
        .cell_at(IVec2::new(x, y))
        .map(|(row, column)| row * viewport.columns + column)
}

fn center_navy_origin_y(current: i32, selected_row: i32) -> i32 {
    let mut viewport = navy_viewport(0, current);
    viewport.center_on(selected_row, 0);
    viewport.origin.y
}

pub(crate) struct NavalBattlePlugin;

impl Plugin for NavalBattlePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::NavalBattle),
            (spawn_naval_battle, bind_naval_battle).chain(),
        )
        .add_systems(
            Update,
            (
                synchronize_interactive_navy_battle,
                scroll_naval_battle,
                project_naval_battle,
            )
                .chain()
                .run_if(in_state(AppState::NavalBattle).and_then(resource_exists::<GameSession>)),
        );
    }
}

fn synchronize_interactive_navy_battle(
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    if session.game.pending_naval_battle().is_some() && session.game.navy_battle().is_none() {
        session.game.synchronize_navy_battle();
        if !matches!(session.game.stop(), TurnStop::NavalBattle(_)) {
            apply_turn_stop(session.game.stop(), &mut next_state);
        }
    }
}

fn spawn_naval_battle(mut commands: Commands) {
    let root = commands.spawn_scene(generated::tactical_3800()).id();
    commands
        .entity(root)
        .insert((NavalBattleRoot, DespawnOnExit(AppState::NavalBattle)));
}

fn bind_naval_battle(
    mut commands: Commands,
    root: Single<Entity, Added<NavalBattleRoot>>,
    tree: RetailTree,
) {
    bind_naval_battle_controls(&mut commands, *root, &tree);
}

fn apply_naval_battle_action(
    action: NavalBattleAction,
    session: &mut GameSession,
    next_state: &mut NextState<AppState>,
) {
    match action {
        NavalBattleAction::Done => {
            let _ = session.game.finish_selected_navy_unit_action();
        }
        NavalBattleAction::Retreat => {
            let _ = session.game.retreat_from_navy_battle();
        }
        NavalBattleAction::Auto => session.game.auto_resolve_navy_battle(),
    }
    if !matches!(session.game.stop(), TurnStop::NavalBattle(_)) {
        apply_turn_stop(session.game.stop(), next_state);
    }
}

fn bind_naval_battle_controls(commands: &mut Commands, root: Entity, tree: &RetailTree) {
    let caption = tree.find(root, fourcc!("curs"));
    commands
        .entity(caption)
        .insert((Text::default(), TextColor(Color::WHITE)));
    for (tag, action) in [
        (fourcc!("done"), NavalBattleAction::Done),
        (fourcc!("auto"), NavalBattleAction::Auto),
        (fourcc!("retr"), NavalBattleAction::Retreat),
    ] {
        commands
            .entity(tree.find(root, tag))
            .insert(ActivateOnPress)
            .remove::<InteractionDisabled>()
            .observe(
                move |_: On<Activate>,
                      mut session: ResMut<GameSession>,
                      mut next_state: ResMut<NextState<AppState>>,
                      mut music: Option<ResMut<MusicDirector>>,
                      time: Option<Res<Time>>| {
                    apply_naval_battle_action(action, &mut session, &mut next_state);
                    if let Some(music) = music.as_mut() {
                        cue_tactical_result(&session.game, music, time.as_deref());
                    }
                },
            );
    }
    let field = tree.find(root, fourcc!("DLOG"));
    commands
        .entity(field)
        .insert((
            NavalBattlefield {
                battle: None,
                view_origin_x: 0,
                view_origin_y: 0,
                centered_ship: None,
            },
            RelativeCursorPosition::default(),
        ))
        .observe(on_battlefield_click);
    commands
        .entity(field)
        .entry::<Node>()
        .and_modify(|mut node| node.overflow = Overflow::clip());
    commands
        .entity(root)
        .insert(NavalBattleView { caption, field });
}

#[allow(clippy::type_complexity)]
fn project_naval_battle(
    mut commands: Commands,
    session: Res<GameSession>,
    views: Query<&NavalBattleView>,
    mut captions: Query<&mut Text>,
    mut battlefields: Query<(&mut NavalBattlefield, Option<&Children>)>,
    projected: Query<Entity, Or<(With<NavalBattleUnit>, With<NavalBattleReachable>)>>,
) {
    let Some(pending) = session.game.pending_naval_battle() else {
        return;
    };
    let Ok(view) = views.single() else {
        return;
    };
    let Ok((mut field_view, children)) = battlefields.get_mut(view.field) else {
        return;
    };
    let mut redraw = session.is_changed() || field_view.is_added() || field_view.is_changed();

    let caption = navy_battle_caption(&session.game, pending);
    captions
        .get_mut(view.caption)
        .expect("caption")
        .0
        .clone_from(&caption);

    let selected = session.game.selected_navy_unit().map(|unit| unit.ship);
    let reachable = session.game.selected_navy_unit_reachable_tiles();
    let Some(battle) = session.game.navy_battle() else {
        return;
    };

    if field_view.battle.as_ref() != Some(pending) {
        field_view.battle = Some(pending.clone());
        field_view.view_origin_x = 0;
        field_view.view_origin_y = 0;
        field_view.centered_ship = None;
        redraw = true;
    }
    if field_view.centered_ship != selected {
        if let Some(unit) = session.game.selected_navy_unit()
            && unit.tile >= 0
        {
            field_view.view_origin_y = center_navy_origin_y(
                field_view.view_origin_y,
                unit.tile / NavyBattle::tile_stride(),
            );
        }
        field_view.centered_ship = selected;
        redraw = true;
    }
    if !redraw {
        return;
    }
    let tile_map = navy_viewport(field_view.view_origin_x, field_view.view_origin_y);
    if let Some(children) = children {
        for child in children.iter() {
            if projected.contains(child) {
                commands.entity(child).despawn();
            }
        }
    }
    let field = view.field;
    for tile in &reachable {
        let (x, y, width, height) = navy_tile_xywh(&tile_map, *tile);
        commands.spawn((
            NavalBattleReachable(*tile),
            ChildOf(field),
            Node {
                position_type: PositionType::Absolute,
                left: px(x),
                top: px(y),
                width: px(width),
                height: px(height),
                ..default()
            },
            BackgroundColor(Color::srgba(1.0, 1.0, 0.2, 0.35)),
        ));
    }
    for unit in battle.units() {
        if unit.destroyed || unit.tile < 0 {
            continue;
        }
        let (x, y, width, height) = navy_unit_xywh(&tile_map, unit.tile);
        let color = match unit.side {
            BattleSide::Attacker => Color::srgb(0.75, 0.2, 0.15),
            BattleSide::Defender => Color::srgb(0.15, 0.3, 0.75),
        };
        let selected = selected == Some(unit.ship);
        commands.spawn((
            NavalBattleUnit(unit.ship),
            ChildOf(field),
            Node {
                position_type: PositionType::Absolute,
                left: px(x),
                top: px(y),
                width: px(width),
                height: px(height),
                border: UiRect::all(px(if selected { 2 } else { 0 })),
                ..default()
            },
            BorderColor::all(Color::WHITE),
            BackgroundColor(color),
            Pickable::IGNORE,
        ));
    }
}

fn scroll_naval_battle(
    time: Res<Time>,
    mut last_scroll_tick: Local<Option<u128>>,
    window: Single<&Window, With<PrimaryWindow>>,
    mut fields: Query<&mut NavalBattlefield>,
    session: Res<GameSession>,
) {
    let Ok(mut view) = fields.single_mut() else {
        return;
    };
    let Some(cursor) = window.cursor_position() else {
        return;
    };
    let direction = if cursor.y <= 4.0 {
        -1
    } else if cursor.y >= window.height() - 4.0 {
        1
    } else {
        return;
    };
    let tick16 = time.elapsed().as_millis() / 16;
    if last_scroll_tick.is_some_and(|last| last + 3 >= tick16) {
        return;
    }
    *last_scroll_tick = Some(tick16);
    if session.game.navy_battle().is_none() {
        return;
    }
    let rows = NavyBattle::tile_count() / NavyBattle::tile_stride();
    let max_origin = (rows * TACTICAL_TILE_ROW_HEIGHT_PX - BATTLEFIELD_HEIGHT_PX).max(0);
    view.view_origin_y =
        (view.view_origin_y + direction * TACTICAL_TILE_ROW_HEIGHT_PX).clamp(0, max_origin);
    view.centered_ship = session.game.selected_navy_unit().map(|unit| unit.ship);
}

fn navy_battle_caption(state: &GameState, battle: &PendingNavalBattle) -> String {
    let attacker_nation = state.task_force(battle.attacker).map(|force| force.nation);
    let defender_nation = state.task_force(battle.defender).map(|force| force.nation);
    let attacker = attacker_nation
        .and_then(|nation| state.nations().display_name(nation))
        .unwrap_or("");
    let defender = defender_nation
        .and_then(|nation| state.nations().display_name(nation))
        .unwrap_or("");
    format!("{attacker} engages {defender}")
}

fn on_battlefield_click(
    click: On<Pointer<Click>>,
    fields: Query<(&RelativeCursorPosition, &NavalBattlefield)>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    if click.event.button != PointerButton::Primary {
        return;
    }
    let Ok((cursor, view)) = fields.get(click.entity) else {
        return;
    };
    let Some((x, y)) = battlefield_cursor_pixel(cursor) else {
        return;
    };
    if apply_battlefield_click(&mut session, x, y, view.view_origin_x, view.view_origin_y)
        && !matches!(session.game.stop(), TurnStop::NavalBattle(_))
    {
        apply_turn_stop(session.game.stop(), &mut next_state);
    }
}

fn apply_battlefield_click(
    session: &mut GameSession,
    x: i32,
    y: i32,
    view_origin_x: i32,
    view_origin_y: i32,
) -> bool {
    let tile_map = navy_viewport(view_origin_x, view_origin_y);
    let Some(tile) = navy_tile_at_pixel(&tile_map, x, y) else {
        return false;
    };
    session.game.navy_action_at(tile).is_ok()
}

fn cue_tactical_result(game: &GameState, music: &mut MusicDirector, time: Option<&Time>) {
    let Some(report) = game.battle_reports().last() else {
        return;
    };
    let winner = report.sides[report
        .participant
        .expect("resolved naval battle report has a winner")]
    .nation;
    let cue = if winner == game.turn().active_nation {
        MusicTrack::BATTLE_VICTORY
    } else {
        MusicTrack::BATTLE_DEFEAT
    };
    let now = time.map_or(0, |time| {
        u32::try_from(time.elapsed().as_millis() / 16).unwrap_or(u32::MAX)
    });
    music.request_preset(cue, false, now);
}

#[cfg(test)]
mod tests {
    use super::super::retail::RetailTag;
    use super::*;
    use crate::ui::test_support::beginning_of_game_parts;
    use bevy::state::app::StatesPlugin;
    use indexmap::IndexMap;

    fn player_naval_battle_state() -> GameState {
        let mut parts = beginning_of_game_parts();
        let player = parts.turn.active_nation;
        let hostile = NationId::new(1);
        parts.diplomacy.relationships[hostile][player] = DiplomaticRelationship::War;
        parts.diplomacy.relationships[player][hostile] = DiplomaticRelationship::War;
        parts.diplomacy.relationship_turns[hostile][player] = None;
        parts.diplomacy.relationship_turns[player][hostile] = None;

        let location = OceanZoneId::new(0);
        let attacker_ship = parts.object_ids.ship();
        let defender_ship = parts.object_ids.ship();
        let attacker_force = parts.object_ids.task_force();
        let defender_force = parts.object_ids.task_force();
        parts.ships.insert(
            attacker_ship,
            ShipState {
                ship_type: ShipType::Frigate,
                location,
                aggression: NavalAggression::Balanced,
                nation: hostile,
                name: String::new(),
                strength: 900,
                experience: 0,
                selection: ShipSelection::Available,
            },
        );
        parts.ships.insert(
            defender_ship,
            ShipState {
                ship_type: ShipType::Frigate,
                location,
                aggression: NavalAggression::Balanced,
                nation: player,
                name: String::new(),
                strength: 900,
                experience: 0,
                selection: ShipSelection::Available,
            },
        );
        parts.task_forces.insert(
            attacker_force,
            TaskForceState::from_parts(
                NavalAggression::Balanced,
                TaskForceOrder::Patrol,
                TaskForceTarget::None,
                location,
                hostile,
                false,
                -1,
                [(attacker_ship, true)]
                    .into_iter()
                    .collect::<IndexMap<_, _>>(),
            ),
        );
        parts.task_forces.insert(
            defender_force,
            TaskForceState::from_parts(
                NavalAggression::Balanced,
                TaskForceOrder::Blockade,
                TaskForceTarget::None,
                location,
                player,
                false,
                -1,
                [(defender_ship, true)]
                    .into_iter()
                    .collect::<IndexMap<_, _>>(),
            ),
        );
        parts.turn = TurnState::new(
            parts.turn.scenario_map,
            parts.turn.economic_turn,
            parts.turn.diplomacy_year_term_raw,
            parts.turn.selected_asset_set,
            PhaseCode::COMBAT_MOVES,
            parts.turn.turn_flow_status_flags,
            parts.turn.phase_state_by_decade,
            parts.turn.difficulty,
            player,
        );
        let mut state = GameState::from_parts(parts);
        state.restore_captured_stop(Some(TurnStop::NavalBattle(
            NavyOrdersContinuation::player_encounter(attacker_force, defender_force),
        )));
        state
    }

    fn test_app(state: GameState) -> App {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(StatesPlugin)
            .insert_resource(GameSession::new(state))
            .insert_state(AppState::NavalBattle)
            .add_systems(
                OnEnter(AppState::NavalBattle),
                (spawn_test_naval_battle, bind_test_naval_battle).chain(),
            )
            .add_systems(
                Update,
                (synchronize_interactive_navy_battle, project_naval_battle)
                    .chain()
                    .run_if(
                        in_state(AppState::NavalBattle).and_then(resource_exists::<GameSession>),
                    ),
            );
        app
    }

    fn spawn_test_naval_battle(mut commands: Commands) {
        let root = commands
            .spawn((
                NavalBattleRoot,
                Node::default(),
                DespawnOnExit(AppState::NavalBattle),
            ))
            .id();
        commands.spawn((RetailTag(fourcc!("curs")), Node::default(), ChildOf(root)));
        commands.spawn((RetailTag(fourcc!("done")), Node::default(), ChildOf(root)));
        commands.spawn((RetailTag(fourcc!("auto")), Node::default(), ChildOf(root)));
        commands.spawn((RetailTag(fourcc!("retr")), Node::default(), ChildOf(root)));
        commands.spawn((
            RetailTag(fourcc!("DLOG")),
            Node {
                position_type: PositionType::Absolute,
                width: px(BATTLEFIELD_WIDTH_PX),
                height: px(BATTLEFIELD_HEIGHT_PX),
                ..default()
            },
            ChildOf(root),
        ));
    }

    fn bind_test_naval_battle(
        mut commands: Commands,
        root: Option<Single<Entity, Added<NavalBattleRoot>>>,
        tree: RetailTree,
    ) {
        let Some(root) = root else {
            return;
        };
        bind_naval_battle_controls(&mut commands, *root, &tree);
    }

    fn action_entity(app: &mut App, action: NavalBattleAction) -> Entity {
        let tag = match action {
            NavalBattleAction::Done => fourcc!("done"),
            NavalBattleAction::Auto => fourcc!("auto"),
            NavalBattleAction::Retreat => fourcc!("retr"),
        };
        app.world_mut()
            .query::<(Entity, &RetailTag)>()
            .iter(app.world())
            .find_map(|(entity, bound)| (bound.0 == tag).then_some(entity))
            .expect("naval-battle action is bound")
    }

    fn caption(app: &mut App) -> String {
        let view = app
            .world_mut()
            .query::<&NavalBattleView>()
            .single(app.world())
            .expect("naval-battle view is bound");
        app.world()
            .get::<Text>(view.caption)
            .expect("naval-battle caption is bound")
            .0
            .clone()
    }

    fn node_left_top(node: &Node) -> (i32, i32) {
        let Val::Px(left) = node.left else {
            panic!("unit node uses pixel left");
        };
        let Val::Px(top) = node.top else {
            panic!("unit node uses pixel top");
        };
        (left as i32, top as i32)
    }

    #[test]
    fn tile_pixel_round_trip_uses_retail_stagger() {
        let map = navy_viewport(0, 60);
        let tile = 2 * NavyBattle::tile_stride() + 4;
        let (x, y, width, height) = navy_tile_xywh(&map, tile);
        let center = (x + width / 2, y + height / 2);
        assert_eq!(navy_tile_at_pixel(&map, center.0, center.1), Some(tile));
        let odd = 3 * NavyBattle::tile_stride() + 4;
        let (ox, oy, ow, oh) = navy_tile_xywh(&map, odd);
        assert_eq!(ox, 4 * TACTICAL_TILE_WIDTH_PX + TACTICAL_TILE_WIDTH_PX / 2);
        assert_eq!(oy, 3 * TACTICAL_TILE_ROW_HEIGHT_PX - 60);
        assert_eq!(
            navy_tile_at_pixel(&map, ox + ow / 2, oy + oh / 2),
            Some(odd)
        );
    }

    #[test]
    fn center_selected_snaps_and_clamps_the_view_origin() {
        let origin = center_navy_origin_y(0, 20);
        assert_eq!(origin % TACTICAL_TILE_ROW_HEIGHT_PX, 0);
        assert_eq!(origin, 360);
        assert_eq!(center_navy_origin_y(origin, 16), origin);
    }

    #[test]
    fn naval_battle_projects_units_onto_stride_six_anchors() {
        let state = player_naval_battle_state();
        let mut probe = player_naval_battle_state();
        probe.ensure_navy_battle();
        let expected: Vec<_> = probe
            .navy_battle()
            .expect("interactive battle starts on enter")
            .units()
            .filter_map(|unit| {
                if unit.tile < 0 {
                    return None;
                }
                let (x, y, _, _) = navy_unit_xywh(&navy_viewport(0, 0), unit.tile);
                Some((unit.ship, x, y))
            })
            .collect();
        assert_eq!(
            probe.navy_battle().unwrap().stage(),
            NavyBattleStage::Deploying
        );
        assert!(
            expected.is_empty(),
            "player-as-defender starts undeployed; auto-deploy does not run first"
        );
        assert!(
            probe
                .selected_navy_unit_reachable_tiles()
                .contains(&(5 * 0x1d)),
            "retail DeployTacticalUnitToTile accepts defender rows tile/29 in 5..=6"
        );

        let mut app = test_app(state);
        app.update();
        app.update();

        let mut projected: Vec<_> = app
            .world_mut()
            .query::<(&NavalBattleUnit, &Node)>()
            .iter(app.world())
            .map(|(unit, node)| {
                let (left, top) = node_left_top(node);
                (unit.0, left, top)
            })
            .collect();
        projected.sort_by_key(|(id, _, _)| *id);
        let mut expected = expected;
        expected.sort_by_key(|(id, _, _)| *id);
        assert_eq!(projected, expected);
        let expected_caption = {
            let session = app.world().resource::<GameSession>();
            let pending = session
                .game
                .pending_naval_battle()
                .cloned()
                .expect("pending encounter");
            navy_battle_caption(&session.game, &pending)
        };
        assert_eq!(caption(&mut app), expected_caption);
    }

    #[test]
    fn clicking_a_deployment_tile_places_the_core_selected_ship() {
        let mut app = test_app(player_naval_battle_state());
        app.update();
        app.update();

        let ship = {
            let session = app.world().resource::<GameSession>();
            let unit = session
                .game
                .selected_navy_unit()
                .expect("core selected ship");
            assert!(unit.tile < 0);
            unit.ship
        };
        let destination = app
            .world_mut()
            .resource_scope(|_, session: Mut<GameSession>| {
                session
                    .game
                    .selected_navy_unit_reachable_tiles()
                    .into_iter()
                    .next()
                    .expect("defender has a deployment tile")
            });
        let dest_pixel = {
            let (x, y, w, h) = navy_tile_xywh(&navy_viewport(0, 0), destination);
            (x + w / 2, y + h / 2)
        };

        app.world_mut()
            .resource_scope(|_, mut session: Mut<GameSession>| {
                assert!(apply_battlefield_click(
                    &mut session,
                    dest_pixel.0,
                    dest_pixel.1,
                    0,
                    0
                ));
            });
        app.update();
        let after = app
            .world()
            .resource::<GameSession>()
            .game
            .navy_battle()
            .and_then(|battle| {
                battle
                    .units()
                    .find(|unit| unit.ship == ship)
                    .map(|unit| unit.tile)
            })
            .expect("ship still in the battle");
        assert_eq!(after, destination);
    }

    #[test]
    fn auto_resolves_the_pending_encounter() {
        let mut app = test_app(player_naval_battle_state());
        app.update();
        app.update();
        assert_eq!(
            *app.world().resource::<State<AppState>>().get(),
            AppState::NavalBattle
        );
        let auto = action_entity(&mut app, NavalBattleAction::Auto);
        app.world_mut()
            .commands()
            .trigger(Activate { entity: auto });
        app.world_mut().flush();
        app.update();

        let session = app.world().resource::<GameSession>();
        assert!(
            session.game.navy_battle().is_none(),
            "auto-resolve commits the encounter"
        );
        assert_ne!(
            *app.world().resource::<State<AppState>>().get(),
            AppState::NavalBattle
        );
    }
}
