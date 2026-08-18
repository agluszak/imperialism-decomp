use super::generated;
use super::retail::RetailTree;
use super::session::{GameSession, apply_turn_stop};
use crate::AppState;
use crate::media::MusicDirector;
use bevy::picking::events::{Click, Pointer};
use bevy::picking::pointer::PointerButton;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui::RelativeCursorPosition;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use imperialism_core::*;
use imperialism_formats::{MusicTrack, fourcc};

/// `TTacArmyView` battlefield surface is 0x5dc×0x1c2; 15 rows fill the 450px DLOG height.
const TACTICAL_TILE_WIDTH_PX: i32 = 50;
const TACTICAL_TILE_ROW_HEIGHT_PX: i32 = 30;
/// `TTacticalBattleView::ComputeTacticalUnitSpriteDrawRectAndApplyFacingOffset` grows the tile up by 0x14.
const UNIT_SPRITE_LIFT_PX: i32 = 0x14;
const BATTLEFIELD_WIDTH_PX: i32 = 575;
const BATTLEFIELD_HEIGHT_PX: i32 = 450;

#[derive(Component)]
struct LandBattleRoot;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum LandBattleAction {
    Done,
    Auto,
    Retreat,
}

#[derive(Component)]
struct LandBattleCaption;

#[derive(Component)]
struct LandBattlefield;

#[derive(Component, Clone, Copy)]
#[allow(dead_code)]
struct LandBattleUnit(ArmyUnitId);

#[derive(Component, Clone, Copy)]
#[allow(dead_code)]
struct LandBattleReachable(TacticalHex);

/// Pixel↔hex for this screen (`TTacticalBattleView` 0x5a86d0 / 0x5a87d0, viewOriginX = 0).
struct LandBattleHexMap {
    column_count: i32,
}

impl LandBattleHexMap {
    fn new(column_count: i32) -> Self {
        Self { column_count }
    }

    fn tile_rect(&self, hex: TacticalHex) -> (i32, i32, i32, i32) {
        let row = hex.row();
        let mut x = hex.column() * TACTICAL_TILE_WIDTH_PX;
        if row & 1 != 0 {
            x += TACTICAL_TILE_WIDTH_PX / 2;
        }
        let y = row * TACTICAL_TILE_ROW_HEIGHT_PX;
        (x, y, TACTICAL_TILE_WIDTH_PX, TACTICAL_TILE_ROW_HEIGHT_PX)
    }

    fn unit_anchor(&self, hex: TacticalHex) -> (i32, i32, i32, i32) {
        let (x, y, width, height) = self.tile_rect(hex);
        (
            x,
            y - UNIT_SPRITE_LIFT_PX,
            width,
            height + UNIT_SPRITE_LIFT_PX,
        )
    }

    fn hex_at_pixel(&self, x: i32, y: i32) -> Option<TacticalHex> {
        let mut row = y / TACTICAL_TILE_ROW_HEIGHT_PX;
        if row < 0 {
            row = 0;
        }
        let max_row = BATTLEFIELD_HEIGHT_PX / TACTICAL_TILE_ROW_HEIGHT_PX - 1;
        if row >= max_row {
            row = max_row;
        }
        let mut col = x;
        if row & 1 != 0 {
            col -= TACTICAL_TILE_WIDTH_PX / 2;
        }
        col /= TACTICAL_TILE_WIDTH_PX;
        if col < 0 {
            col = 0;
        }
        if col >= self.column_count {
            col = self.column_count - 1;
        }
        TacticalHex::from_row_column(row, col)
    }
}

fn battlefield_cursor_pixel(cursor: &RelativeCursorPosition) -> Option<(i32, i32)> {
    let position = cursor.normalized.filter(|_| cursor.cursor_over())?;
    Some((
        ((position.x + 0.5) * BATTLEFIELD_WIDTH_PX as f32).floor() as i32,
        ((position.y + 0.5) * BATTLEFIELD_HEIGHT_PX as f32).floor() as i32,
    ))
}

pub(crate) struct LandBattlePlugin;

impl Plugin for LandBattlePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::LandBattle),
            (spawn_land_battle, bind_land_battle).chain(),
        )
        .add_systems(
            Update,
            (synchronize_interactive_army_battle, project_land_battle)
                .chain()
                .run_if(in_state(AppState::LandBattle).and_then(resource_exists::<GameSession>)),
        );
    }
}

fn synchronize_interactive_army_battle(
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    assets: Option<Res<crate::RetailAssetsResource>>,
) {
    if session.game.pending_land_battle().is_some()
        && session.game.army_battle().is_none()
        && let Some(stop) = session
            .game
            .synchronize_army_battle(super::session::news_story_ids(assets.as_deref()))
        && stop != TurnStop::LandBattle
    {
        apply_turn_stop(stop, &mut next_state);
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
        .entity(tree.find(root, fourcc!("done")))
        .insert((LandBattleAction::Done, ActivateOnPress))
        .observe(on_land_battle_activate)
        .remove::<InteractionDisabled>();
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
    commands
        .entity(tree.find(root, fourcc!("DLOG")))
        .insert((LandBattlefield, RelativeCursorPosition::default()))
        .observe(on_battlefield_click);
}

#[allow(clippy::type_complexity)]
fn project_land_battle(
    mut commands: Commands,
    session: Res<GameSession>,
    added: Query<(), Added<LandBattleCaption>>,
    mut captions: Query<&mut Text, With<LandBattleCaption>>,
    battlefields: Query<(Entity, Option<&Children>), With<LandBattlefield>>,
    projected: Query<Entity, Or<(With<LandBattleUnit>, With<LandBattleReachable>)>>,
) {
    if super::projection_idle(&session, !added.is_empty()) {
        return;
    }
    let Some(pending) = session.game.pending_land_battle() else {
        return;
    };
    let caption = land_battle_caption(&session.game, pending);
    for mut text in &mut captions {
        text.0.clone_from(&caption);
    }
    let selected = session.game.selected_army_unit().map(|unit| unit.id);
    let reachable = session.game.selected_army_unit_reachable_hexes();
    let Some(battle) = session.game.army_battle() else {
        return;
    };
    let hex_map = LandBattleHexMap::new(battle.column_count());
    for (field, children) in &battlefields {
        if let Some(children) = children {
            for child in children.iter() {
                if projected.contains(child) {
                    commands.entity(child).despawn();
                }
            }
        }
        for hex in &reachable {
            let (x, y, width, height) = hex_map.tile_rect(*hex);
            commands.spawn((
                LandBattleReachable(*hex),
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
            let Some(hex) = unit.hex else {
                continue;
            };
            let (x, y, width, height) = hex_map.unit_anchor(hex);
            let color = match unit.side {
                BattleSide::Attacker => Color::srgb(0.75, 0.2, 0.15),
                BattleSide::Defender => Color::srgb(0.15, 0.3, 0.75),
            };
            let selected = selected == Some(unit.id);
            commands.spawn((
                LandBattleUnit(unit.id),
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
                BackgroundColor(color),
                BorderColor::all(Color::WHITE),
                Text::new(unit.strength.to_string()),
                TextColor(Color::WHITE),
            ));
        }
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

fn on_battlefield_click(
    click: On<Pointer<Click>>,
    fields: Query<&RelativeCursorPosition, With<LandBattlefield>>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    assets: Option<Res<crate::RetailAssetsResource>>,
) {
    if click.event.button != PointerButton::Primary {
        return;
    }
    let Ok(cursor) = fields.get(click.entity) else {
        return;
    };
    let Some((x, y)) = battlefield_cursor_pixel(cursor) else {
        return;
    };
    if let Some(stop) = apply_battlefield_click(
        &mut session,
        x,
        y,
        super::session::news_story_ids(assets.as_deref()),
    ) && stop != TurnStop::LandBattle
    {
        apply_turn_stop(stop, &mut next_state);
    }
}

fn apply_battlefield_click(
    session: &mut GameSession,
    x: i32,
    y: i32,
    story_ids: &[i32],
) -> Option<TurnStop> {
    let column_count = session.game.army_battle().map(ArmyBattle::column_count)?;
    let hex_map = LandBattleHexMap::new(column_count);
    let hex = hex_map.hex_at_pixel(x, y)?;
    session
        .game
        .army_action_at(hex, story_ids)
        .ok()
        .and_then(|(_, stop)| stop)
}

fn on_land_battle_activate(
    activate: On<Activate>,
    actions: Query<&LandBattleAction>,
    mut session: ResMut<GameSession>,
    mut next_state: ResMut<NextState<AppState>>,
    mut music: Option<ResMut<MusicDirector>>,
    time: Option<Res<Time>>,
    assets: Option<Res<crate::RetailAssetsResource>>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    match *action {
        LandBattleAction::Done => {
            if let Ok(Some(stop)) = session
                .game
                .finish_selected_army_unit_action(super::session::news_story_ids(assets.as_deref()))
                && stop != TurnStop::LandBattle
            {
                apply_turn_stop(stop, &mut next_state);
            }
        }
        LandBattleAction::Auto => match session
            .game
            .auto_resolve_land_battle(super::session::news_story_ids(assets.as_deref()))
        {
            TurnStop::LandBattle => {}
            stop => apply_turn_stop(stop, &mut next_state),
        },
        LandBattleAction::Retreat => {
            if let Ok(Some(stop)) = session
                .game
                .retreat_from_army_battle(super::session::news_story_ids(assets.as_deref()))
                && stop != TurnStop::LandBattle
            {
                apply_turn_stop(stop, &mut next_state);
            }
        }
    }
    if let Some(music) = music.as_mut() {
        cue_tactical_result(&session.game, music, time.as_deref());
    }
}

/// `TTacticalBattle` result dialog: `RequestAudioPresetChangeWithDeferredApply(9 or 10, 0)`.
fn cue_tactical_result(game: &GameState, music: &mut MusicDirector, time: Option<&Time>) {
    let Some(report) = game.battle_reports().last() else {
        return;
    };
    let winner = report.sides[report.participant].nation;
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

    fn fixture_parts() -> GameStateParts {
        beginning_of_game_parts()
    }

    fn idle_unit(unit: &MilitaryUnitState) -> MilitaryUnitState {
        let stationed = unit.stationed_province();
        MilitaryUnitState::new(
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
        nation: NationId,
        kind: MilitaryUnitKind,
        from: ProvinceId,
        to: ProvinceId,
        strength: i16,
    ) -> MilitaryUnitState {
        MilitaryUnitState::new(
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
            MilitaryEra::First,
            0,
            0,
        )
    }

    fn garrison_unit(
        nation: NationId,
        kind: MilitaryUnitKind,
        province: ProvinceId,
        strength: i16,
    ) -> MilitaryUnitState {
        MilitaryUnitState::new(
            nation,
            kind,
            Some(province),
            MilitaryOrder::idle([Some(province); 3], [Some(province); 3]),
            nation,
            0,
            true,
            String::new(),
            strength,
            MilitaryEra::First,
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

        parts.military_units = parts
            .military_units
            .iter()
            .map(|(id, unit)| (*id, idle_unit(unit)))
            .collect();
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
        parts.military_units.insert(
            MilitaryUnitId::from_serialized(next + 1),
            redeploy_unit(first.2, MilitaryUnitKind::Regulars, first.0, first.1, 500),
        );
        parts.military_units.insert(
            MilitaryUnitId::from_serialized(next + 2),
            garrison_unit(first.3, MilitaryUnitKind::Militia, first.1, 100),
        );
        parts.military_units.insert(
            MilitaryUnitId::from_serialized(next + 3),
            redeploy_unit(
                second.2,
                MilitaryUnitKind::Regulars,
                second.0,
                second.1,
                500,
            ),
        );
        parts.military_units.insert(
            MilitaryUnitId::from_serialized(next + 4),
            garrison_unit(second.3, MilitaryUnitKind::Militia, second.1, 100),
        );

        parts.turn = TurnState::new(
            parts.turn.scenario_map,
            parts.turn.economic_turn,
            parts.turn.diplomacy_year_term_raw,
            PhaseCode::COMBAT_MOVES,
            parts.turn.turn_flow_status_flags,
            parts.turn.quarter_gate_by_decade,
            parts.turn.difficulty,
            parts.turn.active_nation,
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
            .insert_resource(GameSession::new(state))
            .insert_state(AppState::LandBattle)
            .add_systems(
                OnEnter(AppState::LandBattle),
                (spawn_test_land_battle, bind_test_land_battle).chain(),
            )
            .add_systems(
                Update,
                (synchronize_interactive_army_battle, project_land_battle)
                    .chain()
                    .run_if(
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
            .query::<(&Text, &LandBattleCaption)>()
            .iter(app.world())
            .next()
            .map(|(text, _)| text.0.clone())
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
        let mut live_units = {
            let session = app.world().resource::<GameSession>();
            session
                .game
                .army_battle()
                .expect("the second pending battle has fresh live state")
                .units()
                .filter(|unit| unit.hex.is_some())
                .map(|unit| unit.id)
                .collect::<Vec<_>>()
        };
        let mut projected_units: Vec<_> = app
            .world_mut()
            .query::<&LandBattleUnit>()
            .iter(app.world())
            .map(|unit| unit.0)
            .collect();
        live_units.sort_by_key(|id| id.source().get());
        projected_units.sort_by_key(|id| id.source().get());
        assert_eq!(projected_units, live_units);
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
    fn hex_pixel_round_trip_uses_retail_stagger() {
        let map = LandBattleHexMap::new(16);
        let hex = TacticalHex::from_row_column(2, 4).unwrap();
        let (x, y, width, height) = map.tile_rect(hex);
        let center = (x + width / 2, y + height / 2);
        assert_eq!(map.hex_at_pixel(center.0, center.1), Some(hex));
        let odd = TacticalHex::from_row_column(3, 4).unwrap();
        let (ox, oy, ow, oh) = map.tile_rect(odd);
        assert_eq!(ox, 4 * TACTICAL_TILE_WIDTH_PX + TACTICAL_TILE_WIDTH_PX / 2);
        assert_eq!(map.hex_at_pixel(ox + ow / 2, oy + oh / 2), Some(odd));
    }

    #[test]
    fn land_battle_projects_units_onto_retail_hex_anchors() {
        let state = two_land_battles_state();
        let mut probe = state.clone();
        probe.ensure_army_battle();
        let expected: Vec<_> = probe
            .army_battle()
            .expect("interactive battle starts on enter")
            .units()
            .filter_map(|unit| {
                let hex = unit.hex?;
                let (x, y, _, _) =
                    LandBattleHexMap::new(probe.army_battle().unwrap().column_count())
                        .unit_anchor(hex);
                Some((unit.id, x, y))
            })
            .collect();
        assert_eq!(
            probe.army_battle().unwrap().stage(),
            ArmyBattleStage::Deploying
        );

        let mut app = test_app(state);
        app.update();
        app.update();

        let mut projected: Vec<_> = app
            .world_mut()
            .query::<(&LandBattleUnit, &Node)>()
            .iter(app.world())
            .map(|(unit, node)| {
                let (left, top) = node_left_top(node);
                (unit.0, left, top)
            })
            .collect();
        projected.sort_by_key(|(id, _, _)| id.source().get());
        let mut expected = expected;
        expected.sort_by_key(|(id, _, _)| id.source().get());
        assert_eq!(projected, expected);
    }

    #[test]
    fn clicking_a_deployment_hex_places_the_core_selected_unit() {
        let mut app = test_app(two_land_battles_state());
        app.update();
        app.update();

        let unit_id = {
            let session = app.world().resource::<GameSession>();
            let unit = session
                .game
                .selected_army_unit()
                .expect("core selected unit");
            assert_eq!(unit.hex, None);
            unit.id
        };
        let destination = app
            .world_mut()
            .resource_scope(|_, session: Mut<GameSession>| {
                session
                    .game
                    .selected_army_unit_reachable_hexes()
                    .iter()
                    .copied()
                    .next()
                    .expect("attacker has a deployment hex")
            });
        let dest_pixel = {
            let session = app.world().resource::<GameSession>();
            let map = LandBattleHexMap::new(
                session
                    .game
                    .army_battle()
                    .expect("live battle")
                    .column_count(),
            );
            let (x, y, w, h) = map.tile_rect(destination);
            (x + w / 2, y + h / 2)
        };

        app.world_mut()
            .resource_scope(|_, mut session: Mut<GameSession>| {
                assert_eq!(
                    apply_battlefield_click(&mut session, dest_pixel.0, dest_pixel.1, &[]),
                    None
                );
            });
        app.update();
        let after = app
            .world()
            .resource::<GameSession>()
            .game
            .army_battle()
            .and_then(|battle| battle.unit(unit_id))
            .and_then(|unit| unit.hex)
            .expect("unit still on the grid");
        assert_eq!(after, destination);
    }
}
