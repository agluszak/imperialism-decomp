use crate::AppState;
use crate::ui::RetailUiAssets;
use crate::ui::format_currency;
use crate::ui::generated;
use crate::ui::random_setup::GameSession;
use crate::ui::retail::{RetailTag, find_descendant};
use crate::ui::strategic_map::{
    bind_strategic_base_terrain, sync_strategic_base_terrain, sync_strategic_units,
};
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use bevy::window::PrimaryWindow;
use imperialism_core::MajorNationId;
use imperialism_formats::{FourCc, TRADE, fourcc};

#[derive(Component)]
struct StrategicMapRoot;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum GameScreenNavAction {
    StrategicMap,
    Trade,
    Transport,
    City,
    Diplomacy,
}

pub(crate) struct GameShellPlugin;

impl Plugin for GameShellPlugin {
    fn build(&self, app: &mut App) {
        app.add_observer(on_game_screen_activate)
            .add_systems(
                OnEnter(AppState::StrategicMap),
                (
                    enter_strategic_map_view,
                    spawn_strategic_map,
                    bind_strategic_map,
                )
                    .chain(),
            )
            .add_systems(
                Update,
                (
                    scroll_strategic_map,
                    sync_strategic_base_terrain,
                    sync_strategic_units,
                )
                    .chain()
                    .run_if(in_state(AppState::StrategicMap)),
            );
    }
}

fn scroll_strategic_map(
    time: Res<Time>,
    mut last_scroll_tick: Local<Option<u128>>,
    window: Single<&Window, With<PrimaryWindow>>,
    mut session: ResMut<GameSession>,
) {
    let Some(cursor) = window.cursor_position() else {
        return;
    };
    let edge_mask = strategic_edge_scroll_mask(cursor, Vec2::new(window.width(), window.height()));
    if edge_mask == 0 {
        return;
    }
    let tick16 = time.elapsed().as_millis() / 16;
    if last_scroll_tick.is_some_and(|last| last + 3 >= tick16) {
        return;
    }
    *last_scroll_tick = Some(tick16);
    session.0.map.scroll_viewport(edge_mask);
}

fn strategic_edge_scroll_mask(position: Vec2, dialog_size: Vec2) -> u8 {
    const EDGE_PIXELS: f32 = 4.0;
    const EDGE_UP: u8 = 0x01;
    const EDGE_DOWN: u8 = 0x02;
    const EDGE_RIGHT: u8 = 0x04;
    const EDGE_LEFT: u8 = 0x08;

    let x = position.x;
    let y = position.y;
    if x <= -200.0 || y <= -200.0 || x >= dialog_size.x + 200.0 || y >= dialog_size.y + 200.0 {
        return 0;
    }
    let mut edge_mask = 0;
    if x <= EDGE_PIXELS {
        edge_mask |= EDGE_LEFT;
    } else if x >= dialog_size.x - EDGE_PIXELS {
        edge_mask |= EDGE_RIGHT;
    }
    if y <= EDGE_PIXELS {
        edge_mask |= EDGE_UP;
    } else if y >= dialog_size.y - EDGE_PIXELS {
        edge_mask |= EDGE_DOWN;
    }
    edge_mask
}

fn enter_strategic_map_view(mut session: ResMut<GameSession>) {
    let Some(tile) = session
        .0
        .first_idle_civilian_tile(session.0.turn().active_nation)
    else {
        return;
    };
    let origin = session.0.map.viewport_origin_centered_on(tile);
    session.0.map.view_origin = origin;
}

fn spawn_strategic_map(mut commands: Commands) {
    let root = commands.spawn_scene(generated::mapview_2013()).id();
    commands
        .entity(root)
        .insert((StrategicMapRoot, DespawnOnExit(AppState::StrategicMap)));
}

fn bind_strategic_map(
    mut commands: Commands,
    root: Single<Entity, Added<StrategicMapRoot>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    bind_native_game_screen_nav(
        &mut commands,
        *root,
        &children,
        &tags,
        fourcc!("tool"),
        None,
    );
    disable_native_control(&mut commands, *root, &children, &tags, fourcc!("DONE"));
    bind_strategic_base_terrain(
        &mut commands,
        *root,
        &children,
        &tags,
        &mut assets,
        &session.0,
    );
    project_date_and_treasury(
        &mut commands,
        &mut assets,
        *root,
        &children,
        &tags,
        &session,
    );
}

pub(crate) fn project_date_and_treasury(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    session: &GameSession,
) {
    let state = &session.0;
    set_control_text(
        commands,
        root,
        children,
        tags,
        fourcc!("seas"),
        format_retail_date(assets, state.turn().economic_turn),
    );
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("Game screen requires an active major nation");
    let treasury = format_currency(state.nations().major(nation).common.treasury);
    set_control_text(commands, root, children, tags, fourcc!("trea"), treasury);
}

fn format_retail_date(assets: &mut RetailUiAssets, economic_turn: i32) -> String {
    let season = assets
        .string(10_000, (economic_turn % 4) as i16)
        .expect("retail season name must load");
    format!("{season}, {}", 1815 + economic_turn / 4)
}

fn set_control_text(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    tag: FourCc,
    value: String,
) {
    commands
        .entity(find_descendant(root, tag, children, tags))
        .insert(Text::new(value));
}

pub(crate) fn bind_native_game_screen_nav(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    toolbar_tag: FourCc,
    leave_toolbar_tag: Option<FourCc>,
) {
    let toolbar = find_descendant(root, toolbar_tag, children, tags);
    let trade = find_descendant(toolbar, TRADE, children, tags);
    let transport = find_descendant(toolbar, fourcc!("tran"), children, tags);
    let city = find_descendant(toolbar, fourcc!("city"), children, tags);
    let diplomacy = find_descendant(toolbar, fourcc!("dipl"), children, tags);
    for (entity, action) in [
        (trade, GameScreenNavAction::Trade),
        (transport, GameScreenNavAction::Transport),
        (city, GameScreenNavAction::City),
        (diplomacy, GameScreenNavAction::Diplomacy),
    ] {
        commands.entity(entity).insert(action);
    }
    if let Some(leave_toolbar_tag) = leave_toolbar_tag {
        let toolbar = find_descendant(root, leave_toolbar_tag, children, tags);
        let leave = find_descendant(toolbar, fourcc!("end "), children, tags);
        commands
            .entity(leave)
            .insert((GameScreenNavAction::StrategicMap, ActivateOnPress))
            .remove::<InteractionDisabled>();
    }
}

/// Marks a recovered control [`InteractionDisabled`] because its retail behavior
/// is not implemented yet.
fn disable_native_control(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    tag: FourCc,
) {
    commands
        .entity(find_descendant(root, tag, children, tags))
        .insert(InteractionDisabled);
}

fn on_game_screen_activate(
    activate: On<Activate>,
    actions: Query<&GameScreenNavAction>,
    state: Res<State<AppState>>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let destination = match *action {
        GameScreenNavAction::StrategicMap => AppState::StrategicMap,
        GameScreenNavAction::Trade => AppState::Trade,
        GameScreenNavAction::Transport => AppState::Transport,
        GameScreenNavAction::City => AppState::City,
        GameScreenNavAction::Diplomacy => AppState::Diplomacy,
    };
    if destination != *state.get() {
        next_state.set(destination);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategic_scroll_uses_retail_dialog_edges_not_map_child_edges() {
        let dialog = Vec2::new(640.0, 480.0);
        assert_eq!(strategic_edge_scroll_mask(Vec2::new(5.0, 5.0), dialog), 0);
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(4.0, 240.0), dialog),
            0x08
        );
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(636.0, 240.0), dialog),
            0x04
        );
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(320.0, 4.0), dialog),
            0x01
        );
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(320.0, 476.0), dialog),
            0x02
        );
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(-199.0, -199.0), dialog),
            0x09
        );
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(-200.0, 240.0), dialog),
            0
        );
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(840.0, 240.0), dialog),
            0
        );

        // The map child ends at x=517 beneath the right toolbar. Retail tests
        // the enclosing 640-pixel dialog, so toolbar hover is not an edge.
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(520.0, 120.0), dialog),
            0
        );
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(620.0, 120.0), dialog),
            0
        );
    }
}
