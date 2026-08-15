use super::retail::ModalDialog;
use super::session::apply_turn_stop;
use crate::AppState;
use crate::RetailAssetsResource;
use crate::ui::GameSession;
use crate::ui::RetailUiAssets;
use crate::ui::format_currency;
use crate::ui::generated;
use crate::ui::load_save::OpenFlagMenu;
use crate::ui::query_floater::bind_query_floater_control;
use crate::ui::retail::{RetailPictureSwap, RetailTree, ancestor_with};
use crate::ui::strategic_map::{
    bind_civilian_toolbar, bind_minimap, bind_strategic_base_terrain, register_civilian_orders,
    register_civilian_toolbar, sync_minimap, sync_strategic_base_terrain, sync_strategic_units,
};
use bevy::input_focus::tab_navigation::TabGroup;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use bevy::window::PrimaryWindow;
use imperialism_core::MapEdges;
use imperialism_formats::{FourCc, PictureId, RetailTextStylePreset, TRADE, fourcc};

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum GameStatusDisplay {
    Date,
    Treasury,
}

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
        register_civilian_orders(app);
        register_civilian_toolbar(app);
        app.add_systems(
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
            project_game_status_display.run_if(resource_exists::<GameSession>),
        )
        .add_systems(
            Update,
            (
                scroll_strategic_map,
                sync_strategic_base_terrain,
                sync_strategic_units,
                sync_minimap,
                spawn_turn_alerts_if_pending,
                bind_turn_alert_notice,
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
    let edges = strategic_edge_scroll_mask(cursor, Vec2::new(window.width(), window.height()));
    if edges.is_empty() {
        return;
    }
    let tick16 = time.elapsed().as_millis() / 16;
    if last_scroll_tick.is_some_and(|last| last + 3 >= tick16) {
        return;
    }
    *last_scroll_tick = Some(tick16);
    session.game.scroll_map_viewport(edges);
}

fn strategic_edge_scroll_mask(position: Vec2, dialog_size: Vec2) -> MapEdges {
    const EDGE_PIXELS: f32 = 4.0;

    let x = position.x;
    let y = position.y;
    if x <= -200.0 || y <= -200.0 || x >= dialog_size.x + 200.0 || y >= dialog_size.y + 200.0 {
        return MapEdges::empty();
    }
    let mut edges = MapEdges::empty();
    if x <= EDGE_PIXELS {
        edges |= MapEdges::LEFT;
    } else if x >= dialog_size.x - EDGE_PIXELS {
        edges |= MapEdges::RIGHT;
    }
    if y <= EDGE_PIXELS {
        edges |= MapEdges::TOP;
    } else if y >= dialog_size.y - EDGE_PIXELS {
        edges |= MapEdges::BOTTOM;
    }
    edges
}

fn enter_strategic_map_view(mut session: ResMut<GameSession>) {
    session.game.center_map_on_first_idle_civilian();
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
    tree: RetailTree,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
) {
    bind_native_game_screen_nav(&mut commands, *root, &tree, fourcc!("tool"), None);
    bind_strategic_map_management_pictures(&mut commands, &mut assets, *root, &tree);
    disable_native_control(&mut commands, *root, &tree, fourcc!("DONE"));
    let flag = tree.find(*root, fourcc!("Flag"));
    commands
        .entity(flag)
        .insert(OpenFlagMenu)
        .remove::<InteractionDisabled>();
    bind_strategic_base_terrain(&mut commands, *root, &tree, &mut assets, &session.game);
    bind_minimap(&mut commands, *root, &tree, &mut assets, &session.game);
    bind_civilian_toolbar(&mut commands, &mut assets, *root, &tree);
    bind_game_status_display(&mut commands, &mut assets, *root, &tree);
}

fn bind_strategic_map_management_pictures(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let toolbar = tree.find(root, fourcc!("tool"));
    for (tag, idle_id) in [
        (fourcc!("dipl"), 0x24d9),
        (fourcc!("trad"), 0x24db),
        (fourcc!("city"), 0x24dd),
        (fourcc!("tran"), 0x24df),
    ] {
        let entity = tree.find(toolbar, tag);
        let idle = assets
            .picture(PictureId::new(idle_id))
            .expect("retail strategic management button must load");
        let active = assets
            .picture(PictureId::new(idle_id + 1))
            .expect("retail strategic management pressed button must load");
        commands.entity(entity).insert((
            ImageNode::new(idle.clone()),
            RetailPictureSwap { idle, active },
        ));
    }
}

pub(crate) fn bind_game_status_display(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let (season_font, season_layout, season_line_height, _) = assets
        .text_style(imperialism_formats::RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: -2,
        })
        .expect("retail season status text style");
    let (treasury_font, treasury_layout, treasury_line_height, _) = assets
        .text_style(imperialism_formats::RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 1,
        })
        .expect("retail treasury status text style");
    // Retail draws the nominal text first, then its offset "shadow" copy over it.
    // Bevy draws shadows behind text, so use the retail shadow as the visible face.
    let text_color = assets.palette_color(0x28);
    let shadow_color = assets.palette_color(0);
    bind_status_text(
        commands,
        root,
        tree,
        fourcc!("seas"),
        GameStatusDisplay::Date,
        season_font,
        season_layout,
        season_line_height,
        text_color,
        shadow_color,
    );
    bind_status_text(
        commands,
        root,
        tree,
        fourcc!("trea"),
        GameStatusDisplay::Treasury,
        treasury_font,
        treasury_layout,
        treasury_line_height,
        text_color,
        shadow_color,
    );
}

fn project_game_status_display(
    session: Res<GameSession>,
    added: Query<(), Added<GameStatusDisplay>>,
    retail: Res<RetailAssetsResource>,
    mut displays: Query<(&GameStatusDisplay, &mut Text)>,
) {
    if super::projection_idle(&session, !added.is_empty()) {
        return;
    }
    let nation = session.active_major_nation();
    let date = {
        let season = retail
            .string(10_000, (session.game.turn().economic_turn % 4) as i16)
            .expect("retail season name must load");
        format!("{season}, {}", 1815 + session.game.turn().economic_turn / 4)
    };
    let treasury = format_currency(session.game.nations().major(nation).common.treasury);
    for (kind, mut text) in &mut displays {
        text.0 = match kind {
            GameStatusDisplay::Date => date.clone(),
            GameStatusDisplay::Treasury => treasury.clone(),
        };
    }
}

#[allow(clippy::too_many_arguments)]
fn bind_status_text(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    tag: FourCc,
    kind: GameStatusDisplay,
    font: TextFont,
    layout: TextLayout,
    line_height: bevy::text::LineHeight,
    text_color: Color,
    shadow_color: Color,
) {
    commands.entity(tree.find(root, tag)).insert((
        kind,
        Text::default(),
        font,
        layout,
        line_height,
        TextColor(text_color),
        TextShadow {
            offset: Vec2::ONE,
            color: shadow_color,
        },
    ));
}

pub(crate) fn bind_native_game_screen_nav(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    toolbar_tag: FourCc,
    leave_toolbar_tag: Option<FourCc>,
) {
    bind_query_floater_control(commands, root, tree);
    let toolbar = tree.find(root, toolbar_tag);
    let trade = tree.find(toolbar, TRADE);
    let transport = tree.find(toolbar, fourcc!("tran"));
    let city = tree.find(toolbar, fourcc!("city"));
    let diplomacy = tree.find(toolbar, fourcc!("dipl"));
    for (entity, action) in [
        (trade, GameScreenNavAction::Trade),
        (transport, GameScreenNavAction::Transport),
        (city, GameScreenNavAction::City),
        (diplomacy, GameScreenNavAction::Diplomacy),
    ] {
        commands
            .entity(entity)
            .insert(action)
            .observe(on_game_screen_activate);
    }
    if let Some(leave_toolbar_tag) = leave_toolbar_tag {
        let toolbar = tree.find(root, leave_toolbar_tag);
        let leave = tree.find(toolbar, fourcc!("end "));
        commands
            .entity(leave)
            .insert((GameScreenNavAction::StrategicMap, ActivateOnPress))
            .remove::<InteractionDisabled>()
            .observe(on_game_screen_activate);
    }
}

fn disable_native_control(commands: &mut Commands, root: Entity, tree: &RetailTree, tag: FourCc) {
    commands
        .entity(tree.find(root, tag))
        .insert(InteractionDisabled);
}

fn on_game_screen_activate(
    activate: On<Activate>,
    actions: Query<&GameScreenNavAction>,
    state: Res<State<AppState>>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let action = actions
        .get(activate.entity)
        .expect("game-screen Activate is bound on a GameScreenNavAction control");
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

#[derive(Component)]
struct TurnAlertNotice;

fn spawn_turn_alerts_if_pending(
    mut commands: Commands,
    session: Res<GameSession>,
    existing: Query<(), With<TurnAlertNotice>>,
) {
    if !existing.is_empty() || !session.game.turn_alerts_pending() {
        return;
    }
    let root = commands.spawn_scene(generated::linger_2020()).id();
    commands.entity(root).insert((
        TurnAlertNotice,
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(20),
        Pickable::default(),
        DespawnOnExit(AppState::StrategicMap),
    ));
}

fn bind_turn_alert_notice(
    mut commands: Commands,
    notice: Option<Single<Entity, Added<TurnAlertNotice>>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
) {
    let Some(root) = notice else {
        return;
    };
    let root = *root;
    let notice_color = TextColor(assets.palette_color(0));
    commands
        .entity(tree.find(root, fourcc!("titl")))
        .insert((Text::new("Report from your\nAdvisors\n\n"), notice_color));
    let body = tree.find(root, fourcc!("info"));
    let (body_font, body_layout, body_line_height, _) = assets
        .text_style(RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 0,
        })
        .expect("retail turn-alert body style");
    commands.entity(body).insert((
        Text::new("Your ministers have an urgent report."),
        body_font,
        body_layout,
        body_line_height,
        notice_color,
    ));
    let okay = tree.find(root, fourcc!("okay"));
    commands
        .entity(okay)
        .insert(ActivateOnPress)
        .remove::<InteractionDisabled>()
        .observe(on_turn_alert_dismiss);
    let cancel = tree.find(root, fourcc!("cncl"));
    commands.entity(cancel).insert(Visibility::Hidden);
}

fn on_turn_alert_dismiss(
    activate: On<Activate>,
    parents: Query<&ChildOf>,
    notices: Query<Entity, With<TurnAlertNotice>>,
    mut session: ResMut<GameSession>,
    mut commands: Commands,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let root = ancestor_with(activate.entity, &parents, &notices)
        .expect("turn alert belongs to its dialog");
    let stop = session.game.dismiss_turn_alerts();
    commands.entity(root).despawn();
    apply_turn_stop(stop, &mut next_state);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategic_scroll_uses_retail_dialog_edges_not_map_child_edges() {
        let dialog = Vec2::new(640.0, 480.0);
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(5.0, 5.0), dialog),
            MapEdges::empty()
        );
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(4.0, 240.0), dialog),
            MapEdges::LEFT
        );
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(636.0, 240.0), dialog),
            MapEdges::RIGHT
        );
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(320.0, 4.0), dialog),
            MapEdges::TOP
        );
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(320.0, 476.0), dialog),
            MapEdges::BOTTOM
        );
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(-199.0, -199.0), dialog),
            MapEdges::TOP | MapEdges::LEFT
        );
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(-200.0, 240.0), dialog),
            MapEdges::empty()
        );
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(840.0, 240.0), dialog),
            MapEdges::empty()
        );

        // The map child ends at x=517 beneath the right toolbar. Retail tests
        // the enclosing 640-pixel dialog, so toolbar hover is not an edge.
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(520.0, 120.0), dialog),
            MapEdges::empty()
        );
        assert_eq!(
            strategic_edge_scroll_mask(Vec2::new(620.0, 120.0), dialog),
            MapEdges::empty()
        );
    }
}
