use crate::AppState;
use crate::RetailAssetsResource;
use crate::ui::GameSession;
use crate::ui::RetailUiAssets;
use crate::ui::format_currency;
use crate::ui::generated;
use crate::ui::load_save::OpenFlagMenu;
use crate::ui::query_floater::bind_query_floater_control;
use crate::ui::retail::{RetailPictureSwap, RetailTag, find_descendant};
use crate::ui::strategic_map::{
    bind_minimap, bind_strategic_base_terrain, register_civilian_orders, sync_minimap,
    sync_strategic_base_terrain, sync_strategic_units,
};
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use bevy::window::PrimaryWindow;
use imperialism_core::{MajorNationId, MapEdges};
use imperialism_formats::{FourCc, PictureId, TRADE, fourcc};

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
    bind_strategic_map_management_pictures(&mut commands, &mut assets, *root, &children, &tags);
    disable_native_control(&mut commands, *root, &children, &tags, fourcc!("DONE"));
    let flag = find_descendant(*root, fourcc!("Flag"), &children, &tags);
    commands
        .entity(flag)
        .insert(OpenFlagMenu)
        .remove::<InteractionDisabled>();
    bind_strategic_base_terrain(
        &mut commands,
        *root,
        &children,
        &tags,
        &mut assets,
        &session.game,
    );
    bind_minimap(
        &mut commands,
        *root,
        &children,
        &tags,
        &mut assets,
        &session.game,
    );
    bind_game_status_display(
        &mut commands,
        &mut assets,
        *root,
        &children,
        &tags,
        &session,
    );
}

fn bind_strategic_map_management_pictures(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
) {
    let toolbar = find_descendant(root, fourcc!("tool"), children, tags);
    for (tag, idle_id) in [
        (fourcc!("dipl"), 0x24d9),
        (fourcc!("trad"), 0x24db),
        (fourcc!("city"), 0x24dd),
        (fourcc!("tran"), 0x24df),
    ] {
        let entity = find_descendant(toolbar, tag, children, tags);
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
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    session: &GameSession,
) {
    let state = &session.game;
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
        children,
        tags,
        fourcc!("seas"),
        GameStatusDisplay::Date,
        format_retail_date(assets, state.turn().economic_turn),
        season_font,
        season_layout,
        season_line_height,
        text_color,
        shadow_color,
    );
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("Game screen requires an active major nation");
    let treasury = format_currency(state.nations().major(nation).common.treasury);
    bind_status_text(
        commands,
        root,
        children,
        tags,
        fourcc!("trea"),
        GameStatusDisplay::Treasury,
        treasury,
        treasury_font,
        treasury_layout,
        treasury_line_height,
        text_color,
        shadow_color,
    );
}

fn format_retail_date(assets: &RetailUiAssets, economic_turn: i32) -> String {
    let season = assets
        .string(10_000, (economic_turn % 4) as i16)
        .expect("retail season name must load");
    format!("{season}, {}", 1815 + economic_turn / 4)
}

fn project_game_status_display(
    session: Res<GameSession>,
    retail: Res<RetailAssetsResource>,
    mut displays: Query<(&GameStatusDisplay, &mut Text)>,
) {
    if !session.is_changed() {
        return;
    }
    let state = &session.game;
    let nation = MajorNationId::from_nation(state.turn().active_nation)
        .expect("Game screen requires an active major nation");
    let date = {
        let season = retail
            .string(10_000, (state.turn().economic_turn % 4) as i16)
            .expect("retail season name must load");
        format!("{season}, {}", 1815 + state.turn().economic_turn / 4)
    };
    let treasury = format_currency(state.nations().major(nation).common.treasury);
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
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    tag: FourCc,
    kind: GameStatusDisplay,
    value: String,
    font: TextFont,
    layout: TextLayout,
    line_height: bevy::text::LineHeight,
    text_color: Color,
    shadow_color: Color,
) {
    commands
        .entity(find_descendant(root, tag, children, tags))
        .insert((
            kind,
            Text::new(value),
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
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    toolbar_tag: FourCc,
    leave_toolbar_tag: Option<FourCc>,
) {
    bind_query_floater_control(commands, root, children, tags);
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
        commands
            .entity(entity)
            .insert(action)
            .observe(on_game_screen_activate);
    }
    if let Some(leave_toolbar_tag) = leave_toolbar_tag {
        let toolbar = find_descendant(root, leave_toolbar_tag, children, tags);
        let leave = find_descendant(toolbar, fourcc!("end "), children, tags);
        commands
            .entity(leave)
            .insert((GameScreenNavAction::StrategicMap, ActivateOnPress))
            .remove::<InteractionDisabled>()
            .observe(on_game_screen_activate);
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
