use super::{
    MapAction, MapEdges, StrategicMapSession, StrategicSelection, StrategicView,
    animate_civilian_work, animate_strategic_selection, bind_army_toolbar, bind_civilian_toolbar,
    bind_minimap, bind_navy_toolbar, bind_ocean_view, bind_strategic_base_terrain,
    on_strategic_map_click, register_army_toolbar, register_civilian_toolbar, register_map_click,
    register_map_keys, register_map_modals, register_navy_toolbar, register_ocean_view,
    sync_minimap, sync_strategic_base_terrain, sync_strategic_selection, sync_strategic_units,
};
use crate::AppState;
use crate::ui::GameSession;
use crate::ui::RetailUiAssets;
use crate::ui::game_shell::{
    TurnAlertQueue, TurnSummaryNotice, bind_game_status_display, bind_native_game_screen_nav,
};
use crate::ui::generated;
use crate::ui::hover_help::bind_hover_help_texts;
use crate::ui::linger::spawn_linger_dialog;
use crate::ui::load_save::bind_open_flag_menu;
use crate::ui::retail::{RetailPictureSwap, RetailTree};
use crate::ui::session::apply_turn_stop;
use crate::ui::window::no_modal;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::Activate;
use bevy::window::PrimaryWindow;
use imperialism_core::NationId;
use imperialism_formats::{PictureId, fourcc};

#[derive(Component)]
struct StrategicMapRoot;

pub(crate) struct StrategicMapPlugin;

impl Plugin for StrategicMapPlugin {
    fn build(&self, app: &mut App) {
        register_civilian_toolbar(app);
        register_army_toolbar(app);
        register_navy_toolbar(app);
        register_map_click(app);
        register_map_keys(app);
        register_map_modals(app);
        register_ocean_view(app);
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
            (
                scroll_strategic_map.run_if(no_modal),
                sync_strategic_base_terrain,
                sync_strategic_units,
                sync_strategic_selection,
                animate_strategic_selection,
                animate_civilian_work,
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
    mut map: ResMut<StrategicMapSession>,
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
    map.apply(&mut session.game, MapAction::Scroll(edges));
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

fn spawn_strategic_map(mut commands: Commands) {
    let root = commands.spawn_scene(generated::mapview_2013()).id();
    commands
        .entity(root)
        .insert((StrategicMapRoot, DespawnOnExit(AppState::StrategicMap)));
}

fn enter_strategic_map_view(session: Res<GameSession>, mut map: ResMut<StrategicMapSession>) {
    let nation = session.game.turn().active_nation;
    let idle = session.game.first_idle_civilian(nation).map(|(id, _)| id);
    map.selection = StrategicSelection::Civilian(idle);
    if let Some(tile) = session.game.first_idle_civilian_tile(nation) {
        map.view = StrategicView::Detailed {
            origin: session.game.map().viewport_origin_centered_on(tile),
        };
    } else if map.view.is_overview() {
        let origin = map.view.detailed_origin(&session.game);
        map.view = StrategicView::Detailed { origin };
    }
}

fn bind_strategic_map(
    mut commands: Commands,
    root: Single<Entity, Added<StrategicMapRoot>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    mut session: ResMut<GameSession>,
    map: Res<StrategicMapSession>,
    arrow_parts: Query<&crate::ui::retail::NumberedArrowParts>,
    placard_parts: Query<&crate::ui::retail::PlacardParts>,
) {
    bind_native_game_screen_nav(
        &mut commands,
        *root,
        &tree,
        fourcc!("tool"),
        None,
        true,
        AppState::StrategicMap,
    );
    bind_strategic_map_management_pictures(&mut commands, &mut assets, *root, &tree);
    commands
        .entity(tree.find(*root, fourcc!("DONE")))
        .remove::<InteractionDisabled>()
        .observe(on_end_turn);
    let flag = tree.find(*root, fourcc!("Flag"));
    bind_open_flag_menu(&mut commands, flag);
    // `quer` is enabled by `bind_native_game_screen_nav` / query floater binding.
    // Generated `TPictureButton` has the recovered picture and visibility contract.
    crate::ui::technology_store::bind_open_control(
        &mut commands,
        tree.find(*root, fourcc!("mmap")),
    );
    commands
        .entity(tree.find(*root, fourcc!("send")))
        .insert(Visibility::Hidden);
    let land = bind_strategic_base_terrain(
        &mut commands,
        *root,
        &tree,
        &mut assets,
        &session,
        map.view.detailed_origin(&session.game),
    );
    commands.entity(land).observe(on_strategic_map_click);
    // `TCountry` lazily fills this serialized cache while the view is bound.
    // Continuous map projection reads the resulting tile without mutating game
    // state.
    for nation in NationId::all() {
        session.game.overlay_anchor_for_nation(nation);
    }
    let ocean = bind_ocean_view(&mut commands, &mut assets, *root, &tree, &session);
    commands.entity(ocean).observe(on_strategic_map_click);
    bind_minimap(
        &mut commands,
        *root,
        &tree,
        &mut assets,
        &session,
        map.view.detailed_origin(&session.game),
    );
    bind_civilian_toolbar(&mut commands, &mut assets, *root, &tree);
    bind_army_toolbar(&mut commands, *root, &tree, &arrow_parts, &placard_parts);
    bind_navy_toolbar(&mut commands, *root, &tree, &arrow_parts, &placard_parts);
    bind_game_status_display(&mut commands, &mut assets, *root, &tree);
    bind_strategic_hover(&mut commands, &mut assets, *root, &tree);
}

fn on_end_turn(
    _activate: On<Activate>,
    mut commands: Commands,
    mut session: ResMut<GameSession>,
    prefs: Res<crate::ui::preferences::GamePreferences>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let stop = session
        .game
        .finish_player_orders(prefs.turn_alerts_enabled());
    let stop = session
        .game
        .apply_land_battle_watch_policy(stop, prefs.tactical_battles_enabled());
    match stop {
        imperialism_core::TurnStop::TurnAlerts(alerts) => {
            commands.insert_resource(TurnAlertQueue(alerts.into()));
            next_state.set(AppState::StrategicMap);
        }
        stop => {
            commands.remove_resource::<TurnAlertQueue>();
            apply_turn_stop(stop, &mut next_state);
        }
    }
}

fn bind_strategic_hover(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    // HoverHelpBar + recovered curs style come from codegen / Windows deltas.
    let civilian_seas = format!(
        "{}, {}",
        assets.get_string(0x2730, 0x12),
        assets.get_string(0x2730, 8)
    );
    bind_hover_help_texts(
        commands,
        root,
        tree,
        [
            (fourcc!("seas"), civilian_seas),
            (fourcc!("ZmOt"), String::new()),
        ],
    );
    commands
        .entity(tree.find(root, fourcc!("ZmOt")))
        .remove::<InteractionDisabled>()
        .observe(on_ocean_toggle);
}

fn on_ocean_toggle(
    _activate: On<Activate>,
    keys: Res<ButtonInput<KeyCode>>,
    mut commands: Commands,
    assets: RetailUiAssets,
    mut session: ResMut<GameSession>,
    mut map: ResMut<StrategicMapSession>,
) {
    if keys.pressed(KeyCode::ControlLeft) || keys.pressed(KeyCode::ControlRight) {
        let tag = session.game.map().scenario_tag.as_str();
        let body = if tag.is_empty() {
            String::from("Imperialism")
        } else {
            crate::ui::fill_brackets(&assets.get_string(0x273f, 1), &[tag])
        };
        spawn_linger_dialog(
            &mut commands,
            TurnSummaryNotice(body),
            AppState::StrategicMap,
        );
        return;
    }
    map.apply(&mut session.game, MapAction::ToggleZoom);
}

fn bind_strategic_map_management_pictures(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let toolbar = tree.find(root, fourcc!("tool"));
    for (tag, idle_id) in [
        (fourcc!("dipl"), PictureId::new(0x24d9)),
        (fourcc!("trad"), PictureId::new(0x24db)),
        (fourcc!("city"), PictureId::new(0x24dd)),
        (fourcc!("tran"), PictureId::new(0x24df)),
    ] {
        let entity = tree.find(toolbar, tag);
        let idle = assets.picture(idle_id);
        let active = assets.picture(idle_id.offset(1));
        commands.entity(entity).insert((
            ImageNode::new(idle.clone()),
            RetailPictureSwap { idle, active },
        ));
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
