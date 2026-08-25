use super::linger::{bind_linger_dialog, spawn_linger_dialog};
use super::session::apply_turn_stop;
use crate::AppState;
use crate::RetailAssetsResource;
use crate::ui::RetailUiAssets;
use crate::ui::format_currency;
use crate::ui::generated;
use crate::ui::hover_help::{
    HoverHelpBarStyle, HoverHelpText, bind_hover_help_bar, bind_hover_help_texts, get_string,
};
use crate::ui::load_save::bind_open_flag_menu;
use crate::ui::map_help;
use crate::ui::query_floater::bind_query_floater_control;
use crate::ui::retail::{RetailPictureSwap, RetailPressedOverlay, RetailTag};
use crate::ui::strategic_map::{
    MapEdges, MapInteractionMode, MapProjection, MapTransition, MapZoomControl,
    StrategicInteraction, StrategicViewport, animate_civilian_work, animate_strategic_selection,
    apply_map_transition, bind_army_toolbar, bind_civilian_toolbar, bind_minimap,
    bind_navy_toolbar, bind_ocean_view, bind_strategic_base_terrain, on_strategic_map_click,
    register_army_toolbar, register_civilian_toolbar, register_map_click, register_map_keys,
    register_map_modals, register_navy_toolbar, register_ocean_view, sync_minimap,
    sync_strategic_base_terrain, sync_strategic_selection, sync_strategic_units,
};
use crate::ui::window::no_modal;
use crate::ui::{GameSession, MapViewOrigin};
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, ActivateOnPress};
use bevy::window::PrimaryWindow;
use imperialism_core::TurnAlert;
use imperialism_formats::{PictureId, fourcc};
use std::collections::VecDeque;

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
        register_civilian_toolbar(app);
        register_army_toolbar(app);
        register_navy_toolbar(app);
        register_map_click(app);
        register_map_keys(app);
        register_map_modals(app);
        register_ocean_view(app);
        map_help::register(app);
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
                scroll_strategic_map.run_if(no_modal),
                sync_status_date_hover,
                sync_strategic_base_terrain,
                sync_strategic_units,
                sync_strategic_selection,
                animate_strategic_selection,
                animate_civilian_work,
                sync_minimap,
                sync_zoom_control,
                spawn_turn_alerts_if_pending,
                bind_turn_alert_notice,
                bind_turn_summary_notice,
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
    mut origin: ResMut<MapViewOrigin>,
    mut maps: Query<(&mut StrategicInteraction, &mut StrategicViewport)>,
) {
    let Ok((mut interaction, mut viewport)) = maps.single_mut() else {
        return;
    };
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
    apply_map_transition(
        &mut session,
        &mut origin,
        &mut interaction,
        &mut viewport,
        MapTransition::Scroll(edges),
    );
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
    let ui = generated::spawn_mapview_2013(&mut commands);
    commands
        .entity(ui.root)
        .insert((StrategicMapRoot, ui, DespawnOnExit(AppState::StrategicMap)));
}

fn enter_strategic_map_view(session: Res<GameSession>, mut origin: ResMut<MapViewOrigin>) {
    if let Some(tile) = session
        .game
        .first_idle_civilian_tile(session.game.turn().active_nation)
    {
        origin.center_on(&session.game, tile);
    }
}

fn bind_strategic_map(
    mut commands: Commands,
    ui: Single<&generated::Mapview2013, Added<StrategicMapRoot>>,
    mut nodes: Query<&mut Node>,
    mut pictures: Query<&mut ImageNode>,
    mut assets: RetailUiAssets,
    session: Res<GameSession>,
    origin: Res<MapViewOrigin>,
) {
    bind_native_game_screen_nav(
        &mut commands,
        ui.trad,
        ui.tran,
        ui.city,
        ui.dipl,
        None,
        Some(ui.quer),
    );
    bind_strategic_map_management_pictures(&mut commands, &mut assets, **ui);
    commands
        .entity(ui.done)
        .insert(ActivateOnPress)
        .remove::<InteractionDisabled>()
        .observe(on_end_turn);
    bind_pressed_overlay(&mut commands, &mut pictures, ui.flag);
    bind_open_flag_menu(&mut commands, ui.flag);
    bind_pressed_overlay(&mut commands, &mut pictures, ui.quer);
    bind_pressed_overlay(&mut commands, &mut pictures, ui.zmot);
    super::technology_store::bind_open_control(&mut commands, ui.mmap);
    commands.entity(ui.send).insert(Visibility::Hidden);
    let land = bind_strategic_base_terrain(&mut commands, ui.dlog, &mut assets, &session, origin.0);
    commands.entity(land).observe(on_strategic_map_click);
    let ocean = bind_ocean_view(&mut commands, &mut assets, ui.dlog, ui.doog, &session);
    commands.entity(ocean).observe(on_strategic_map_click);
    bind_minimap(&mut commands, ui.tool, &mut assets, &session, origin.0);
    bind_civilian_toolbar(&mut commands, &mut assets, **ui);
    bind_army_toolbar(&mut commands, &mut assets, **ui);
    bind_navy_toolbar(&mut commands, &mut assets, **ui);
    bind_game_status_display(&mut commands, &mut assets, ui.seas, ui.trea);
    bind_strategic_hover(&mut commands, &mut assets, **ui, &mut nodes);
}

fn bind_pressed_overlay(
    commands: &mut Commands,
    pictures: &mut Query<&mut ImageNode>,
    entity: Entity,
) {
    commands
        .entity(entity)
        .insert(RetailPressedOverlay)
        .remove::<InteractionDisabled>();
    pictures
        .get_mut(entity)
        .expect("retail picture button has an image")
        .color
        .set_alpha(0.0);
}

fn on_end_turn(
    _activate: On<Activate>,
    mut commands: Commands,
    mut session: ResMut<GameSession>,
    prefs: Res<super::preferences::GamePreferences>,
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
    ui: generated::Mapview2013,
    nodes: &mut Query<&mut Node>,
) {
    bind_hover_help_bar(
        commands,
        assets,
        ui.curs,
        &mut nodes
            .get_mut(ui.curs)
            .expect("strategic hover-help bar has Node"),
        HoverHelpBarStyle::CITY_SITE,
    );
    let civilian_seas = format!(
        "{}, {}",
        get_string(assets, 0x2730, 0x12),
        get_string(assets, 0x2730, 8)
    );
    bind_hover_help_texts(
        commands,
        [(ui.seas, civilian_seas), (ui.zmot, String::new())],
    );
    commands
        .entity(ui.zmot)
        .insert(MapZoomControl)
        .insert(ActivateOnPress)
        .observe(on_ocean_toggle);
}

fn on_ocean_toggle(
    _activate: On<Activate>,
    keys: Res<ButtonInput<KeyCode>>,
    mut commands: Commands,
    assets: RetailUiAssets,
    mut session: ResMut<GameSession>,
    mut origin: ResMut<MapViewOrigin>,
    mut maps: Query<(&mut StrategicInteraction, &mut StrategicViewport)>,
) {
    let Ok((mut interaction, mut viewport)) = maps.single_mut() else {
        return;
    };
    if keys.pressed(KeyCode::ControlLeft) || keys.pressed(KeyCode::ControlRight) {
        let tag = session.game.map().scenario_tag.as_str();
        let body = if tag.is_empty() {
            String::from("Imperialism")
        } else {
            crate::ui::fill_brackets(&get_string(&assets, 0x273f, 1), &[tag])
        };
        spawn_linger_dialog(
            &mut commands,
            TurnSummaryNotice(body),
            AppState::StrategicMap,
        );
        return;
    }
    apply_map_transition(
        &mut session,
        &mut origin,
        &mut interaction,
        &mut viewport,
        MapTransition::ToggleZoom,
    );
}

fn sync_zoom_control(
    viewports: Query<&StrategicViewport>,
    mut controls: Query<&mut RetailTag, With<MapZoomControl>>,
) {
    let (Ok(viewport), Ok(mut tag)) = (viewports.single(), controls.single_mut()) else {
        return;
    };
    tag.0 = if viewport.projection == MapProjection::Overview {
        fourcc!("ZmIn")
    } else {
        fourcc!("ZmOt")
    };
}

fn bind_strategic_map_management_pictures(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    ui: generated::Mapview2013,
) {
    for (entity, idle_id) in [
        (ui.dipl, 0x24d9),
        (ui.trad, 0x24db),
        (ui.city, 0x24dd),
        (ui.tran, 0x24df),
    ] {
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
    season: Entity,
    treasury: Entity,
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
        season,
        GameStatusDisplay::Date,
        season_font,
        season_layout,
        season_line_height,
        text_color,
        shadow_color,
    );
    bind_status_text(
        commands,
        treasury,
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
    entity: Entity,
    kind: GameStatusDisplay,
    font: TextFont,
    layout: TextLayout,
    line_height: bevy::text::LineHeight,
    text_color: Color,
    shadow_color: Color,
) {
    commands.entity(entity).insert((
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

fn sync_status_date_hover(
    interactions: Query<Ref<StrategicInteraction>>,
    assets: RetailUiAssets,
    mut texts: Query<(&GameStatusDisplay, &mut HoverHelpText)>,
) {
    let Ok(interaction) = interactions.single() else {
        return;
    };
    if !interaction.is_changed() {
        return;
    }
    let help = if interaction.mode == MapInteractionMode::Army {
        get_string(&assets, 0x2732, 0x11)
    } else {
        format!(
            "{}, {}",
            get_string(&assets, 0x2730, 0x12),
            get_string(&assets, 0x2730, 8)
        )
    };
    for (kind, mut text) in &mut texts {
        if *kind == GameStatusDisplay::Date {
            text.0.clone_from(&help);
        }
    }
}

pub(crate) fn bind_native_game_screen_nav(
    commands: &mut Commands,
    trade: Entity,
    transport: Entity,
    city: Entity,
    diplomacy: Entity,
    leave: Option<Entity>,
    query: Option<Entity>,
) {
    if let Some(query) = query {
        bind_query_floater_control(commands, query);
    }
    for (entity, action) in [
        (trade, GameScreenNavAction::Trade),
        (transport, GameScreenNavAction::Transport),
        (city, GameScreenNavAction::City),
        (diplomacy, GameScreenNavAction::Diplomacy),
    ] {
        commands
            .entity(entity)
            .insert((action, ActivateOnPress))
            .remove::<InteractionDisabled>()
            .observe(on_game_screen_activate);
    }
    if let Some(leave) = leave {
        commands
            .entity(leave)
            .insert((GameScreenNavAction::StrategicMap, ActivateOnPress))
            .remove::<InteractionDisabled>()
            .observe(on_game_screen_activate);
    }
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
struct TurnAlertNotice(TurnAlert);

#[derive(Resource)]
struct TurnAlertQueue(VecDeque<TurnAlert>);

#[derive(Component)]
struct TurnSummaryNotice(String);

fn spawn_turn_alerts_if_pending(
    mut commands: Commands,
    queue: Option<Res<TurnAlertQueue>>,
    existing: Query<(), With<TurnAlertNotice>>,
) {
    let Some(alert) = queue.as_deref().and_then(|queue| queue.0.front()).copied() else {
        return;
    };
    if !existing.is_empty() {
        return;
    }
    spawn_linger_dialog(
        &mut commands,
        TurnAlertNotice(alert),
        AppState::StrategicMap,
    );
}

fn bind_turn_alert_notice(
    mut commands: Commands,
    notice: Option<Single<(&TurnAlertNotice, &generated::Linger2020), Added<TurnAlertNotice>>>,
    mut assets: RetailUiAssets,
) {
    let Some(root) = notice else {
        return;
    };
    let (notice, ui) = root.into_inner();
    let linger = bind_linger_dialog(&mut commands, *ui);
    let (title_index, body_index) = match notice.0 {
        TurnAlert::LandCapitolThreatened => (0x28, 0x29),
        TurnAlert::NavalCapitolThreatened => (0x2a, 0x2b),
        TurnAlert::Treasury { prompt_code } => (prompt_code - 1, prompt_code),
        TurnAlert::CommodityShortage => (0x46, 0x47),
        TurnAlert::TransportShortage => (0x22, 0x23),
        TurnAlert::Starvation => (0x20, 0x21),
    };
    let title = assets
        .string(0x2753, title_index)
        .expect("retail turn-alert title must load");
    let body = assets
        .string(0x2753, body_index)
        .expect("retail turn-alert body must load");
    linger.set_title(&mut commands, &mut assets, title);
    linger.set_body(&mut commands, &mut assets, body);
    commands
        .entity(linger.okay)
        .insert(ActivateOnPress)
        .remove::<InteractionDisabled>()
        .observe(on_turn_alert_dismiss);
    commands.entity(linger.cancel).insert(Visibility::Hidden);
}

fn bind_turn_summary_notice(
    mut commands: Commands,
    notice: Option<Single<(&TurnSummaryNotice, &generated::Linger2020), Added<TurnSummaryNotice>>>,
    mut assets: RetailUiAssets,
) {
    let Some(notice) = notice else {
        return;
    };
    let (notice, ui) = notice.into_inner();
    let linger = bind_linger_dialog(&mut commands, *ui);
    linger.set_title(&mut commands, &mut assets, "Imperialism");
    linger.set_body(&mut commands, &mut assets, &notice.0);
    commands
        .entity(linger.okay)
        .insert(ActivateOnPress)
        .remove::<InteractionDisabled>();
    commands.entity(linger.cancel).insert(Visibility::Hidden);
}

fn on_turn_alert_dismiss(_activate: On<Activate>, mut queue: ResMut<TurnAlertQueue>) {
    queue
        .0
        .pop_front()
        .expect("turn-alert dismissal requires a pending alert");
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
