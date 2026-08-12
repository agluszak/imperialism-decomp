use crate::AppState;
use crate::ui::catalog::{SpawnedView, UiAssetResources, UiCatalogResource, spawn_view};
use crate::ui::random_setup::GameSession;
use crate::ui::strategic_map::{bind_strategic_base_terrain, sync_strategic_base_terrain};
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::Activate;
use imperialism_core::{FlowStop, GameScreen, MajorNationId};
use imperialism_formats::{FourCc, ScopedViewId, TRADE, fourcc};

pub(crate) fn strategic_map_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "MapView.rsrc".to_owned(),
        resource_id: 2013,
    }
}

pub(crate) fn newspaper_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "FlagView.rsrc".to_owned(),
        resource_id: 8451,
    }
}

pub(crate) fn deal_book_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "FlagView.rsrc".to_owned(),
        resource_id: 8800,
    }
}

pub(crate) fn trade_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "Trade.rsrc".to_owned(),
        resource_id: 2009,
    }
}

pub(crate) fn city_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "Citymain.rsrc".to_owned(),
        resource_id: 2011,
    }
}

pub(crate) fn transport_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "Transport.rsrc".to_owned(),
        resource_id: 2014,
    }
}

pub(crate) fn diplomacy_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "Diplo.rsrc".to_owned(),
        resource_id: 2008,
    }
}

fn view_id_for_state(state: AppState) -> Option<ScopedViewId> {
    match state {
        AppState::StrategicMap => Some(strategic_map_view_id()),
        AppState::Trade => Some(trade_view_id()),
        AppState::City => Some(city_view_id()),
        AppState::Transport => Some(transport_view_id()),
        AppState::Diplomacy => Some(diplomacy_view_id()),
        AppState::MainMenu
        | AppState::RandomSetup
        | AppState::CitySite
        | AppState::DealBook
        | AppState::Newspaper => None,
    }
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum GameScreenNavAction {
    StrategicMap,
    Trade,
    Transport,
    City,
    Diplomacy,
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum TurnFlowAction {
    FinishPlayerOrders,
    DismissBlockingScreen,
}

pub(crate) struct GameShellPlugin;

impl Plugin for GameShellPlugin {
    fn build(&self, app: &mut App) {
        app.add_observer(on_game_screen_activate)
            .add_observer(
                on_turn_flow_activate.run_if(
                    in_state(AppState::StrategicMap)
                        .or_else(in_state(AppState::DealBook))
                        .or_else(in_state(AppState::Newspaper)),
                ),
            )
            .add_systems(
                OnEnter(AppState::StrategicMap),
                (enter_strategic_map_view, enter_game_screen).chain(),
            )
            .add_systems(OnEnter(AppState::DealBook), enter_turn_flow_screen)
            .add_systems(OnEnter(AppState::Newspaper), enter_turn_flow_screen)
            .add_systems(
                Update,
                sync_strategic_base_terrain.run_if(in_state(AppState::StrategicMap)),
            );
    }
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

#[derive(Component, Clone, Debug, Eq, PartialEq)]
pub(crate) struct GameScreenRoot(pub(crate) ScopedViewId);

fn enter_game_screen(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut assets: UiAssetResources,
    state: Res<State<AppState>>,
    session: Res<GameSession>,
) {
    let current = *state.get();
    let Some(view_id) = view_id_for_state(current) else {
        return;
    };
    let view = catalog.required_view(&view_id);
    let spawned = spawn_view(&mut commands, catalog.catalog(), view, &mut assets);
    bind_game_screen_nav(&mut commands, &catalog, &spawned);
    if current == AppState::StrategicMap {
        let end = spawned.unique(fourcc!("DONE"));
        commands
            .entity(end)
            .insert(TurnFlowAction::FinishPlayerOrders)
            .remove::<InteractionDisabled>();
        bind_strategic_base_terrain(&mut commands, &spawned, &mut assets, &session.0);
        project_date_and_treasury(&mut commands, &mut assets, &spawned, &session);
    }
    commands
        .entity(spawned.root)
        .insert((GameScreenRoot(view_id), DespawnOnExit(current)));
}

fn enter_turn_flow_screen(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut assets: UiAssetResources,
    state: Res<State<AppState>>,
    session: Res<GameSession>,
) {
    let current = *state.get();
    let view_id = match current {
        AppState::DealBook => deal_book_view_id(),
        AppState::Newspaper => newspaper_view_id(),
        _ => return,
    };
    let view = catalog.required_view(&view_id);
    let spawned = spawn_view(&mut commands, catalog.catalog(), view, &mut assets);
    let end = spawned.unique(fourcc!("end "));
    commands
        .entity(end)
        .insert(TurnFlowAction::DismissBlockingScreen)
        .remove::<InteractionDisabled>();
    disable_control(&mut commands, &spawned, fourcc!("quer"));

    match current {
        AppState::DealBook => {
            disable_control(&mut commands, &spawned, fourcc!("tabs"));
            disable_control(&mut commands, &spawned, fourcc!("mark"));
            project_deal_book_chrome(&mut commands, &mut assets, &spawned, &session);
        }
        AppState::Newspaper => {
            project_newspaper_chrome(&mut commands, &mut assets, &spawned, &session)
        }
        _ => unreachable!(),
    }

    commands
        .entity(spawned.root)
        .insert((GameScreenRoot(view_id), DespawnOnExit(current)));
}

fn project_deal_book_chrome(
    commands: &mut Commands,
    assets: &mut UiAssetResources,
    spawned: &SpawnedView,
    session: &GameSession,
) {
    // Retail starts the deal summary on its sold/bought page.
    let sold = assets
        .string(0x2740, 0x19)
        .expect("retail deal-book sold title must load");
    let bought = assets
        .string(0x2740, 0x1a)
        .expect("retail deal-book bought title must load");
    set_control_text(commands, spawned, fourcc!("titL"), sold);
    set_control_text(commands, spawned, fourcc!("rtil"), bought);
    project_date_and_treasury(commands, assets, spawned, session);
}

fn project_date_and_treasury(
    commands: &mut Commands,
    assets: &mut UiAssetResources,
    spawned: &SpawnedView,
    session: &GameSession,
) {
    let state = &session.0;
    set_control_text(
        commands,
        spawned,
        fourcc!("seas"),
        format_retail_date(assets, state.turn().economic_turn),
    );
    let treasury = MajorNationId::from_nation(state.turn().active_nation)
        .map(|nation| format_currency(state.nations().major(nation).common.treasury))
        .unwrap_or_default();
    set_control_text(commands, spawned, fourcc!("trea"), treasury);
}

fn project_newspaper_chrome(
    commands: &mut Commands,
    assets: &mut UiAssetResources,
    spawned: &SpawnedView,
    session: &GameSession,
) {
    let date = format_retail_date(assets, session.0.turn().economic_turn);
    set_control_text(commands, spawned, fourcc!("date"), date);
    // The catalog carries a false date placeholder here. The quarter-specific
    // newspaper metric is not authoritative state yet, so do not invent it.
    set_control_text(commands, spawned, fourcc!("spec"), String::new());
}

fn format_retail_date(assets: &mut UiAssetResources, economic_turn: i32) -> String {
    let season = assets
        .string(10_000, (economic_turn % 4) as i16)
        .expect("retail season name must load");
    format!("{season}, {}", 1815 + economic_turn / 4)
}

fn format_currency(value: i32) -> String {
    let negative = value < 0;
    let digits = i64::from(value).abs().to_string();
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index != 0 && (digits.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(digit);
    }
    if negative {
        format!("-${grouped}")
    } else {
        format!("${grouped}")
    }
}

fn set_control_text(commands: &mut Commands, spawned: &SpawnedView, tag: FourCc, value: String) {
    commands
        .entity(spawned.unique(tag))
        .insert(Text::new(value));
}

pub(crate) fn bind_game_screen_nav(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
) {
    let toolbar = if spawned.view_id == strategic_map_view_id() {
        fourcc!("tool")
    } else {
        fourcc!("topB")
    };
    let trade = spawned.under(catalog, toolbar, TRADE);
    let transport = spawned.under(catalog, toolbar, fourcc!("tran"));
    let city = spawned.under(catalog, toolbar, fourcc!("city"));
    let diplomacy = spawned.under(catalog, toolbar, fourcc!("dipl"));
    for (entity, action) in [
        (trade, GameScreenNavAction::Trade),
        (transport, GameScreenNavAction::Transport),
        (city, GameScreenNavAction::City),
        (diplomacy, GameScreenNavAction::Diplomacy),
    ] {
        commands.entity(entity).insert(action);
    }
    if spawned.view_id != strategic_map_view_id() {
        let toolbar = if spawned.view_id == diplomacy_view_id() {
            fourcc!("too3")
        } else {
            fourcc!("tool")
        };
        let leave = spawned.under(catalog, toolbar, fourcc!("end "));
        commands
            .entity(leave)
            .insert(GameScreenNavAction::StrategicMap)
            .remove::<InteractionDisabled>();
    }
}

/// Marks a catalog-tagged control [`InteractionDisabled`] because its retail behavior
/// is not implemented yet.
pub(crate) fn disable_control(commands: &mut Commands, spawned: &SpawnedView, tag: FourCc) {
    commands
        .entity(spawned.unique(tag))
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

fn on_turn_flow_activate(
    activate: On<Activate>,
    actions: Query<&TurnFlowAction>,
    mut session: ResMut<GameSession>,
    state: Res<State<AppState>>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let stop = match *action {
        TurnFlowAction::FinishPlayerOrders => session.0.finish_player_orders(),
        TurnFlowAction::DismissBlockingScreen => session.0.dismiss_blocking_screen(),
    };
    let destination = match stop {
        FlowStop::PlayerOrders => Some(AppState::StrategicMap),
        FlowStop::Show {
            screen: GameScreen::DealBook,
        } => Some(AppState::DealBook),
        FlowStop::Show {
            screen: GameScreen::Newspaper,
        } => Some(AppState::Newspaper),
        FlowStop::Unimplemented { .. } => None,
    };
    if let Some(destination) = destination.filter(|destination| *destination != *state.get()) {
        next_state.set(destination);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::catalog::spawn_view_nodes;
    use bevy::ui_widgets::Button as UiButton;
    use imperialism_formats::{
        LegacyGameStateContext, LegacySaveV62, UiBehavior, UiCatalog, fourcc,
    };
    use std::collections::HashSet;

    const CATALOG_JSON: &str = include_str!("../../../imperialism-formats/assets/ui_catalog.json");
    const BEGINNING_OF_GAME: &[u8] =
        include_bytes!("../../../../../fixtures/retail/beginning_of_game.imp");

    fn catalog() -> UiCatalog {
        serde_json::from_str(CATALOG_JSON).unwrap()
    }

    fn register_structure_screens(app: &mut App) {
        app.add_observer(on_game_screen_activate)
            .add_observer(on_turn_flow_activate);
        for state in [
            AppState::StrategicMap,
            AppState::Trade,
            AppState::City,
            AppState::Transport,
            AppState::Diplomacy,
        ] {
            app.add_systems(OnEnter(state), enter_game_screen_structure_only);
        }
    }

    #[derive(Resource)]
    struct TestSpawned(SpawnedView);

    fn enter_game_screen_structure_only(
        mut commands: Commands,
        catalog: Res<UiCatalogResource>,
        state: Res<State<AppState>>,
    ) {
        let current = *state.get();
        let Some(view_id) = view_id_for_state(current) else {
            return;
        };
        let view = catalog.required_view(&view_id);
        let spawned = spawn_view_nodes(&mut commands, catalog.catalog().logical_resolution, view);
        bind_game_screen_nav(&mut commands, &catalog, &spawned);
        commands.insert_resource(TestSpawned(spawned.clone()));
        commands
            .entity(spawned.root)
            .insert((GameScreenRoot(view_id), DespawnOnExit(current)));
        if current == AppState::StrategicMap {
            let end = spawned.unique(fourcc!("DONE"));
            commands
                .entity(end)
                .insert(TurnFlowAction::FinishPlayerOrders)
                .remove::<InteractionDisabled>();
        }
    }

    fn app_at(state: AppState) -> App {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .insert_resource(UiCatalogResource::new(catalog()))
            .insert_resource(fixture_session())
            .add_plugins(bevy::state::app::StatesPlugin)
            .init_state::<AppState>();
        register_structure_screens(&mut app);
        app.world_mut()
            .resource_mut::<NextState<AppState>>()
            .set(state);
        app.update();
        app.update();
        app
    }

    fn fixture_session() -> GameSession {
        let save = LegacySaveV62::parse(BEGINNING_OF_GAME);
        let state = save.game_state(LegacyGameStateContext {
            crt_rand_state: 1,
            map_generation_lcg: 0,
            zone_status_lcg: 3_916_827_792,
            selected_nation: imperialism_core::NationId::new(6),
        });
        GameSession(state)
    }

    fn activate_turn_flow(app: &mut App, action: TurnFlowAction) {
        let entity = app.world_mut().spawn(action).id();
        app.world_mut().commands().trigger(Activate { entity });
        app.world_mut().flush();
        app.update();
        app.update();
    }

    fn current_roots(app: &mut App) -> HashSet<ScopedViewId> {
        let world = app.world_mut();
        world
            .query::<&GameScreenRoot>()
            .iter(world)
            .map(|root| root.0.clone())
            .collect()
    }

    fn nav_entity(app: &mut App, action: GameScreenNavAction) -> Entity {
        app.world_mut()
            .query_filtered::<Entity, With<GameScreenNavAction>>()
            .iter(app.world())
            .find(|entity| app.world().get::<GameScreenNavAction>(*entity) == Some(&action))
            .unwrap_or_else(|| panic!("missing nav action {action:?}"))
    }

    fn activate_nav(app: &mut App, action: GameScreenNavAction) {
        let entity = nav_entity(app, action);
        app.world_mut().commands().trigger(Activate { entity });
        app.world_mut().flush();
        app.update();
        app.update();
    }

    #[test]
    fn strategic_map_done_binds_end_turn() {
        let app = app_at(AppState::StrategicMap);
        let spawned = app.world().resource::<TestSpawned>().0.clone();
        let end = spawned.unique(fourcc!("DONE"));
        assert!(app.world().get::<InteractionDisabled>(end).is_none());
        assert!(app.world().get::<UiButton>(end).is_some());
        assert_eq!(
            app.world().get::<TurnFlowAction>(end),
            Some(&TurnFlowAction::FinishPlayerOrders)
        );
    }

    #[test]
    fn strategic_map_entry_centers_the_loaded_view_on_the_first_idle_civilian() {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(bevy::state::app::StatesPlugin)
            .init_state::<AppState>()
            .insert_resource(fixture_session())
            .add_systems(OnEnter(AppState::StrategicMap), enter_strategic_map_view);
        assert_eq!(
            app.world().resource::<GameSession>().0.map.view_origin,
            imperialism_core::TileId::new(1)
        );

        app.world_mut()
            .resource_mut::<NextState<AppState>>()
            .set(AppState::StrategicMap);
        app.update();
        app.update();

        assert_eq!(
            app.world().resource::<GameSession>().0.map.view_origin,
            imperialism_core::TileId::new(1358)
        );
    }

    #[test]
    fn economic_leave_hotspot_returns_to_map() {
        for state in [
            AppState::Trade,
            AppState::City,
            AppState::Transport,
            AppState::Diplomacy,
        ] {
            let mut app = app_at(state);
            let spawned = app.world().resource::<TestSpawned>().0.clone();
            let leave = spawned.unique(fourcc!("end "));
            assert!(
                app.world().get::<InteractionDisabled>(leave).is_none(),
                "{state:?}"
            );
            assert_eq!(
                app.world().get::<GameScreenNavAction>(leave),
                Some(&GameScreenNavAction::StrategicMap),
                "{state:?}"
            );
            activate_nav(&mut app, GameScreenNavAction::StrategicMap);
            assert_eq!(
                app.world().resource::<State<AppState>>().get(),
                &AppState::StrategicMap
            );
            assert_eq!(
                current_roots(&mut app),
                HashSet::from([strategic_map_view_id()])
            );
        }
    }

    #[test]
    fn map_toolbar_opens_trade_city_transport_and_diplomacy() {
        let mut app = app_at(AppState::StrategicMap);
        activate_nav(&mut app, GameScreenNavAction::Trade);
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::Trade
        );
        assert_eq!(current_roots(&mut app), HashSet::from([trade_view_id()]));

        activate_nav(&mut app, GameScreenNavAction::City);
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::City
        );
        assert_eq!(current_roots(&mut app), HashSet::from([city_view_id()]));

        activate_nav(&mut app, GameScreenNavAction::Transport);
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::Transport
        );
        assert_eq!(
            current_roots(&mut app),
            HashSet::from([transport_view_id()])
        );

        activate_nav(&mut app, GameScreenNavAction::Diplomacy);
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::Diplomacy
        );
        assert_eq!(
            current_roots(&mut app),
            HashSet::from([diplomacy_view_id()])
        );
    }

    #[test]
    fn end_turn_closes_retail_gates_and_returns_to_player_orders() {
        let mut app = app_at(AppState::StrategicMap);

        activate_turn_flow(&mut app, TurnFlowAction::FinishPlayerOrders);
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::DealBook
        );

        activate_turn_flow(&mut app, TurnFlowAction::DismissBlockingScreen);
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::Newspaper
        );

        activate_turn_flow(&mut app, TurnFlowAction::DismissBlockingScreen);
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::StrategicMap
        );
        let session = app.world().resource::<GameSession>();
        assert_eq!(session.0.turn().economic_turn, 2);
        assert_eq!(
            session.0.turn().phase(),
            imperialism_core::PhaseCode::STRATEGIC_MAP
        );
    }

    #[test]
    fn diplomacy_trade_radio_does_not_steal_toolbar_navigation() {
        let mut app = app_at(AppState::Diplomacy);
        let toolbar_trade = nav_entity(&mut app, GameScreenNavAction::Trade);
        let spawned = app.world().resource::<TestSpawned>().0.clone();
        let radio_trad = {
            let catalog = app.world().resource::<UiCatalogResource>();
            let view = catalog.required_view(&diplomacy_view_id());
            view.nodes
                .iter()
                .find_map(|node| {
                    if node.tag != fourcc!("trad") || node.behavior != UiBehavior::RadioButton {
                        return None;
                    }
                    Some(spawned.nodes[&node.id])
                })
                .expect("diplomacy has a non-toolbar trad control")
        };
        assert_ne!(radio_trad, toolbar_trade);
        app.world_mut()
            .commands()
            .trigger(Activate { entity: radio_trad });
        app.world_mut().flush();
        app.update();
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::Diplomacy
        );
        activate_nav(&mut app, GameScreenNavAction::Trade);
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::Trade
        );
    }
}
