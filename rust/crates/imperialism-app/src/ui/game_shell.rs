use crate::AppState;
use crate::ui::catalog::{SpawnedView, UiAssetResources, UiCatalogResource, spawn_view};
use crate::ui::random_setup::GameSession;
use crate::ui::strategic_map::{bind_strategic_base_terrain, sync_strategic_base_terrain};
use bevy::log::warn;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::Activate;
use imperialism_core::{AdvanceTurnOutcome, MajorNationId, TurnYield, UiRequest};
use imperialism_formats::{FourCc, ScopedViewId, TRADE, fourcc};

pub(crate) const TOOLBAR_PARENT_TAGS: &[FourCc] = &[fourcc!("tool"), fourcc!("topB")];
/// Retail leave/end controls hang under `tool` or the diplomacy `too3` strip.
pub(crate) const LEAVE_PARENT_TAGS: &[FourCc] =
    &[fourcc!("tool"), fourcc!("too2"), fourcc!("too3")];

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

pub(crate) fn validate_application_bindings(catalog: &UiCatalogResource) -> Result<(), String> {
    catalog.require_unique_bindings(
        &strategic_map_view_id(),
        &[
            fourcc!("DLOG"),
            fourcc!("DONE"),
            fourcc!("seas"),
            fourcc!("trea"),
            TRADE,
            fourcc!("tran"),
            fourcc!("city"),
            fourcc!("dipl"),
        ],
    )?;
    catalog.require_unique_bindings(
        &newspaper_view_id(),
        &[
            fourcc!("end "),
            fourcc!("quer"),
            fourcc!("date"),
            fourcc!("spec"),
        ],
    )?;
    catalog.require_unique_bindings(
        &deal_book_view_id(),
        &[
            fourcc!("end "),
            fourcc!("quer"),
            fourcc!("tabs"),
            fourcc!("mark"),
            fourcc!("seas"),
            fourcc!("trea"),
            fourcc!("titL"),
            fourcc!("rtil"),
        ],
    )?;
    for view_id in [
        trade_view_id(),
        city_view_id(),
        transport_view_id(),
        diplomacy_view_id(),
    ] {
        catalog.require_unique_bindings(&view_id, &[fourcc!("end ")])?;
    }
    for view_id in [
        strategic_map_view_id(),
        trade_view_id(),
        city_view_id(),
        transport_view_id(),
        diplomacy_view_id(),
    ] {
        for tag in [TRADE, fourcc!("tran"), fourcc!("city"), fourcc!("dipl")] {
            catalog.require_control_under(&view_id, tag, TOOLBAR_PARENT_TAGS)?;
        }
    }
    for view_id in [
        trade_view_id(),
        city_view_id(),
        transport_view_id(),
        diplomacy_view_id(),
    ] {
        catalog.require_control_under(&view_id, fourcc!("end "), LEAVE_PARENT_TAGS)?;
    }
    Ok(())
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
    Resume(UiRequest),
}

pub(crate) struct GameShellPlugin;

impl Plugin for GameShellPlugin {
    fn build(&self, app: &mut App) {
        app.add_observer(on_game_screen_activate)
            .add_observer(on_turn_flow_activate)
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

fn enter_strategic_map_view(mut session: Option<ResMut<GameSession>>) {
    if let Some(session) = session.as_deref_mut() {
        session.0.enter_strategic_map_view();
    }
}

#[derive(Component, Clone, Debug, Eq, PartialEq)]
pub(crate) struct GameScreenRoot(pub(crate) ScopedViewId);

fn enter_game_screen(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut assets: UiAssetResources,
    state: Res<State<AppState>>,
    session: Option<Res<GameSession>>,
) {
    let current = *state.get();
    let Some(view_id) = view_id_for_state(current) else {
        return;
    };
    let view = catalog
        .view(&view_id)
        .expect("validated game-screen catalog view");
    let spawned = spawn_view(&mut commands, catalog.catalog(), view, &mut assets);
    bind_game_screen_nav(&mut commands, &catalog, &spawned);
    if current == AppState::StrategicMap {
        let end = spawned
            .require_unique(fourcc!("DONE"))
            .expect("validated strategic-map end-turn binding");
        commands
            .entity(end)
            .insert(TurnFlowAction::FinishPlayerOrders)
            .remove::<InteractionDisabled>();
        if let Some(session) = session.as_deref() {
            bind_strategic_base_terrain(&mut commands, &spawned, &mut assets, &session.0);
        } else {
            warn!("strategic map opened without an authoritative game session");
        }
        project_date_and_treasury(
            &mut commands,
            &mut assets,
            &spawned,
            session.as_deref(),
            "strategic map",
        );
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
    session: Option<Res<GameSession>>,
) {
    let current = *state.get();
    let view_id = match current {
        AppState::DealBook => deal_book_view_id(),
        AppState::Newspaper => newspaper_view_id(),
        _ => return,
    };
    let view = catalog
        .view(&view_id)
        .expect("validated turn-flow catalog view");
    let spawned = spawn_view(&mut commands, catalog.catalog(), view, &mut assets);
    let end = spawned
        .require_unique(fourcc!("end "))
        .expect("validated turn-flow close binding");
    let gate = match current {
        AppState::DealBook => UiRequest::DealBook,
        AppState::Newspaper => UiRequest::Newspaper,
        _ => unreachable!(),
    };
    commands
        .entity(end)
        .insert(TurnFlowAction::Resume(gate))
        .remove::<InteractionDisabled>();
    disable_control(&mut commands, &spawned, fourcc!("quer"));

    match current {
        AppState::DealBook => {
            disable_control(&mut commands, &spawned, fourcc!("tabs"));
            disable_control(&mut commands, &spawned, fourcc!("mark"));
            project_deal_book_chrome(&mut commands, &mut assets, &spawned, session.as_deref());
        }
        AppState::Newspaper => {
            project_newspaper_chrome(&mut commands, &mut assets, &spawned, session.as_deref())
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
    session: Option<&GameSession>,
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
    project_date_and_treasury(commands, assets, spawned, session, "deal book");
}

fn project_date_and_treasury(
    commands: &mut Commands,
    assets: &mut UiAssetResources,
    spawned: &SpawnedView,
    session: Option<&GameSession>,
    screen: &str,
) {
    let Some(session) = session else {
        warn!("{screen} opened without an authoritative game session");
        set_control_text(commands, spawned, fourcc!("seas"), String::new());
        set_control_text(commands, spawned, fourcc!("trea"), String::new());
        return;
    };
    let state = &session.0;
    set_control_text(
        commands,
        spawned,
        fourcc!("seas"),
        format_retail_date(assets, state.turn().economic_turn),
    );
    let treasury = MajorNationId::from_nation(state.turn().active_nation)
        .map(|nation| format_currency(state.nations().major(nation).common().treasury))
        .unwrap_or_default();
    set_control_text(commands, spawned, fourcc!("trea"), treasury);
}

fn project_newspaper_chrome(
    commands: &mut Commands,
    assets: &mut UiAssetResources,
    spawned: &SpawnedView,
    session: Option<&GameSession>,
) {
    let date = session.map_or_else(String::new, |session| {
        format_retail_date(assets, session.0.turn().economic_turn)
    });
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
    let entity = spawned
        .require_unique(tag)
        .unwrap_or_else(|error| panic!("validated {tag} text binding: {error}"));
    commands.entity(entity).insert(Text::new(value));
}

pub(crate) fn bind_game_screen_nav(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
) {
    let trade = control_under_parents(catalog, spawned, TRADE, TOOLBAR_PARENT_TAGS)
        .expect("validated game-screen trade binding");
    let transport = control_under_parents(catalog, spawned, fourcc!("tran"), TOOLBAR_PARENT_TAGS)
        .expect("validated game-screen transport binding");
    let city = control_under_parents(catalog, spawned, fourcc!("city"), TOOLBAR_PARENT_TAGS)
        .expect("validated game-screen city binding");
    let diplomacy = control_under_parents(catalog, spawned, fourcc!("dipl"), TOOLBAR_PARENT_TAGS)
        .expect("validated game-screen diplomacy binding");
    for (entity, action) in [
        (trade, GameScreenNavAction::Trade),
        (transport, GameScreenNavAction::Transport),
        (city, GameScreenNavAction::City),
        (diplomacy, GameScreenNavAction::Diplomacy),
    ] {
        commands.entity(entity).insert(action);
    }
    if spawned.view_id != strategic_map_view_id() {
        let leave = control_under_parents(catalog, spawned, fourcc!("end "), LEAVE_PARENT_TAGS)
            .expect("validated game-screen return-to-map binding");
        commands
            .entity(leave)
            .insert(GameScreenNavAction::StrategicMap)
            .remove::<InteractionDisabled>();
    }
}

/// Marks a catalog-tagged control [`InteractionDisabled`] because its retail behavior
/// is not implemented yet.
pub(crate) fn disable_control(commands: &mut Commands, spawned: &SpawnedView, tag: FourCc) {
    let entity = spawned
        .require_unique(tag)
        .expect("validated disabled control binding");
    commands.entity(entity).insert(InteractionDisabled);
}

/// Resolve an activate control under one of the given ancestor tags.
fn control_under_parents(
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
    tag: FourCc,
    parents: &[FourCc],
) -> Option<Entity> {
    for &parent in parents {
        if let Ok(entity) = spawned.require_under(catalog, parent, tag) {
            return Some(entity);
        }
    }
    None
}

fn on_game_screen_activate(
    activate: On<Activate>,
    actions: Query<&GameScreenNavAction>,
    session: Option<ResMut<GameSession>>,
    state: Res<State<AppState>>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    if *action == GameScreenNavAction::StrategicMap
        && let Some(mut session) = session
        && let Some(request) = session.0.pending_ui_request()
    {
        match request {
            UiRequest::DiplomacyMap { .. } if *state.get() == AppState::Diplomacy => {
                let outcome = session.0.resume_after_ui(request);
                let _effects = outcome.effects();
                apply_turn_yield_destination(&outcome, &state, &mut next_state);
                return;
            }
            UiRequest::OfferSheet { .. } if *state.get() == AppState::Trade => {
                let outcome = session.0.resume_after_ui(request);
                let _effects = outcome.effects();
                apply_turn_yield_destination(&outcome, &state, &mut next_state);
                return;
            }
            _ => {}
        }
    }
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

fn apply_turn_yield_destination(
    outcome: &AdvanceTurnOutcome,
    state: &State<AppState>,
    next_state: &mut NextState<AppState>,
) {
    let destination = match outcome {
        AdvanceTurnOutcome::Blocked {
            yield_: TurnYield::PlayerOrders,
            ..
        } => Some(AppState::StrategicMap),
        AdvanceTurnOutcome::Blocked {
            yield_: TurnYield::Ui {
                request: UiRequest::DealBook,
            },
            ..
        } => Some(AppState::DealBook),
        AdvanceTurnOutcome::Blocked {
            yield_: TurnYield::Ui {
                request: UiRequest::Newspaper,
            },
            ..
        } => Some(AppState::Newspaper),
        AdvanceTurnOutcome::Blocked {
            yield_: TurnYield::Ui {
                request: UiRequest::DiplomacyMap { .. },
            },
            ..
        } => Some(AppState::Diplomacy),
        AdvanceTurnOutcome::Blocked {
            yield_: TurnYield::Ui {
                request: UiRequest::OfferSheet { .. },
            },
            ..
        } => Some(AppState::Trade),
        _ => None,
    };
    if let Some(destination) = destination.filter(|destination| *destination != *state.get()) {
        next_state.set(destination);
    }
}

fn on_turn_flow_activate(
    activate: On<Activate>,
    actions: Query<&TurnFlowAction>,
    mut session: Option<ResMut<GameSession>>,
    state: Res<State<AppState>>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let session = session
        .as_deref_mut()
        .expect("turn-flow control activated without an authoritative game session");
    let outcome = match *action {
        TurnFlowAction::FinishPlayerOrders => session.0.finish_player_orders(),
        TurnFlowAction::Resume(gate) => session.0.resume_after_ui(gate),
    };
    let _effects = outcome.effects();
    apply_turn_yield_destination(&outcome, &state, &mut next_state);
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
        let view = catalog
            .view(&view_id)
            .expect("validated game-screen catalog view");
        let spawned = spawn_view_nodes(&mut commands, catalog.catalog().logical_resolution, view);
        bind_game_screen_nav(&mut commands, &catalog, &spawned);
        commands.insert_resource(TestSpawned(spawned.clone()));
        commands
            .entity(spawned.root)
            .insert((GameScreenRoot(view_id), DespawnOnExit(current)));
        if current == AppState::StrategicMap {
            let end = spawned.require_unique(fourcc!("DONE")).unwrap();
            commands
                .entity(end)
                .insert(TurnFlowAction::FinishPlayerOrders)
                .remove::<InteractionDisabled>();
        }
    }

    fn app_at(state: AppState) -> App {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .insert_resource(UiCatalogResource::new(catalog()).unwrap())
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
        let save = LegacySaveV62::parse(BEGINNING_OF_GAME).unwrap();
        let state = save
            .game_state(LegacyGameStateContext {
                crt_rand_state: 1,
                map_generation_lcg: 0,
                zone_status_lcg: 3_916_827_792,
                selected_nation: imperialism_core::NationId::new(6),
            })
            .unwrap();
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
    fn strategic_map_spawns_combined_map_with_toolbar_navigation() {
        let mut app = app_at(AppState::StrategicMap);
        assert_eq!(
            current_roots(&mut app),
            HashSet::from([strategic_map_view_id()])
        );
        for action in [
            GameScreenNavAction::Trade,
            GameScreenNavAction::Transport,
            GameScreenNavAction::City,
            GameScreenNavAction::Diplomacy,
        ] {
            let entity = nav_entity(&mut app, action);
            assert!(app.world().get::<UiButton>(entity).is_some());
            assert!(app.world().get::<InteractionDisabled>(entity).is_none());
        }
    }

    #[test]
    fn strategic_map_done_binds_end_turn() {
        let app = app_at(AppState::StrategicMap);
        let spawned = app.world().resource::<TestSpawned>().0.clone();
        let end = spawned.require_unique(fourcc!("DONE")).unwrap();
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
            app.world().resource::<GameSession>().0.world().view_origin(),
            imperialism_core::TileId::new(1)
        );

        app.world_mut()
            .resource_mut::<NextState<AppState>>()
            .set(AppState::StrategicMap);
        app.update();
        app.update();

        assert_eq!(
            app.world().resource::<GameSession>().0.world().view_origin(),
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
            let leave = spawned
                .require_unique(fourcc!("end "))
                .unwrap_or_else(|error| panic!("{state:?} missing leave control: {error}"));
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
        app.insert_resource(fixture_session());

        activate_turn_flow(&mut app, TurnFlowAction::FinishPlayerOrders);
        // First-turn yields may stop at diplomacy-map or offer-sheet before the deal book.
        loop {
            let current = *app.world().resource::<State<AppState>>().get();
            let request = app
                .world()
                .resource::<GameSession>()
                .0
                .pending_ui_request();
            match (current, request) {
                (AppState::DealBook, Some(UiRequest::DealBook)) => break,
                (AppState::Diplomacy, Some(request @ UiRequest::DiplomacyMap { .. }))
                | (AppState::Trade, Some(request @ UiRequest::OfferSheet { .. })) => {
                    activate_turn_flow(&mut app, TurnFlowAction::Resume(request));
                }
                other => panic!("unexpected turn-flow yield state: {other:?}"),
            }
        }

        activate_turn_flow(&mut app, TurnFlowAction::Resume(UiRequest::DealBook));
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::Newspaper
        );

        activate_turn_flow(&mut app, TurnFlowAction::Resume(UiRequest::Newspaper));
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
            let view = catalog.view(&diplomacy_view_id()).unwrap();
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

    #[test]
    fn catalog_game_shell_exposes_expected_roots() {
        let catalog = catalog();
        for (view_id, min_nodes) in [
            (strategic_map_view_id(), 70usize),
            (newspaper_view_id(), 8),
            (deal_book_view_id(), 20),
            (trade_view_id(), 160),
            (city_view_id(), 20),
            (transport_view_id(), 60),
            (diplomacy_view_id(), 60),
        ] {
            let view = catalog
                .views
                .iter()
                .find(|view| view.id == view_id)
                .unwrap_or_else(|| panic!("missing {view_id:?}"));
            assert!(view.nodes.len() >= min_nodes, "{view_id:?}");
            let spawned_ids = view
                .nodes
                .iter()
                .map(|node| node.id)
                .collect::<HashSet<_>>();
            assert_eq!(spawned_ids.len(), view.nodes.len());
        }
    }
}
