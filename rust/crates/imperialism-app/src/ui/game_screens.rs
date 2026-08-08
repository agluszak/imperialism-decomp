use crate::AppState;
use crate::ui::catalog::{SpawnedView, UiAssetResources, UiCatalogResource, spawn_view};
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::Activate;
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

/// Retail's persistent newspaper/flag chrome. It is spawned alongside the strategic
/// map only: Trade, City, Transport, and Diplomacy each embed their own toolbar
/// (including their own `end ` control) directly in their own view.
pub(crate) fn flag_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "FlagView.rsrc".to_owned(),
        resource_id: 8451,
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
        AppState::MainMenu | AppState::RandomSetup | AppState::CitySite => None,
    }
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum GameScreenNavAction {
    Trade,
    Transport,
    City,
    Diplomacy,
}

pub(crate) struct GameScreensPlugin;

impl Plugin for GameScreensPlugin {
    fn build(&self, app: &mut App) {
        app.add_observer(on_game_screen_activate);
        for state in [
            AppState::StrategicMap,
            AppState::Trade,
            AppState::City,
            AppState::Transport,
            AppState::Diplomacy,
        ] {
            app.add_systems(OnEnter(state), enter_game_screen);
        }
    }
}

#[derive(Component, Clone, Debug, Eq, PartialEq)]
struct GameScreenRoot(ScopedViewId);

fn enter_game_screen(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut assets: UiAssetResources,
    state: Res<State<AppState>>,
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
    commands
        .entity(spawned.root)
        .insert((GameScreenRoot(view_id), DespawnOnExit(current)));

    if current == AppState::StrategicMap {
        spawn_flag_view_chrome(&mut commands, &catalog, &mut assets, current);
    }
}

/// Spawns retail's persistent newspaper/flag chrome alongside the strategic map.
fn spawn_flag_view_chrome(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    assets: &mut UiAssetResources,
    current: AppState,
) {
    let view_id = flag_view_id();
    let view = catalog
        .view(&view_id)
        .expect("validated flag-view catalog view");
    let spawned = spawn_view(commands, catalog.catalog(), view, assets);
    // `end ` is End Turn and `quer` is the help/query hotspot; neither is
    // implemented yet, so keep both inert rather than leave unbound no-ops.
    disable_control(commands, &spawned, fourcc!("end "));
    disable_control(commands, &spawned, fourcc!("quer"));
    commands
        .entity(spawned.root)
        .insert((GameScreenRoot(view_id), DespawnOnExit(current)));
}

fn bind_game_screen_nav(
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
    // Retail's `end ` hotspot (`kControlTagEnd`) always dispatches End Turn on every
    // screen that hosts it; it is never a leave-to-map control. End Turn is not
    // implemented yet, so keep it disabled rather than bind a fake leave-to-map action.
    disable_control(commands, spawned, fourcc!("end "));
}

/// Marks a catalog-tagged control [`InteractionDisabled`] because its retail behavior
/// is not implemented yet.
fn disable_control(commands: &mut Commands, spawned: &SpawnedView, tag: FourCc) {
    if let Some(entity) = spawned.tag(tag) {
        commands.entity(entity).insert(InteractionDisabled);
    }
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
    state: Res<State<AppState>>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let destination = match *action {
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
    use crate::ui::catalog::{UiCatalogPlugin, spawn_view_nodes};
    use bevy::ui_widgets::Button as UiButton;
    use imperialism_formats::{UiBehavior, UiCatalog, fourcc};
    use std::collections::HashSet;

    const CATALOG_JSON: &str = include_str!("../../../imperialism-formats/assets/ui_catalog.json");

    fn catalog() -> UiCatalog {
        serde_json::from_str(CATALOG_JSON).unwrap()
    }

    fn register_structure_screens(app: &mut App) {
        app.add_observer(on_game_screen_activate);
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

    #[derive(Resource)]
    struct TestFlagSpawned(SpawnedView);

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
            let flag_view_id = flag_view_id();
            let flag_view = catalog
                .view(&flag_view_id)
                .expect("validated flag-view catalog view");
            let flag_spawned = spawn_view_nodes(
                &mut commands,
                catalog.catalog().logical_resolution,
                flag_view,
            );
            disable_control(&mut commands, &flag_spawned, fourcc!("end "));
            disable_control(&mut commands, &flag_spawned, fourcc!("quer"));
            commands.insert_resource(TestFlagSpawned(flag_spawned.clone()));
            commands
                .entity(flag_spawned.root)
                .insert((GameScreenRoot(flag_view_id), DespawnOnExit(current)));
        }
    }

    fn app_at(state: AppState) -> App {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .insert_resource(UiCatalogResource::new(catalog()).unwrap())
            .add_plugins(bevy::state::app::StatesPlugin)
            .add_plugins(UiCatalogPlugin)
            .init_state::<AppState>();
        register_structure_screens(&mut app);
        app.world_mut()
            .resource_mut::<NextState<AppState>>()
            .set(state);
        app.update();
        app.update();
        app
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
    fn strategic_map_spawns_flag_view_and_combined_map_with_toolbar_navigation() {
        let mut app = app_at(AppState::StrategicMap);
        assert_eq!(
            current_roots(&mut app),
            HashSet::from([strategic_map_view_id(), flag_view_id()])
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
    fn strategic_map_flag_view_disables_end_turn_and_query() {
        let app = app_at(AppState::StrategicMap);
        let catalog = app.world().resource::<UiCatalogResource>();
        let spawned = app.world().resource::<TestFlagSpawned>().0.clone();
        for tag in [fourcc!("end "), fourcc!("quer")] {
            let entity = spawned
                .require_unique(catalog, tag)
                .unwrap_or_else(|error| panic!("flag view missing {tag}: {error}"));
            assert!(
                app.world().get::<InteractionDisabled>(entity).is_some(),
                "{tag} should be disabled"
            );
            assert!(
                app.world().get::<GameScreenNavAction>(entity).is_none(),
                "{tag} must not be bound to a nav action"
            );
        }
    }

    #[test]
    fn end_turn_hotspot_stays_disabled_and_unbound_on_every_screen_that_has_it() {
        for state in [
            AppState::Trade,
            AppState::City,
            AppState::Transport,
            AppState::Diplomacy,
        ] {
            let app = app_at(state);
            let catalog = app.world().resource::<UiCatalogResource>();
            let spawned = app.world().resource::<TestSpawned>().0.clone();
            let end_turn = spawned
                .require_unique(catalog, fourcc!("end "))
                .unwrap_or_else(|error| panic!("{state:?} missing end turn control: {error}"));
            assert!(
                app.world().get::<InteractionDisabled>(end_turn).is_some(),
                "{state:?}"
            );
            assert!(
                app.world().get::<GameScreenNavAction>(end_turn).is_none(),
                "{state:?}"
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
    fn catalog_game_screens_expose_expected_roots() {
        let catalog = catalog();
        for (view_id, min_nodes) in [
            (strategic_map_view_id(), 70usize),
            (flag_view_id(), 8),
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
