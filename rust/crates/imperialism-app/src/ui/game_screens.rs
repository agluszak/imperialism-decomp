use crate::AppState;
use crate::ui::catalog::{
    SpawnedView, UiCatalogResource, UiPictureResources, find_view, spawn_view,
};
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, Button as UiButton};
use imperialism_formats::{ScopedViewId, UiNodeId, UiView as CatalogView};
use std::collections::HashMap;

const TOOLBAR_PARENT_TAGS: &[&str] = &["tool", "topB"];
/// Retail leave/end controls hang under `tool` or the diplomacy `too3` strip.
const LEAVE_PARENT_TAGS: &[&str] = &["tool", "too2", "too3"];

pub(crate) fn strategic_map_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: "MapView.rsrc".to_owned(),
        resource_id: 2013,
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
    LeaveToMap,
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
    mut pictures: UiPictureResources,
    state: Res<State<AppState>>,
) {
    let current = *state.get();
    let Some(view_id) = view_id_for_state(current) else {
        return;
    };
    let Some(view) = find_view(catalog.catalog(), &view_id) else {
        return;
    };
    let spawned = spawn_view(&mut commands, catalog.catalog(), view, &mut pictures);
    if !bind_game_screen_nav(&mut commands, view, &spawned) {
        commands.entity(spawned.root).despawn();
        return;
    }
    commands
        .entity(spawned.root)
        .insert((GameScreenRoot(view_id), DespawnOnExit(current)));
}

fn bind_game_screen_nav(
    commands: &mut Commands,
    view: &CatalogView,
    spawned: &SpawnedView,
) -> bool {
    let Some(trade) = control_under_parents(view, spawned, "trad", TOOLBAR_PARENT_TAGS) else {
        return false;
    };
    let Some(transport) = control_under_parents(view, spawned, "tran", TOOLBAR_PARENT_TAGS) else {
        return false;
    };
    let Some(city) = control_under_parents(view, spawned, "city", TOOLBAR_PARENT_TAGS) else {
        return false;
    };
    let Some(diplomacy) = control_under_parents(view, spawned, "dipl", TOOLBAR_PARENT_TAGS) else {
        return false;
    };
    for (entity, action) in [
        (trade, GameScreenNavAction::Trade),
        (transport, GameScreenNavAction::Transport),
        (city, GameScreenNavAction::City),
        (diplomacy, GameScreenNavAction::Diplomacy),
    ] {
        commands
            .entity(entity)
            .insert((UiButton, action))
            .remove::<InteractionDisabled>();
    }
    if let Some(leave) = control_under_parents(view, spawned, "end ", LEAVE_PARENT_TAGS) {
        commands
            .entity(leave)
            .insert((UiButton, GameScreenNavAction::LeaveToMap))
            .remove::<InteractionDisabled>();
    }
    true
}

/// Resolve an interactive control under one of the given ancestor tags.
fn control_under_parents(
    view: &CatalogView,
    spawned: &SpawnedView,
    tag: &str,
    parents: &[&str],
) -> Option<Entity> {
    let by_id: HashMap<UiNodeId, &imperialism_formats::UiNode> =
        view.nodes.iter().map(|node| (node.id, node)).collect();
    view.nodes.iter().find_map(|node| {
        if node.tag.0 != tag || !node.interactive {
            return None;
        }
        let mut parent = node.parent;
        while let Some(parent_id) = parent {
            let parent_node = by_id.get(&parent_id)?;
            if parents.contains(&parent_node.tag.0.as_str()) {
                return Some(spawned.nodes[&node.id]);
            }
            parent = parent_node.parent;
        }
        None
    })
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
        GameScreenNavAction::LeaveToMap => AppState::StrategicMap,
    };
    if destination != *state.get() {
        next_state.set(destination);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::catalog::{UiCatalogPlugin, spawn_view_nodes};
    use imperialism_formats::UiCatalog;
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

    fn enter_game_screen_structure_only(
        mut commands: Commands,
        catalog: Res<UiCatalogResource>,
        state: Res<State<AppState>>,
    ) {
        let current = *state.get();
        let Some(view_id) = view_id_for_state(current) else {
            return;
        };
        let catalog = catalog.catalog();
        let view = catalog
            .views
            .iter()
            .find(|view| view.id == view_id)
            .unwrap();
        let spawned = spawn_view_nodes(&mut commands, catalog.logical_resolution, view);
        assert!(
            bind_game_screen_nav(&mut commands, view, &spawned),
            "toolbar nav controls"
        );
        commands.insert_resource(TestSpawned(spawned.clone()));
        commands
            .entity(spawned.root)
            .insert((GameScreenRoot(view_id), DespawnOnExit(current)));
    }

    fn app_at(state: AppState) -> App {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .insert_resource(UiCatalogResource::new(catalog()))
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
        assert!(
            app.world_mut()
                .query_filtered::<Entity, With<GameScreenNavAction>>()
                .iter(app.world())
                .all(|entity| {
                    app.world().get::<GameScreenNavAction>(entity)
                        != Some(&GameScreenNavAction::LeaveToMap)
                })
        );
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
    fn leave_control_returns_to_the_strategic_map() {
        let mut app = app_at(AppState::Trade);
        activate_nav(&mut app, GameScreenNavAction::LeaveToMap);
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::StrategicMap
        );
        assert_eq!(
            current_roots(&mut app),
            HashSet::from([strategic_map_view_id()])
        );
    }

    #[test]
    fn diplomacy_trade_radio_does_not_steal_toolbar_navigation() {
        let mut app = app_at(AppState::Diplomacy);
        let toolbar_trade = nav_entity(&mut app, GameScreenNavAction::Trade);
        let catalog = catalog();
        let view = catalog
            .views
            .iter()
            .find(|view| view.id == diplomacy_view_id())
            .unwrap();
        let spawned = app.world().resource::<TestSpawned>().0.clone();
        let by_id: std::collections::HashMap<_, _> =
            view.nodes.iter().map(|node| (node.id, node)).collect();
        let radio_trad = view
            .nodes
            .iter()
            .find_map(|node| {
                if node.tag.0 != "trad" || !node.interactive {
                    return None;
                }
                let mut parent = node.parent;
                while let Some(parent_id) = parent {
                    let parent_node = by_id.get(&parent_id)?;
                    if TOOLBAR_PARENT_TAGS.contains(&parent_node.tag.0.as_str()) {
                        return None;
                    }
                    parent = parent_node.parent;
                }
                Some(spawned.nodes[&node.id])
            })
            .expect("diplomacy has a non-toolbar trad control");
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
    fn diplomacy_leave_returns_to_the_strategic_map() {
        let mut app = app_at(AppState::Diplomacy);
        activate_nav(&mut app, GameScreenNavAction::LeaveToMap);
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::StrategicMap
        );
        assert_eq!(
            current_roots(&mut app),
            HashSet::from([strategic_map_view_id()])
        );
    }

    #[test]
    fn catalog_game_screens_expose_expected_roots() {
        let catalog = catalog();
        for (view_id, min_nodes) in [
            (strategic_map_view_id(), 70usize),
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
