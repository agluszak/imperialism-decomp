use crate::AppState;
use crate::ui::catalog::{SpawnedView, UiCatalogResource, spawn_view};
use bevy::app::AppExit;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, Button as UiButton};
use imperialism_formats::{ScopedViewId, UiView as CatalogView};

const STARTUP_RESOURCE_FILE: &str = "Startup.rsrc";
const MAIN_MENU_RESOURCE_ID: i16 = 1500;

pub(crate) fn main_menu_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: STARTUP_RESOURCE_FILE.to_owned(),
        resource_id: MAIN_MENU_RESOURCE_ID,
    }
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainMenuAction {
    RandomGame,
    Quit,
}

pub(crate) struct MainMenuPlugin;

impl Plugin for MainMenuPlugin {
    fn build(&self, app: &mut App) {
        register_main_menu_logic(app);
        app.add_systems(OnEnter(AppState::MainMenu), enter_main_menu);
    }
}

pub(crate) fn register_main_menu_logic(app: &mut App) {
    app.add_observer(on_main_menu_activate);
}

fn enter_main_menu(world: &mut World) {
    let view_id = main_menu_view_id();
    let Some(view) = world
        .resource::<UiCatalogResource>()
        .catalog()
        .views
        .iter()
        .find(|view| view.id == view_id)
        .cloned()
    else {
        return;
    };
    let spawned = spawn_view(world, &view);
    bind_main_menu_actions(world, &view, &spawned);
    world
        .entity_mut(spawned.root)
        .insert(DespawnOnExit(AppState::MainMenu));
}

pub(crate) fn bind_main_menu_actions(world: &mut World, view: &CatalogView, spawned: &SpawnedView) {
    for node in &view.nodes {
        if !node.interactive {
            continue;
        }
        let entity = spawned.nodes[&node.id];
        match node.tag.0.as_str() {
            "rand" => {
                world
                    .entity_mut(entity)
                    .insert((UiButton, MainMenuAction::RandomGame))
                    .remove::<InteractionDisabled>();
            }
            "quit" => {
                world
                    .entity_mut(entity)
                    .insert((UiButton, MainMenuAction::Quit))
                    .remove::<InteractionDisabled>();
            }
            _ => {
                // Retain visible but disabled Specialized menu choices.
                world
                    .entity_mut(entity)
                    .insert((UiButton, InteractionDisabled));
            }
        }
    }
}

fn on_main_menu_activate(
    activate: On<Activate>,
    actions: Query<&MainMenuAction>,
    mut next_state: ResMut<NextState<AppState>>,
    mut exit: MessageWriter<AppExit>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    match *action {
        MainMenuAction::RandomGame => next_state.set(AppState::RandomSetup),
        MainMenuAction::Quit => {
            exit.write(AppExit::Success);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::catalog::{UiCatalogPlugin, spawn_view_nodes};
    use bevy::ecs::message::Messages;
    use imperialism_formats::UiCatalog;

    const CATALOG_JSON: &str = include_str!("../../../imperialism-formats/assets/ui_catalog.json");

    #[derive(Resource)]
    struct TestSpawned(SpawnedView);

    fn app() -> App {
        let catalog = serde_json::from_str::<UiCatalog>(CATALOG_JSON).unwrap();
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_message::<AppExit>()
            .insert_resource(UiCatalogResource::new(catalog))
            .add_plugins(bevy::state::app::StatesPlugin)
            .init_state::<AppState>()
            .add_plugins(UiCatalogPlugin);
        register_main_menu_logic(&mut app);
        app.add_systems(OnEnter(AppState::MainMenu), enter_main_menu_structure_only);
        app.update();
        app
    }

    fn enter_main_menu_structure_only(world: &mut World) {
        let view_id = main_menu_view_id();
        let (logical_resolution, view) = {
            let catalog = world.resource::<UiCatalogResource>().catalog();
            let view = catalog
                .views
                .iter()
                .find(|view| view.id == view_id)
                .cloned()
                .unwrap();
            (catalog.logical_resolution, view)
        };
        let spawned = spawn_view_nodes(world, logical_resolution, &view);
        bind_main_menu_actions(world, &view, &spawned);
        world
            .entity_mut(spawned.root)
            .insert(DespawnOnExit(AppState::MainMenu));
        world.insert_resource(TestSpawned(spawned));
    }

    #[test]
    fn main_menu_enables_only_random_and_quit_without_hiding_other_choices() {
        let app = app();
        let catalog = app
            .world()
            .resource::<UiCatalogResource>()
            .catalog()
            .clone();
        let view = catalog
            .views
            .iter()
            .find(|view| view.id == main_menu_view_id())
            .unwrap();
        let spawned = app.world().resource::<TestSpawned>().0.clone();
        let world = app.world();
        let mut by_tag = std::collections::HashMap::new();
        for node in &view.nodes {
            if !node.interactive {
                continue;
            }
            let entity = spawned.nodes[&node.id];
            by_tag.insert(
                node.tag.0.clone(),
                (
                    world.get::<InteractionDisabled>(entity).is_some(),
                    world.get::<MainMenuAction>(entity).copied(),
                ),
            );
        }
        assert_eq!(by_tag["rand"], (false, Some(MainMenuAction::RandomGame)));
        assert_eq!(by_tag["quit"], (false, Some(MainMenuAction::Quit)));
        for tag in ["load", "mult", "high", "scen", "pref"] {
            assert_eq!(by_tag[tag], (true, None));
        }
    }

    #[test]
    fn random_game_and_quit_use_typed_actions() {
        let mut app = app();
        let random = app
            .world_mut()
            .query_filtered::<Entity, With<MainMenuAction>>()
            .iter(app.world())
            .find(|entity| {
                app.world().get::<MainMenuAction>(*entity) == Some(&MainMenuAction::RandomGame)
            })
            .unwrap();
        app.world_mut()
            .commands()
            .trigger(Activate { entity: random });
        app.world_mut().flush();
        app.update();
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::RandomSetup
        );

        app.world_mut()
            .resource_mut::<NextState<AppState>>()
            .set(AppState::MainMenu);
        app.update();

        let quit = app
            .world_mut()
            .query_filtered::<Entity, With<MainMenuAction>>()
            .iter(app.world())
            .find(|entity| {
                app.world().get::<MainMenuAction>(*entity) == Some(&MainMenuAction::Quit)
            })
            .unwrap();
        app.world_mut()
            .commands()
            .trigger(Activate { entity: quit });
        app.world_mut().flush();
        app.update();
        let exits = app
            .world_mut()
            .resource_mut::<Messages<AppExit>>()
            .drain()
            .collect::<Vec<_>>();
        assert_eq!(exits, vec![AppExit::Success]);
    }
}
