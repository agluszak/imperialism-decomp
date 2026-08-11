use crate::AppState;
use crate::ui::catalog::{SpawnedView, UiAssetResources, UiCatalogResource, spawn_view};
use bevy::app::AppExit;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::Activate;
use imperialism_formats::{ScopedViewId, UiBehavior};

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

fn enter_main_menu(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut assets: UiAssetResources,
) {
    let view = catalog.required_view(&main_menu_view_id());
    let spawned = spawn_view(&mut commands, catalog.catalog(), view, &mut assets);
    bind_main_menu_actions(&mut commands, &catalog, &spawned);
    commands
        .entity(spawned.root)
        .insert(DespawnOnExit(AppState::MainMenu));
}

pub(crate) fn bind_main_menu_actions(
    commands: &mut Commands,
    catalog: &UiCatalogResource,
    spawned: &SpawnedView,
) {
    let view = catalog.required_view(&spawned.view_id);
    for node in &view.nodes {
        if node.behavior != UiBehavior::Activate {
            continue;
        }
        let entity = spawned.nodes[&node.id];
        match node.tag {
            tag if tag == imperialism_formats::fourcc!("rand") => {
                commands
                    .entity(entity)
                    .insert(MainMenuAction::RandomGame)
                    .remove::<InteractionDisabled>();
            }
            tag if tag == imperialism_formats::fourcc!("quit") => {
                commands
                    .entity(entity)
                    .insert(MainMenuAction::Quit)
                    .remove::<InteractionDisabled>();
            }
            _ => {
                // Retain visible but unavailable Specialized menu choices.
                commands.entity(entity).insert(InteractionDisabled);
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
    use crate::ui::catalog::spawn_view_nodes;
    use bevy::ecs::message::Messages;
    use imperialism_formats::UiCatalog;

    const CATALOG_JSON: &str = include_str!("../../../imperialism-formats/assets/ui_catalog.json");

    fn app() -> App {
        let catalog = serde_json::from_str::<UiCatalog>(CATALOG_JSON).unwrap();
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_message::<AppExit>()
            .insert_resource(UiCatalogResource::new(catalog))
            .add_plugins(bevy::state::app::StatesPlugin)
            .init_state::<AppState>();
        register_main_menu_logic(&mut app);
        app.add_systems(OnEnter(AppState::MainMenu), enter_main_menu_structure_only);
        app.update();
        app
    }

    fn enter_main_menu_structure_only(mut commands: Commands, catalog: Res<UiCatalogResource>) {
        let view_id = main_menu_view_id();
        let view = catalog.required_view(&view_id);
        let spawned = spawn_view_nodes(&mut commands, catalog.catalog().logical_resolution, view);
        bind_main_menu_actions(&mut commands, &catalog, &spawned);
        commands
            .entity(spawned.root)
            .insert(DespawnOnExit(AppState::MainMenu));
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
