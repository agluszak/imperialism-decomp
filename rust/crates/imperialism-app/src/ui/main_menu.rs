use crate::AppState;
use crate::ui::generated;
use crate::ui::hover_help::{
    HoverHelpBarStyle, bind_hover_help_bar, bind_hover_help_texts, get_string,
};
use crate::ui::retail::{RetailTag, RetailUiAssets, find_descendant};
use bevy::app::AppExit;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::Activate;
use imperialism_formats::fourcc;

#[derive(Component)]
struct MainMenuRoot;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainMenuAction {
    RandomGame,
    Quit,
}

pub(crate) struct MainMenuPlugin;

impl Plugin for MainMenuPlugin {
    fn build(&self, app: &mut App) {
        register_main_menu_logic(app);
        app.add_systems(
            OnEnter(AppState::MainMenu),
            (
                enter_main_menu,
                bind_main_menu_actions,
                bind_main_menu_hover_help,
            )
                .chain(),
        );
    }
}

pub(crate) fn register_main_menu_logic(app: &mut App) {
    app.add_observer(on_main_menu_activate);
}

fn enter_main_menu(mut commands: Commands) {
    let root = commands.spawn_scene(generated::startup_1500()).id();
    commands
        .entity(root)
        .insert((MainMenuRoot, DespawnOnExit(AppState::MainMenu)));
}

fn bind_main_menu_actions(
    mut commands: Commands,
    root: Single<Entity, Added<MainMenuRoot>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
) {
    for (tag, action) in [
        (fourcc!("rand"), MainMenuAction::RandomGame),
        (fourcc!("quit"), MainMenuAction::Quit),
    ] {
        let entity = find_descendant(*root, tag, &children, &tags);
        commands
            .entity(entity)
            .insert(action)
            .remove::<InteractionDisabled>();
    }
}

fn bind_main_menu_hover_help(
    mut commands: Commands,
    root: Single<Entity, Added<MainMenuRoot>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
) {
    let bar = find_descendant(*root, fourcc!("curs"), &children, &tags);
    bind_hover_help_bar(
        &mut commands,
        &mut assets,
        bar,
        HoverHelpBarStyle::MAIN_MENU,
    );
    bind_hover_help_texts(
        &mut commands,
        *root,
        &children,
        &tags,
        [
            (fourcc!("main"), String::new()),
            (fourcc!("rand"), get_string(&assets, 0x2737, 0)),
            (fourcc!("load"), get_string(&assets, 0x2737, 1)),
            (fourcc!("mult"), get_string(&assets, 0x2737, 2)),
            (fourcc!("high"), get_string(&assets, 0x2737, 3)),
            (fourcc!("scen"), get_string(&assets, 0x2737, 4)),
            (fourcc!("quit"), get_string(&assets, 0x2737, 9)),
            (fourcc!("pref"), get_string(&assets, 0x2743, 8)),
        ],
    );
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
    use bevy::ecs::message::Messages;

    fn app() -> App {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_message::<AppExit>()
            .add_plugins(bevy::state::app::StatesPlugin)
            .init_state::<AppState>();
        register_main_menu_logic(&mut app);
        app.add_systems(
            OnEnter(AppState::MainMenu),
            (spawn_test_main_menu, bind_main_menu_actions).chain(),
        );
        app.update();
        app
    }

    fn spawn_test_main_menu(mut commands: Commands) {
        let root = commands.spawn((MainMenuRoot, Node::default())).id();
        commands.spawn((RetailTag(fourcc!("rand")), Node::default(), ChildOf(root)));
        commands.spawn((RetailTag(fourcc!("quit")), Node::default(), ChildOf(root)));
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
