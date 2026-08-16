use crate::ui::generated;
use crate::ui::hover_help::{
    HoverHelpBarStyle, bind_hover_help_bar, bind_hover_help_texts, get_string,
};
use crate::ui::load_save::{LoadSaveMode, open_load_save};
use crate::ui::retail::{RetailTree, RetailUiAssets};
use crate::{AppState, ReturnTo};
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
    LoadGame,
    Preferences,
    Quit,
}

pub(crate) struct MainMenuPlugin;

impl Plugin for MainMenuPlugin {
    fn build(&self, app: &mut App) {
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

fn enter_main_menu(mut commands: Commands) {
    let root = commands.spawn_scene(generated::startup_1500()).id();
    commands
        .entity(root)
        .insert((MainMenuRoot, DespawnOnExit(AppState::MainMenu)));
}

fn bind_main_menu_actions(
    mut commands: Commands,
    root: Single<Entity, Added<MainMenuRoot>>,
    tree: RetailTree,
) {
    for (tag, action) in [
        (fourcc!("rand"), MainMenuAction::RandomGame),
        (fourcc!("load"), MainMenuAction::LoadGame),
        (fourcc!("pref"), MainMenuAction::Preferences),
        (fourcc!("quit"), MainMenuAction::Quit),
    ] {
        let entity = tree.find(*root, tag);
        commands
            .entity(entity)
            .insert(action)
            .remove::<InteractionDisabled>()
            .observe(on_main_menu_activate);
    }
}

fn bind_main_menu_hover_help(
    mut commands: Commands,
    root: Single<Entity, Added<MainMenuRoot>>,
    tree: RetailTree,
    mut nodes: Query<&mut Node>,
    mut assets: RetailUiAssets,
) {
    let bar = tree.find(*root, fourcc!("curs"));
    bind_hover_help_bar(
        &mut commands,
        &mut assets,
        bar,
        &mut nodes
            .get_mut(bar)
            .expect("main-menu hover-help bar has Node"),
        HoverHelpBarStyle::MAIN_MENU,
    );
    bind_hover_help_texts(
        &mut commands,
        *root,
        &tree,
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
    mut commands: Commands,
) {
    let action = actions
        .get(activate.entity)
        .expect("main-menu Activate is bound on a MainMenuAction control");
    match *action {
        MainMenuAction::RandomGame => next_state.set(AppState::RandomSetup),
        MainMenuAction::LoadGame => {
            open_load_save(
                &mut commands,
                &mut next_state,
                LoadSaveMode::Load,
                AppState::MainMenu,
            );
        }
        MainMenuAction::Preferences => {
            commands.insert_resource(ReturnTo(AppState::MainMenu));
            next_state.set(AppState::Preferences);
        }
        MainMenuAction::Quit => {
            exit.write(AppExit::Success);
        }
    }
}
