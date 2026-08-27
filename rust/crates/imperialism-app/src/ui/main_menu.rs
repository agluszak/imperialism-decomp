use crate::ui::generated;
use crate::ui::hover_help::{
    HoverHelpBarStyle, bind_hover_help_bar, bind_hover_help_texts, retail_string,
};
use crate::ui::load_save::{LoadSaveMode, open_load_save};
use crate::ui::retail::{RetailTree, RetailUiAssets};
use crate::{AppState, ReturnTo};
use bevy::app::AppExit;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::Activate;
use imperialism_formats::{StringGroup, fourcc};

#[derive(Component)]
struct MainMenuRoot;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MainMenuAction {
    RandomGame,
    Scenario,
    LoadGame,
    HighScores,
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
        (fourcc!("scen"), MainMenuAction::Scenario),
        (fourcc!("load"), MainMenuAction::LoadGame),
        (fourcc!("high"), MainMenuAction::HighScores),
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
            (
                fourcc!("rand"),
                retail_string(&assets, StringGroup::new(0x2737).offset(0)),
            ),
            (
                fourcc!("load"),
                retail_string(&assets, StringGroup::new(0x2737).offset(1)),
            ),
            (
                fourcc!("mult"),
                retail_string(&assets, StringGroup::new(0x2737).offset(2)),
            ),
            (
                fourcc!("high"),
                retail_string(&assets, StringGroup::new(0x2737).offset(3)),
            ),
            (
                fourcc!("scen"),
                retail_string(&assets, StringGroup::new(0x2737).offset(4)),
            ),
            (
                fourcc!("quit"),
                retail_string(&assets, StringGroup::new(0x2737).offset(9)),
            ),
            (
                fourcc!("pref"),
                retail_string(&assets, StringGroup::new(0x2743).offset(8)),
            ),
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
        MainMenuAction::Scenario => next_state.set(AppState::ScenarioSetup),
        MainMenuAction::LoadGame => {
            open_load_save(
                &mut commands,
                &mut next_state,
                LoadSaveMode::Load,
                AppState::MainMenu,
            );
        }
        MainMenuAction::HighScores => next_state.set(AppState::HighScore),
        MainMenuAction::Preferences => {
            commands.insert_resource(ReturnTo(AppState::MainMenu));
            next_state.set(AppState::Preferences);
        }
        MainMenuAction::Quit => {
            exit.write(AppExit::Success);
        }
    }
}
