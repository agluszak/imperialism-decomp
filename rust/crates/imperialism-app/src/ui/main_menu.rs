use crate::ui::generated;
use crate::ui::hover_help::{
    HoverHelpBarStyle, bind_hover_help_bar, bind_hover_help_texts, get_string,
};
use crate::ui::load_save::{LoadSaveMode, open_load_save};
use crate::ui::retail::RetailUiAssets;
use crate::{AppState, ReturnTo};
use bevy::app::AppExit;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::Activate;

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
    let ui = generated::spawn_startup_1500(&mut commands);
    commands
        .entity(ui.root)
        .insert((MainMenuRoot, ui, DespawnOnExit(AppState::MainMenu)));
}

fn bind_main_menu_actions(
    mut commands: Commands,
    ui: Single<&generated::Startup1500, Added<MainMenuRoot>>,
) {
    for (entity, action) in [
        (ui.rand, MainMenuAction::RandomGame),
        (ui.scen, MainMenuAction::Scenario),
        (ui.load, MainMenuAction::LoadGame),
        (ui.high, MainMenuAction::HighScores),
        (ui.pref, MainMenuAction::Preferences),
        (ui.quit, MainMenuAction::Quit),
    ] {
        commands
            .entity(entity)
            .insert(action)
            .remove::<InteractionDisabled>()
            .observe(on_main_menu_activate);
    }
}

fn bind_main_menu_hover_help(
    mut commands: Commands,
    ui: Single<&generated::Startup1500, Added<MainMenuRoot>>,
    mut nodes: Query<&mut Node>,
    mut assets: RetailUiAssets,
) {
    bind_hover_help_bar(
        &mut commands,
        &mut assets,
        ui.curs,
        &mut nodes
            .get_mut(ui.curs)
            .expect("main-menu hover-help bar has Node"),
        HoverHelpBarStyle::MAIN_MENU,
    );
    bind_hover_help_texts(
        &mut commands,
        [
            (ui.main, String::new()),
            (ui.rand, get_string(&assets, 0x2737, 0)),
            (ui.load, get_string(&assets, 0x2737, 1)),
            (ui.mult, get_string(&assets, 0x2737, 2)),
            (ui.high, get_string(&assets, 0x2737, 3)),
            (ui.scen, get_string(&assets, 0x2737, 4)),
            (ui.quit, get_string(&assets, 0x2737, 9)),
            (ui.pref, get_string(&assets, 0x2743, 8)),
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
