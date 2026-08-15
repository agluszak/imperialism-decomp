use crate::AppState;
use crate::ui::GameSession;
use crate::ui::credits::CreditsReturn;
use crate::ui::generated;
use crate::ui::hover_help::get_string;
use crate::ui::load_save::{LoadSaveMode, open_load_save};
use crate::ui::preferences::PreferencesReturn;
use crate::ui::retail::{ModalDialog, RetailTag, RetailUiAssets, find_descendant};
use bevy::app::AppExit;
use bevy::input_focus::tab_navigation::TabGroup;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::Activate;
use imperialism_formats::{FourCc, fourcc};

const FLAG_MENU_STRING_GROUP: i16 = 0x2743;
const FLAG_LABEL_TAGS: [FourCc; 8] = [
    fourcc!("txt0"),
    fourcc!("txt1"),
    fourcc!("txt2"),
    fourcc!("txt3"),
    fourcc!("txt4"),
    fourcc!("txt5"),
    fourcc!("txt6"),
    fourcc!("txt7"),
];

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OpenFlagMenu;

#[derive(Component)]
struct FlagMenuRoot;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum FlagMenuAction {
    Save,
    Load,
    Cancel,
    NewGame,
    Preferences,
    Credits,
    Quit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlagMenuNavigation {
    Dismiss,
    Save,
    Load,
    Preferences,
    Credits,
    Confirm(FlagMenuPending),
}

fn flag_menu_navigation(action: FlagMenuAction) -> FlagMenuNavigation {
    match action {
        FlagMenuAction::Cancel => FlagMenuNavigation::Dismiss,
        FlagMenuAction::Save => FlagMenuNavigation::Save,
        FlagMenuAction::Load => FlagMenuNavigation::Load,
        FlagMenuAction::Preferences => FlagMenuNavigation::Preferences,
        FlagMenuAction::Credits => FlagMenuNavigation::Credits,
        FlagMenuAction::NewGame => FlagMenuNavigation::Confirm(FlagMenuPending::NewGame),
        FlagMenuAction::Quit => FlagMenuNavigation::Confirm(FlagMenuPending::Quit),
    }
}

/// New-game or quit confirmation posed by the flag menu.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlagMenuPending {
    NewGame,
    Quit,
}

#[derive(Component)]
struct FlagMenuPrompt {
    kind: FlagMenuPending,
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum FlagMenuPromptAction {
    Accept,
    Dismiss,
}

pub(crate) struct FlagMenuPlugin;

impl Plugin for FlagMenuPlugin {
    fn build(&self, app: &mut App) {
        register_flag_menu_logic(app);
        app.add_systems(
            Update,
            (bind_flag_menu, bind_flag_menu_prompt).run_if(in_state(AppState::StrategicMap)),
        );
    }
}

fn register_flag_menu_logic(app: &mut App) {
    app.add_observer(on_open_flag_menu.run_if(in_state(AppState::StrategicMap)))
        .add_observer(on_flag_menu_activate.run_if(in_state(AppState::StrategicMap)))
        .add_observer(on_flag_menu_prompt_activate.run_if(in_state(AppState::StrategicMap)));
}

fn on_open_flag_menu(
    activate: On<Activate>,
    openers: Query<&OpenFlagMenu>,
    existing: Query<(), With<FlagMenuRoot>>,
    dialogs: Query<(), With<ModalDialog>>,
    mut commands: Commands,
) {
    if openers.get(activate.entity).is_err() || !existing.is_empty() || !dialogs.is_empty() {
        return;
    }
    let root = commands.spawn_scene(generated::linger_4140()).id();
    commands.entity(root).insert((
        FlagMenuRoot,
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(20),
        Pickable::default(),
        DespawnOnExit(AppState::StrategicMap),
    ));
}

fn bind_flag_menu(
    mut commands: Commands,
    root: Single<Entity, Added<FlagMenuRoot>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
) {
    let root = *root;
    for (index, tag) in FLAG_LABEL_TAGS.iter().copied().enumerate() {
        let entity = find_descendant(root, tag, &children, &tags);
        let (font, layout, line_height, _) = assets
            .text_style(imperialism_formats::RetailTextStylePreset {
                font_family: 1,
                face_flags: 0,
                point_size: if index == 0 { 12 } else { 14 },
                alignment: if index > 1 { -2 } else { 1 },
            })
            .expect("retail flag-menu label style");
        let (text_palette, shadow_palette) = if index == 0 {
            (0x5c, 0x28)
        } else {
            (0x28, 0xd2)
        };
        commands.entity(entity).insert((
            Text::new(get_string(&assets, FLAG_MENU_STRING_GROUP, index as i16)),
            font,
            layout,
            line_height,
            TextColor(assets.palette_color(text_palette)),
            TextShadow {
                offset: Vec2::ONE,
                color: assets.palette_color(shadow_palette),
            },
        ));
    }
    for (tag, action) in [
        (fourcc!("save"), FlagMenuAction::Save),
        (fourcc!("load"), FlagMenuAction::Load),
        (fourcc!("cncl"), FlagMenuAction::Cancel),
        (fourcc!("newg"), FlagMenuAction::NewGame),
        (fourcc!("pref"), FlagMenuAction::Preferences),
        (fourcc!("cred"), FlagMenuAction::Credits),
        (fourcc!("quit"), FlagMenuAction::Quit),
    ] {
        commands
            .entity(find_descendant(root, tag, &children, &tags))
            .insert(action)
            .remove::<InteractionDisabled>();
    }
}

fn on_flag_menu_activate(
    activate: On<Activate>,
    actions: Query<&FlagMenuAction>,
    menus: Query<Entity, With<FlagMenuRoot>>,
    prompts: Query<(), With<FlagMenuPrompt>>,
    mut next_state: ResMut<NextState<AppState>>,
    mut commands: Commands,
) {
    if !prompts.is_empty() {
        return;
    }
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    match flag_menu_navigation(*action) {
        FlagMenuNavigation::Dismiss => {
            for entity in &menus {
                commands.entity(entity).despawn();
            }
        }
        FlagMenuNavigation::Save => {
            open_load_save(
                &mut commands,
                &mut next_state,
                LoadSaveMode::Save,
                AppState::StrategicMap,
            );
        }
        FlagMenuNavigation::Load => {
            open_load_save(
                &mut commands,
                &mut next_state,
                LoadSaveMode::Load,
                AppState::StrategicMap,
            );
        }
        FlagMenuNavigation::Preferences => {
            commands.insert_resource(PreferencesReturn(AppState::StrategicMap));
            next_state.set(AppState::Preferences);
        }
        FlagMenuNavigation::Credits => {
            commands.insert_resource(CreditsReturn(AppState::StrategicMap));
            next_state.set(AppState::Credits);
        }
        FlagMenuNavigation::Confirm(pending) => {
            open_flag_menu_prompt(&mut commands, pending);
        }
    }
}

fn open_flag_menu_prompt(commands: &mut Commands, pending: FlagMenuPending) {
    let root = commands.spawn_scene(generated::linger_2020()).id();
    commands.entity(root).insert((
        FlagMenuPrompt { kind: pending },
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(21),
        Pickable::default(),
        DespawnOnExit(AppState::StrategicMap),
    ));
}

fn bind_flag_menu_prompt(
    mut commands: Commands,
    prompt: Single<(Entity, &FlagMenuPrompt), Added<FlagMenuPrompt>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
) {
    let (root, prompt) = prompt.into_inner();
    // `TViewMgr::DispatchGameStateEventIfLocalizedPromptAccepted` for single-player.
    let index = match prompt.kind {
        FlagMenuPending::NewGame => 0x2b,
        FlagMenuPending::Quit => 0x2a,
    };
    let body = assets
        .string(0x2737, index)
        .expect("retail flag-menu confirm string");
    let info = find_descendant(root, fourcc!("info"), &children, &tags);
    let (body_font, body_layout, body_line_height, _) = assets
        .text_style(imperialism_formats::RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 0,
        })
        .expect("retail flag-menu prompt body style");
    commands.entity(info).insert((
        Text::new(body),
        body_font,
        body_layout,
        body_line_height,
        TextColor(assets.palette_color(0)),
    ));
    commands
        .entity(find_descendant(root, fourcc!("okay"), &children, &tags))
        .insert(FlagMenuPromptAction::Accept)
        .remove::<InteractionDisabled>();
    commands
        .entity(find_descendant(root, fourcc!("cncl"), &children, &tags))
        .insert(FlagMenuPromptAction::Dismiss)
        .remove::<InteractionDisabled>();
}

fn on_flag_menu_prompt_activate(
    activate: On<Activate>,
    actions: Query<&FlagMenuPromptAction>,
    prompts: Query<(Entity, &FlagMenuPrompt)>,
    menus: Query<Entity, With<FlagMenuRoot>>,
    mut next_state: ResMut<NextState<AppState>>,
    mut exit: MessageWriter<AppExit>,
    mut commands: Commands,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let Ok((prompt_entity, prompt)) = prompts.single() else {
        return;
    };
    match *action {
        FlagMenuPromptAction::Dismiss => {
            commands.entity(prompt_entity).despawn();
        }
        FlagMenuPromptAction::Accept => {
            commands.entity(prompt_entity).despawn();
            for entity in &menus {
                commands.entity(entity).despawn();
            }
            match prompt.kind {
                FlagMenuPending::NewGame => {
                    commands.remove_resource::<GameSession>();
                    next_state.set(AppState::MainMenu);
                }
                FlagMenuPending::Quit => {
                    exit.write(AppExit::Success);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperialism_core::{GameState, NationId};
    use imperialism_formats::{LegacyGameStateContext, LegacySaveV62, peek_save_header};

    const BEGINNING_OF_GAME: &[u8] =
        include_bytes!("../../../../../fixtures/retail/beginning_of_game.imp");

    fn fixture_state() -> GameState {
        let selected_nation = peek_save_header(BEGINNING_OF_GAME)
            .and_then(|header| NationId::try_new(header.active_nation))
            .expect("beginning-of-game fixture names a nation in range");
        LegacySaveV62::parse(BEGINNING_OF_GAME).game_state(LegacyGameStateContext {
            crt_rand_state: 1,
            map_generation_lcg: 0,
            zone_status_lcg: 0,
            selected_nation,
        })
    }

    fn test_app() -> App {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(bevy::state::app::StatesPlugin)
            .add_message::<AppExit>()
            .insert_state(AppState::StrategicMap);
        register_flag_menu_logic(&mut app);
        app
    }

    fn spawn_test_flag_menu(mut commands: Commands) {
        commands.spawn((FlagMenuRoot, Node::default()));
    }

    fn spawn_test_flag_prompt(mut commands: Commands, kind: FlagMenuPending) {
        let root = commands
            .spawn((FlagMenuPrompt { kind }, Node::default()))
            .id();
        commands.spawn((FlagMenuPromptAction::Accept, ChildOf(root)));
        commands.spawn((FlagMenuPromptAction::Dismiss, ChildOf(root)));
    }

    #[test]
    fn flag_menu_actions_map_to_navigation_intent() {
        assert_eq!(
            flag_menu_navigation(FlagMenuAction::Cancel),
            FlagMenuNavigation::Dismiss
        );
        assert_eq!(
            flag_menu_navigation(FlagMenuAction::Save),
            FlagMenuNavigation::Save
        );
        assert_eq!(
            flag_menu_navigation(FlagMenuAction::Load),
            FlagMenuNavigation::Load
        );
        assert_eq!(
            flag_menu_navigation(FlagMenuAction::Preferences),
            FlagMenuNavigation::Preferences
        );
        assert_eq!(
            flag_menu_navigation(FlagMenuAction::Credits),
            FlagMenuNavigation::Credits
        );
        assert_eq!(
            flag_menu_navigation(FlagMenuAction::NewGame),
            FlagMenuNavigation::Confirm(FlagMenuPending::NewGame)
        );
        assert_eq!(
            flag_menu_navigation(FlagMenuAction::Quit),
            FlagMenuNavigation::Confirm(FlagMenuPending::Quit)
        );
    }

    #[test]
    fn accepting_new_game_drops_the_session_and_returns_to_the_main_menu() {
        let mut app = test_app();
        app.insert_resource(GameSession {
            game: fixture_state(),
        });
        app.add_systems(Startup, spawn_test_flag_menu);
        app.add_systems(Startup, |commands: Commands| {
            spawn_test_flag_prompt(commands, FlagMenuPending::NewGame)
        });
        app.update();

        let accept = app
            .world_mut()
            .query_filtered::<Entity, With<FlagMenuPromptAction>>()
            .iter(app.world())
            .find(|entity| {
                app.world().get::<FlagMenuPromptAction>(*entity)
                    == Some(&FlagMenuPromptAction::Accept)
            })
            .unwrap();
        app.world_mut()
            .commands()
            .trigger(Activate { entity: accept });
        app.world_mut().flush();
        app.update();
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::MainMenu
        );
        assert!(app.world().get_resource::<GameSession>().is_none());
    }

    #[test]
    fn accepting_quit_posts_app_exit() {
        let mut app = test_app();
        app.add_systems(Startup, |commands: Commands| {
            spawn_test_flag_prompt(commands, FlagMenuPending::Quit)
        });
        app.update();

        let accept = app
            .world_mut()
            .query_filtered::<Entity, With<FlagMenuPromptAction>>()
            .iter(app.world())
            .find(|entity| {
                app.world().get::<FlagMenuPromptAction>(*entity)
                    == Some(&FlagMenuPromptAction::Accept)
            })
            .unwrap();
        app.world_mut()
            .commands()
            .trigger(Activate { entity: accept });
        app.world_mut().flush();
        app.update();
        let exits = app
            .world_mut()
            .resource_mut::<bevy::ecs::message::Messages<AppExit>>()
            .drain()
            .collect::<Vec<_>>();
        assert_eq!(exits, vec![AppExit::Success]);
    }

    #[test]
    fn dismissing_new_game_keeps_the_flag_menu_open() {
        let mut app = test_app();
        app.add_systems(Startup, spawn_test_flag_menu);
        app.add_systems(Startup, |commands: Commands| {
            spawn_test_flag_prompt(commands, FlagMenuPending::NewGame)
        });
        app.update();

        let dismiss = app
            .world_mut()
            .query_filtered::<Entity, With<FlagMenuPromptAction>>()
            .iter(app.world())
            .find(|entity| {
                app.world().get::<FlagMenuPromptAction>(*entity)
                    == Some(&FlagMenuPromptAction::Dismiss)
            })
            .unwrap();
        app.world_mut()
            .commands()
            .trigger(Activate { entity: dismiss });
        app.world_mut().flush();
        app.update();
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::StrategicMap
        );
        assert!(
            app.world_mut()
                .query_filtered::<Entity, With<FlagMenuPrompt>>()
                .iter(app.world())
                .next()
                .is_none()
        );
        assert!(
            app.world_mut()
                .query_filtered::<Entity, With<FlagMenuRoot>>()
                .iter(app.world())
                .next()
                .is_some()
        );
    }
}
