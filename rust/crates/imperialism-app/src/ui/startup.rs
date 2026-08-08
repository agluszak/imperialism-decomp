use crate::session::{GameLoopSet, SubmitCommand};
use crate::ui::{
    DespawnUiView, InteractiveUiWidget, PresentedViewId, SpawnUiView, UiIntent, UiRuntimeSet,
    UiViewSpawned, UiWidgetFlags, ViewInstanceId, WidgetTag,
};
use bevy::app::AppExit;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use imperialism_core::GameCommand;
use imperialism_formats::ScopedViewId;

const STARTUP_RESOURCE_FILE: &str = "Startup.rsrc";
const MAIN_MENU_RESOURCE_ID: i16 = 1500;
const RANDOM_SETUP_RESOURCE_ID: i16 = 1501;

pub fn main_menu_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: STARTUP_RESOURCE_FILE.to_owned(),
        resource_id: MAIN_MENU_RESOURCE_ID,
    }
}

pub fn random_setup_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: STARTUP_RESOURCE_FILE.to_owned(),
        resource_id: RANDOM_SETUP_RESOURCE_ID,
    }
}

#[derive(Resource, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StartupScreenInstances {
    main_menu: Option<ViewInstanceId>,
    random_setup: Option<ViewInstanceId>,
}

impl StartupScreenInstances {
    pub const fn main_menu(&self) -> Option<ViewInstanceId> {
        self.main_menu
    }

    pub const fn random_setup(&self) -> Option<ViewInstanceId> {
        self.random_setup
    }
}

pub struct StartupUiPlugin;

impl Plugin for StartupUiPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<StartupScreenInstances>()
            .add_systems(Startup, request_main_menu)
            .add_systems(
                Update,
                translate_startup_intents
                    .after(UiRuntimeSet::EmitIntents)
                    .in_set(GameLoopSet::TranslateUiIntents),
            )
            .add_systems(
                Update,
                (record_spawned_startup_views, apply_main_menu_availability)
                    .chain()
                    .after(UiRuntimeSet::DespawnViews)
                    .in_set(GameLoopSet::UpdatePresentation),
            );
    }
}

fn request_main_menu(mut spawn: MessageWriter<SpawnUiView>) {
    spawn.write(SpawnUiView(main_menu_view_id()));
}

fn record_spawned_startup_views(
    mut spawned: MessageReader<UiViewSpawned>,
    mut instances: ResMut<StartupScreenInstances>,
) {
    for message in spawned.read() {
        if message.view == main_menu_view_id() {
            instances.main_menu = Some(message.instance);
        } else if message.view == random_setup_view_id() {
            instances.random_setup = Some(message.instance);
        }
    }
}

fn apply_main_menu_availability(
    mut commands: Commands,
    mut widgets: Query<
        (Entity, &PresentedViewId, &WidgetTag, &mut UiWidgetFlags),
        With<InteractiveUiWidget>,
    >,
) {
    let main_menu = main_menu_view_id();
    for (entity, view, tag, mut flags) in &mut widgets {
        if view.0 != main_menu {
            continue;
        }
        let available = matches!(tag.0.0.as_str(), "rand" | "quit");
        flags.enabled = available;
        if available {
            commands.entity(entity).remove::<InteractionDisabled>();
        } else {
            commands.entity(entity).insert(InteractionDisabled);
        }
    }
}

fn translate_startup_intents(
    mut intents: MessageReader<UiIntent>,
    mut instances: ResMut<StartupScreenInstances>,
    mut spawn: MessageWriter<SpawnUiView>,
    mut despawn: MessageWriter<DespawnUiView>,
    mut commands: MessageWriter<SubmitCommand>,
    mut exit: MessageWriter<AppExit>,
) {
    for intent in intents.read() {
        let view = match intent {
            UiIntent::Activated { view, .. }
            | UiIntent::ValueChanged { view, .. }
            | UiIntent::TextChanged { view, .. } => *view,
        };
        if instances.main_menu == Some(view) {
            if let UiIntent::Activated { tag, .. } = intent {
                match tag.0.as_str() {
                    "rand" => {
                        instances.main_menu = None;
                        despawn.write(DespawnUiView(view));
                        spawn.write(SpawnUiView(random_setup_view_id()));
                    }
                    "quit" => {
                        exit.write(AppExit::Success);
                    }
                    _ => {}
                }
            }
            continue;
        }
        if instances.random_setup != Some(view) {
            continue;
        }
        if let Some(command) = random_setup_command(intent) {
            commands.write(SubmitCommand(command));
        }
    }
}

fn random_setup_command(intent: &UiIntent) -> Option<GameCommand> {
    match intent {
        UiIntent::Activated { tag, .. } => match tag.0.as_str() {
            "dif0" => Some(GameCommand::SetRandomGameDifficulty { difficulty: 0 }),
            "dif1" => Some(GameCommand::SetRandomGameDifficulty { difficulty: 1 }),
            "dif2" => Some(GameCommand::SetRandomGameDifficulty { difficulty: 2 }),
            "dif3" => Some(GameCommand::SetRandomGameDifficulty { difficulty: 3 }),
            "dif4" => Some(GameCommand::SetRandomGameDifficulty { difficulty: 4 }),
            "hist" => Some(GameCommand::SetRandomGameNameMode {
                use_localized_name_tables: true,
            }),
            "rand" => Some(GameCommand::SetRandomGameNameMode {
                use_localized_name_tables: false,
            }),
            _ => None,
        },
        UiIntent::ValueChanged { tag, value, .. } => match tag.0.as_str() {
            "diff" => Some(GameCommand::SetRandomGameDifficulty { difficulty: *value }),
            "name" => Some(GameCommand::SetRandomGameNameMode {
                use_localized_name_tables: *value != 0,
            }),
            "map " => i16::try_from(*value)
                .ok()
                .map(|nation_slot| GameCommand::SelectRandomGameNation { nation_slot }),
            _ => None,
        },
        UiIntent::TextChanged { tag, value, .. } => {
            (tag.0 == "coun").then(|| GameCommand::SetRandomGameCountryName {
                country_name: value.clone(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{UiCatalogResource, UiRuntimePlugin, UiViewRoot};
    use bevy::ecs::message::{MessageCursor, Messages};
    use imperialism_formats::{FourCc, UiCatalog};
    use std::collections::HashMap;

    const CATALOG_JSON: &str = include_str!("../../../imperialism-formats/assets/ui_catalog.json");

    fn app() -> App {
        let catalog = serde_json::from_str::<UiCatalog>(CATALOG_JSON).unwrap();
        let mut app = App::new();
        app.insert_resource(UiCatalogResource::new(catalog).unwrap())
            .add_message::<SubmitCommand>()
            .add_plugins((UiRuntimePlugin, StartupUiPlugin));
        app.update();
        app.update();
        app
    }

    fn startup_roots(app: &mut App) -> HashMap<ScopedViewId, (Entity, ViewInstanceId)> {
        let world = app.world_mut();
        world
            .query_filtered::<(Entity, &PresentedViewId, &ViewInstanceId), With<UiViewRoot>>()
            .iter(world)
            .map(|(entity, view, instance)| (view.0.clone(), (entity, *instance)))
            .collect()
    }

    #[derive(Resource)]
    struct PressOnce(Entity);

    fn press_once(pressed: Res<PressOnce>, mut interactions: Query<&mut Interaction>) {
        *interactions.get_mut(pressed.0).unwrap() = Interaction::Pressed;
    }

    #[test]
    fn main_menu_enables_only_random_and_quit_without_hiding_other_choices() {
        let mut app = app();
        let world = app.world_mut();
        let widgets = world
            .query::<(
                Entity,
                &PresentedViewId,
                &WidgetTag,
                &UiWidgetFlags,
                &Node,
                Option<&InteractionDisabled>,
            )>()
            .iter(world)
            .filter(|(_, view, _, _, _, _)| view.0 == main_menu_view_id())
            .map(|(entity, _, tag, flags, node, disabled)| {
                (
                    tag.0.0.clone(),
                    (entity, *flags, node.display, disabled.is_some()),
                )
            })
            .collect::<HashMap<_, _>>();
        for tag in ["rand", "quit"] {
            let (_, flags, display, disabled) = widgets[tag];
            assert!(flags.enabled);
            assert_eq!(display, Display::Flex);
            assert!(!disabled);
        }
        for tag in ["load", "mult", "high", "scen", "pref"] {
            let (_, flags, display, disabled) = widgets[tag];
            assert!(!flags.enabled);
            assert_eq!(display, Display::Flex);
            assert!(disabled);
        }
    }

    #[test]
    fn disabled_choice_emits_no_intent_and_random_replaces_only_the_menu() {
        let mut app = app();
        app.world_mut()
            .write_message(SpawnUiView(ScopedViewId {
                resource_file: "FlagView.rsrc".to_owned(),
                resource_id: 8451,
            }))
            .unwrap();
        app.update();
        let menu_instance = app
            .world()
            .resource::<StartupScreenInstances>()
            .main_menu()
            .unwrap();
        let (load, _) = app
            .world_mut()
            .query::<(Entity, &ViewInstanceId, &WidgetTag)>()
            .iter(app.world())
            .find(|(_, instance, tag)| **instance == menu_instance && tag.0.0 == "load")
            .map(|(entity, instance, _)| (entity, *instance))
            .unwrap();
        app.insert_resource(PressOnce(load))
            .add_systems(PreUpdate, press_once);
        let mut intent_cursor = MessageCursor::<UiIntent>::default();
        app.update();
        assert_eq!(
            intent_cursor
                .read(app.world().resource::<Messages<UiIntent>>())
                .count(),
            0
        );

        app.world_mut()
            .write_message(UiIntent::Activated {
                view: menu_instance,
                tag: FourCc("rand".to_owned()),
            })
            .unwrap();
        app.update();
        app.update();
        let roots = startup_roots(&mut app);
        assert!(!roots.contains_key(&main_menu_view_id()));
        assert!(roots.contains_key(&random_setup_view_id()));
        assert!(
            roots
                .keys()
                .any(|view| view.resource_file == "FlagView.rsrc")
        );
    }

    #[test]
    fn quit_requests_a_successful_app_exit() {
        let mut app = app();
        let menu = app
            .world()
            .resource::<StartupScreenInstances>()
            .main_menu()
            .unwrap();
        app.world_mut()
            .write_message(UiIntent::Activated {
                view: menu,
                tag: FourCc("quit".to_owned()),
            })
            .unwrap();
        app.update();
        let exits = app
            .world_mut()
            .resource_mut::<Messages<AppExit>>()
            .drain()
            .collect::<Vec<_>>();
        assert_eq!(exits, vec![AppExit::Success]);
    }

    #[test]
    fn random_setup_intents_enqueue_commands_without_a_game_session() {
        let mut app = app();
        let menu = app
            .world()
            .resource::<StartupScreenInstances>()
            .main_menu()
            .unwrap();
        app.world_mut()
            .write_message(UiIntent::Activated {
                view: menu,
                tag: FourCc("rand".to_owned()),
            })
            .unwrap();
        app.update();
        app.update();
        let setup = app
            .world()
            .resource::<StartupScreenInstances>()
            .random_setup()
            .unwrap();
        let intents = [
            UiIntent::Activated {
                view: setup,
                tag: FourCc("dif3".to_owned()),
            },
            UiIntent::Activated {
                view: setup,
                tag: FourCc("hist".to_owned()),
            },
            UiIntent::ValueChanged {
                view: setup,
                tag: FourCc("map ".to_owned()),
                value: 4,
            },
            UiIntent::TextChanged {
                view: setup,
                tag: FourCc("coun".to_owned()),
                value: "Testland".to_owned(),
            },
        ];
        for intent in intents {
            app.world_mut().write_message(intent).unwrap();
        }
        app.update();
        assert!(
            !app.world()
                .contains_resource::<crate::session::GameSession>()
        );
        let commands = app
            .world_mut()
            .resource_mut::<Messages<SubmitCommand>>()
            .drain()
            .collect::<Vec<_>>();
        assert_eq!(
            commands,
            vec![
                SubmitCommand(GameCommand::SetRandomGameDifficulty { difficulty: 3 }),
                SubmitCommand(GameCommand::SetRandomGameNameMode {
                    use_localized_name_tables: true,
                }),
                SubmitCommand(GameCommand::SelectRandomGameNation { nation_slot: 4 }),
                SubmitCommand(GameCommand::SetRandomGameCountryName {
                    country_name: "Testland".to_owned(),
                }),
            ]
        );
    }
}
