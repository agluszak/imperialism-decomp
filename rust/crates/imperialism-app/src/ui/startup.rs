use crate::flow::AppState;
use crate::session::GameLoopSet;
use crate::ui::{
    DespawnUiView, InteractiveUiWidget, PresentedViewId, SpawnUiView, UiIntent, UiRuntimeSet,
    UiViewSpawned, UiWidgetFlags, ViewInstanceId, WidgetTag,
};
use bevy::app::AppExit;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use imperialism_core::{MajorNationId, RetailTopologyByte};
use imperialism_formats::ScopedViewId;

const STARTUP_RESOURCE_FILE: &str = "Startup.rsrc";
const MAIN_MENU_RESOURCE_ID: i16 = 1500;
const RANDOM_SETUP_RESOURCE_ID: i16 = 1501;

pub(crate) fn main_menu_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: STARTUP_RESOURCE_FILE.to_owned(),
        resource_id: MAIN_MENU_RESOURCE_ID,
    }
}

pub(crate) fn random_setup_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: STARTUP_RESOURCE_FILE.to_owned(),
        resource_id: RANDOM_SETUP_RESOURCE_ID,
    }
}

/// The five values exposed by the recovered random-game setup controls.
///
/// Their retail labels have not yet been recovered, so the draft retains the
/// control values rather than assigning speculative names to them.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum Difficulty {
    #[default]
    Level0,
    Level1,
    Level2,
    Level3,
    Level4,
}

impl Difficulty {
    pub(crate) const fn from_retail_value(value: i32) -> Option<Self> {
        match value {
            0 => Some(Self::Level0),
            1 => Some(Self::Level1),
            2 => Some(Self::Level2),
            3 => Some(Self::Level3),
            4 => Some(Self::Level4),
            _ => None,
        }
    }
}

/// Presentation-owned values edited by the random-game setup screen.
///
/// This is deliberately not simulation state: pressing Start will later pass
/// this complete draft to the one game-creation operation.
#[derive(Resource, Clone, Debug, Eq, PartialEq)]
pub(crate) struct RandomGameSetup {
    pub(crate) planet_seed: String,
    pub(crate) topology: RetailTopologyByte,
    pub(crate) nation: MajorNationId,
    pub(crate) country_name: String,
    pub(crate) difficulty: Difficulty,
    pub(crate) localized_names: bool,
}

impl Default for RandomGameSetup {
    fn default() -> Self {
        Self {
            planet_seed: String::new(),
            topology: RetailTopologyByte::from_wraps_horizontally(true),
            nation: MajorNationId::new(0),
            country_name: String::new(),
            difficulty: Difficulty::default(),
            localized_names: false,
        }
    }
}

#[derive(Resource, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct StartupScreenInstances {
    main_menu: Option<ViewInstanceId>,
    random_setup: Option<ViewInstanceId>,
}

impl StartupScreenInstances {
    #[cfg(test)]
    pub(crate) const fn main_menu(&self) -> Option<ViewInstanceId> {
        self.main_menu
    }

    #[cfg(test)]
    pub(crate) const fn random_setup(&self) -> Option<ViewInstanceId> {
        self.random_setup
    }
}

pub(crate) struct StartupUiPlugin;

impl Plugin for StartupUiPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<StartupScreenInstances>()
            .init_resource::<RandomGameSetup>()
            .add_systems(OnEnter(AppState::MainMenu), request_main_menu)
            .add_systems(OnExit(AppState::MainMenu), dismiss_main_menu)
            .add_systems(OnEnter(AppState::RandomSetup), request_random_setup)
            .add_systems(OnExit(AppState::RandomSetup), dismiss_random_setup)
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

fn dismiss_main_menu(
    mut instances: ResMut<StartupScreenInstances>,
    mut despawn: MessageWriter<DespawnUiView>,
) {
    if let Some(instance) = instances.main_menu.take() {
        despawn.write(DespawnUiView(instance));
    }
}

fn request_random_setup(mut spawn: MessageWriter<SpawnUiView>) {
    spawn.write(SpawnUiView(random_setup_view_id()));
}

fn dismiss_random_setup(
    mut instances: ResMut<StartupScreenInstances>,
    mut despawn: MessageWriter<DespawnUiView>,
) {
    if let Some(instance) = instances.random_setup.take() {
        despawn.write(DespawnUiView(instance));
    }
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
    instances: Res<StartupScreenInstances>,
    state: Res<State<AppState>>,
    mut next_state: ResMut<NextState<AppState>>,
    mut setup: ResMut<RandomGameSetup>,
    mut exit: MessageWriter<AppExit>,
) {
    for intent in intents.read() {
        let view = match intent {
            UiIntent::Activated { view, .. }
            | UiIntent::ValueChanged { view, .. }
            | UiIntent::TextChanged { view, .. } => *view,
        };
        if *state.get() == AppState::MainMenu && instances.main_menu == Some(view) {
            if let UiIntent::Activated { tag, .. } = intent {
                match tag.0.as_str() {
                    "rand" => {
                        next_state.set(AppState::RandomSetup);
                    }
                    "quit" => {
                        exit.write(AppExit::Success);
                    }
                    _ => {}
                }
            }
            continue;
        }
        if *state.get() != AppState::RandomSetup || instances.random_setup != Some(view) {
            continue;
        }
        apply_random_setup_intent(&mut setup, intent);
    }
}

fn apply_random_setup_intent(setup: &mut RandomGameSetup, intent: &UiIntent) {
    match intent {
        UiIntent::Activated { tag, .. } => match tag.0.as_str() {
            "dif0" => setup.difficulty = Difficulty::Level0,
            "dif1" => setup.difficulty = Difficulty::Level1,
            "dif2" => setup.difficulty = Difficulty::Level2,
            "dif3" => setup.difficulty = Difficulty::Level3,
            "dif4" => setup.difficulty = Difficulty::Level4,
            "hist" => setup.localized_names = true,
            "rand" => setup.localized_names = false,
            _ => {}
        },
        UiIntent::ValueChanged { tag, value, .. } => match tag.0.as_str() {
            "diff" => {
                if let Some(difficulty) = Difficulty::from_retail_value(*value) {
                    setup.difficulty = difficulty;
                }
            }
            "name" => setup.localized_names = *value != 0,
            "map " => {
                if let Ok(nation) = u8::try_from(*value)
                    && nation < MajorNationId::COUNT
                {
                    setup.nation = MajorNationId::new(nation);
                }
            }
            _ => {}
        },
        UiIntent::TextChanged { tag, value, .. } => {
            if tag.0 == "coun" {
                setup.country_name.clone_from(value);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::ScreenFlowPlugin;
    use crate::session::{GameSession, SessionPlugin, SubmitCommand};
    use crate::ui::{UiCatalogResource, UiRuntimePlugin, UiViewRoot};
    use bevy::ecs::message::{MessageCursor, Messages};
    use imperialism_formats::{FourCc, UiCatalog};
    use std::collections::HashMap;

    const CATALOG_JSON: &str = include_str!("../../../imperialism-formats/assets/ui_catalog.json");

    fn app() -> App {
        let catalog = serde_json::from_str::<UiCatalog>(CATALOG_JSON).unwrap();
        let mut app = App::new();
        app.insert_resource(UiCatalogResource::new(catalog))
            .add_plugins(bevy::state::app::StatesPlugin)
            .add_plugins((
                ScreenFlowPlugin,
                SessionPlugin,
                UiRuntimePlugin,
                StartupUiPlugin,
            ));
        app.world_mut()
            .resource_mut::<NextState<AppState>>()
            .set(AppState::MainMenu);
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
    fn disabled_choice_emits_no_intent_and_random_setup_replaces_only_the_menu() {
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
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::RandomSetup
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
    fn random_setup_intents_update_the_app_draft_without_a_game_session() {
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
            UiIntent::ValueChanged {
                view: setup,
                tag: FourCc("diff".to_owned()),
                value: 5,
            },
            UiIntent::ValueChanged {
                view: setup,
                tag: FourCc("map ".to_owned()),
                value: 7,
            },
            UiIntent::Activated {
                view: setup,
                tag: FourCc("okay".to_owned()),
            },
        ];
        for intent in intents {
            app.world_mut().write_message(intent).unwrap();
        }
        app.update();
        assert!(!app.world().contains_resource::<GameSession>());
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::RandomSetup
        );
        assert_eq!(
            app.world().resource::<RandomGameSetup>(),
            &RandomGameSetup {
                planet_seed: String::new(),
                topology: RetailTopologyByte::from_wraps_horizontally(true),
                nation: MajorNationId::new(4),
                country_name: "Testland".to_owned(),
                difficulty: Difficulty::Level3,
                localized_names: true,
            }
        );
        assert_eq!(app.world().resource::<Messages<SubmitCommand>>().len(), 0);
    }
}
