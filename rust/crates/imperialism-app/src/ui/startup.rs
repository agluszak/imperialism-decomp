use crate::ui::{
    DespawnUiView, InteractiveUiWidget, SpawnUiView, UiIntent, UiRuntimeSet, UiViewSpawned,
    ViewInstanceId, WidgetTag,
};
use crate::{AppState, GameLoopSet};
use bevy::app::AppExit;
use bevy::ecs::system::SystemParam;
use bevy::input::ButtonState;
use bevy::input::keyboard::{KeyCode, KeyboardInput};
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use imperialism_core::{
    MajorNationId, RandomSetupPreview as GeneratedRandomSetupPreview, RetailCrtRng, RetailLcg,
    RetailTopologyByte, generate_english_random_setup_name,
    generate_random_setup_preview_with_clock_seed,
};
use imperialism_formats::ScopedViewId;
use std::time::{SystemTime, UNIX_EPOCH};

const STARTUP_RESOURCE_FILE: &str = "Startup.rsrc";
const MAIN_MENU_RESOURCE_ID: i16 = 1500;
const RANDOM_SETUP_RESOURCE_ID: i16 = 1501;
const PLANET_SEED_RESOURCE_FILE: &str = "Linger.rsrc";
const PLANET_SEED_RESOURCE_ID: i16 = 954;
const COUNTRY_NAME_MAX_CHARS: usize = 12;
const PLANET_SEED_MAX_CHARS: usize = 32;

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

fn planet_seed_dialog_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: PLANET_SEED_RESOURCE_FILE.to_owned(),
        resource_id: PLANET_SEED_RESOURCE_ID,
    }
}

/// Presentation-owned values edited by the random-game setup screen.
///
/// This is deliberately not simulation state: pressing Start will later pass
/// this complete draft to the one game-creation operation.
///
/// `difficulty` is the opaque retail control value `0..=4`; labels are unknown.
#[derive(Resource, Clone, Debug, Eq, PartialEq)]
pub(crate) struct RandomGameSetup {
    pub(crate) planet_seed: String,
    pub(crate) topology: RetailTopologyByte,
    pub(crate) nation: MajorNationId,
    pub(crate) country_name: String,
    pub(crate) difficulty: u8,
    pub(crate) localized_names: bool,
}

impl Default for RandomGameSetup {
    fn default() -> Self {
        // This draft is initialized from retail's clock-seeded setup path when
        // the Random Setup screen first opens. It is never presented in this
        // sentinel state.
        Self {
            planet_seed: String::new(),
            topology: RetailTopologyByte::from_wraps_horizontally(true),
            nation: MajorNationId::new(0),
            country_name: String::new(),
            difficulty: 0,
            localized_names: false,
        }
    }
}

/// The generated map data owned by the setup screen.
#[derive(Resource, Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RandomSetupPreview {
    pub(crate) preview: Option<GeneratedRandomSetupPreview>,
}

/// The one clock value retail shares between the CRT setup draw and its
/// English random-name stream for this setup entry.
#[derive(Resource, Clone, Copy, Debug, Eq, PartialEq)]
struct RandomSetupClockSeed(u32);

impl Default for RandomSetupClockSeed {
    fn default() -> Self {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());
        Self(seconds as u32)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RandomSetupEditTarget {
    CountryName,
    PlanetSeed,
}

#[derive(Resource, Clone, Copy, Debug, Default, Eq, PartialEq)]
struct RandomSetupEditFocus(Option<RandomSetupEditTarget>);

#[derive(Resource, Clone, Debug, Default, Eq, PartialEq)]
struct PlanetSeedDialog {
    active: bool,
    instance: Option<ViewInstanceId>,
    draft: String,
    selected_on_open: bool,
}

#[derive(SystemParam)]
struct RandomSetupInteraction<'w> {
    clock_seed: Res<'w, RandomSetupClockSeed>,
    setup: ResMut<'w, RandomGameSetup>,
    preview: ResMut<'w, RandomSetupPreview>,
    edit_focus: ResMut<'w, RandomSetupEditFocus>,
    dialog: ResMut<'w, PlanetSeedDialog>,
    spawn: MessageWriter<'w, SpawnUiView>,
    despawn: MessageWriter<'w, DespawnUiView>,
}

#[derive(SystemParam)]
struct RandomSetupTextInput<'w> {
    clock_seed: Res<'w, RandomSetupClockSeed>,
    setup: ResMut<'w, RandomGameSetup>,
    preview: ResMut<'w, RandomSetupPreview>,
    edit_focus: ResMut<'w, RandomSetupEditFocus>,
    dialog: ResMut<'w, PlanetSeedDialog>,
    despawn: MessageWriter<'w, DespawnUiView>,
}

#[derive(Resource, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct StartupScreenInstances {
    main_menu: Option<ViewInstanceId>,
    random_setup: Option<ViewInstanceId>,
}

impl StartupScreenInstances {
    #[cfg(test)]
    pub(crate) const fn main_menu(self) -> Option<ViewInstanceId> {
        self.main_menu
    }

    #[cfg(test)]
    pub(crate) const fn random_setup(self) -> Option<ViewInstanceId> {
        self.random_setup
    }
}

pub(crate) struct StartupUiPlugin;

impl Plugin for StartupUiPlugin {
    fn build(&self, app: &mut App) {
        app.init_resource::<StartupScreenInstances>()
            .init_resource::<RandomGameSetup>()
            .init_resource::<RandomSetupPreview>()
            .init_resource::<RandomSetupClockSeed>()
            .init_resource::<RandomSetupEditFocus>()
            .init_resource::<PlanetSeedDialog>()
            .add_message::<KeyboardInput>()
            .add_systems(OnEnter(AppState::MainMenu), request_main_menu)
            .add_systems(OnExit(AppState::MainMenu), dismiss_main_menu)
            .add_systems(
                OnEnter(AppState::RandomSetup),
                (initialize_random_setup, request_random_setup).chain(),
            )
            .add_systems(OnExit(AppState::RandomSetup), dismiss_random_setup)
            .add_systems(
                Update,
                (
                    translate_startup_intents.after(UiRuntimeSet::EmitIntents),
                    edit_random_setup_text.after(translate_startup_intents),
                )
                    .chain()
                    .in_set(GameLoopSet::TranslateUiIntents),
            )
            .add_systems(
                Update,
                (
                    record_spawned_startup_views,
                    apply_main_menu_availability,
                    apply_random_setup_availability,
                    sync_random_setup_edit_text,
                )
                    .chain()
                    .after(UiRuntimeSet::DespawnViews)
                    .in_set(GameLoopSet::UpdatePresentation),
            );
    }
}

fn request_main_menu(mut spawn: MessageWriter<SpawnUiView>) {
    spawn.write(SpawnUiView(main_menu_view_id()));
}

fn initialize_random_setup(
    clock_seed: Res<RandomSetupClockSeed>,
    mut setup: ResMut<RandomGameSetup>,
    mut preview: ResMut<RandomSetupPreview>,
) {
    // Re-entering the retail setup screen keeps the existing generated map and
    // selected nation. A nonempty generated planet seed is that concrete state
    // in the current app boundary.
    if !setup.planet_seed.is_empty() {
        return;
    }

    let mut crt_rng = RetailCrtRng::from_state(clock_seed.0);
    let nation = MajorNationId::new((crt_rng.next_rand() % i32::from(MajorNationId::COUNT)) as u8);

    // TSetupRandomMapPicture generates these two English fallbacks from one
    // shared zone/status stream: planet first, country second.
    let mut name_rng = RetailLcg::from_state(clock_seed.0);
    let planet_seed = generate_english_random_setup_name(&mut name_rng);
    let country_name = generate_english_random_setup_name(&mut name_rng);
    let topology = RetailTopologyByte::from_wraps_horizontally(true);

    *setup = RandomGameSetup {
        planet_seed,
        topology,
        nation,
        country_name,
        difficulty: 0,
        localized_names: true,
    };
    update_random_setup_preview(
        &mut preview,
        generate_random_setup_preview_with_clock_seed(
            setup.planet_seed.as_bytes(),
            setup.topology,
            clock_seed.0,
        ),
    );
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
    mut dialog: ResMut<PlanetSeedDialog>,
    mut edit_focus: ResMut<RandomSetupEditFocus>,
    mut despawn: MessageWriter<DespawnUiView>,
) {
    if let Some(instance) = instances.random_setup.take() {
        despawn.write(DespawnUiView(instance));
    }
    if let Some(instance) = dialog.instance.take() {
        despawn.write(DespawnUiView(instance));
    }
    dialog.active = false;
    dialog.draft.clear();
    dialog.selected_on_open = false;
    edit_focus.0 = None;
}

fn record_spawned_startup_views(
    mut spawned: MessageReader<UiViewSpawned>,
    mut instances: ResMut<StartupScreenInstances>,
    mut dialog: ResMut<PlanetSeedDialog>,
) {
    for message in spawned.read() {
        if message.view == main_menu_view_id() {
            instances.main_menu = Some(message.instance);
        } else if message.view == random_setup_view_id() {
            instances.random_setup = Some(message.instance);
        } else if message.view == planet_seed_dialog_view_id() && dialog.active {
            dialog.instance = Some(message.instance);
        }
    }
}

fn apply_main_menu_availability(
    mut commands: Commands,
    instances: Res<StartupScreenInstances>,
    widgets: Query<(Entity, &ViewInstanceId, &WidgetTag), With<InteractiveUiWidget>>,
) {
    let Some(main_menu) = instances.main_menu else {
        return;
    };
    for (entity, instance, tag) in &widgets {
        if *instance != main_menu {
            continue;
        }
        let available = matches!(tag.0.0.as_str(), "rand" | "quit");
        if available {
            commands.entity(entity).remove::<InteractionDisabled>();
        } else {
            commands.entity(entity).insert(InteractionDisabled);
        }
    }
}

fn apply_random_setup_availability(
    mut commands: Commands,
    instances: Res<StartupScreenInstances>,
    dialog: Res<PlanetSeedDialog>,
    widgets: Query<(Entity, &ViewInstanceId, &WidgetTag), With<InteractiveUiWidget>>,
) {
    let Some(random_setup) = instances.random_setup else {
        return;
    };
    for (entity, instance, tag) in &widgets {
        if *instance == random_setup && matches!(tag.0.0.as_str(), "key " | "cncl") {
            if dialog.active {
                commands.entity(entity).insert(InteractionDisabled);
            } else {
                commands.entity(entity).remove::<InteractionDisabled>();
            }
        }
    }
}

fn translate_startup_intents(
    mut intents: MessageReader<UiIntent>,
    instances: Res<StartupScreenInstances>,
    state: Res<State<AppState>>,
    mut next_state: ResMut<NextState<AppState>>,
    mut random_setup: RandomSetupInteraction,
    mut exit: MessageWriter<AppExit>,
) {
    for intent in intents.read() {
        let UiIntent::Activated { view, tag } = intent;
        if *state.get() == AppState::MainMenu && instances.main_menu == Some(*view) {
            match tag.0.as_str() {
                "rand" => next_state.set(AppState::RandomSetup),
                "quit" => {
                    exit.write(AppExit::Success);
                }
                _ => {}
            }
            continue;
        }
        if *state.get() != AppState::RandomSetup {
            continue;
        }
        if instances.random_setup == Some(*view) {
            if !random_setup.dialog.active {
                if tag.0 == "cncl" {
                    next_state.set(AppState::MainMenu);
                } else {
                    apply_random_setup_intent(
                        random_setup.clock_seed.0,
                        &mut random_setup.setup,
                        &mut random_setup.preview,
                        &mut random_setup.edit_focus,
                        &mut random_setup.dialog,
                        &mut random_setup.spawn,
                        tag.0.as_str(),
                    );
                }
            }
            continue;
        }
        if random_setup.dialog.instance == Some(*view) {
            apply_planet_seed_dialog_intent(
                random_setup.clock_seed.0,
                &mut random_setup.setup,
                &mut random_setup.preview,
                &mut random_setup.edit_focus,
                &mut random_setup.dialog,
                &mut random_setup.despawn,
                tag.0.as_str(),
            );
        }
    }
}

fn apply_random_setup_intent(
    clock_seed: u32,
    setup: &mut RandomGameSetup,
    preview: &mut RandomSetupPreview,
    edit_focus: &mut RandomSetupEditFocus,
    dialog: &mut PlanetSeedDialog,
    spawn: &mut MessageWriter<SpawnUiView>,
    tag: &str,
) {
    match tag {
        "dif0" => setup.difficulty = 0,
        "dif1" => setup.difficulty = 1,
        "dif2" => setup.difficulty = 2,
        "dif3" => setup.difficulty = 3,
        "dif4" => setup.difficulty = 4,
        "hist" => setup.localized_names = true,
        "rand" => setup.localized_names = false,
        "glob" => regenerate_random_setup_planet(clock_seed, setup, preview),
        "coun" => edit_focus.0 = Some(RandomSetupEditTarget::CountryName),
        "key " => open_planet_seed_dialog(setup, edit_focus, dialog, spawn),
        _ => {}
    }
}

fn regenerate_random_setup_planet(
    clock_seed: u32,
    setup: &mut RandomGameSetup,
    preview: &mut RandomSetupPreview,
) {
    // A completed retail map build resets the zone/status generator from the
    // clock.  Globe activation starts a new mapped-name draw from that reset
    // state rather than continuing the country-name stream.
    let mut name_rng = RetailLcg::from_state(clock_seed);
    setup.planet_seed = generate_english_random_setup_name(&mut name_rng);
    update_random_setup_preview(
        preview,
        generate_random_setup_preview_with_clock_seed(
            setup.planet_seed.as_bytes(),
            setup.topology,
            clock_seed,
        ),
    );
}

fn open_planet_seed_dialog(
    setup: &RandomGameSetup,
    edit_focus: &mut RandomSetupEditFocus,
    dialog: &mut PlanetSeedDialog,
    spawn: &mut MessageWriter<SpawnUiView>,
) {
    if dialog.active {
        return;
    }
    dialog.active = true;
    dialog.draft.clone_from(&setup.planet_seed);
    dialog.selected_on_open = true;
    edit_focus.0 = Some(RandomSetupEditTarget::PlanetSeed);
    spawn.write(SpawnUiView(planet_seed_dialog_view_id()));
}

fn apply_planet_seed_dialog_intent(
    clock_seed: u32,
    setup: &mut RandomGameSetup,
    preview: &mut RandomSetupPreview,
    edit_focus: &mut RandomSetupEditFocus,
    dialog: &mut PlanetSeedDialog,
    despawn: &mut MessageWriter<DespawnUiView>,
    tag: &str,
) {
    match tag {
        "plan" => edit_focus.0 = Some(RandomSetupEditTarget::PlanetSeed),
        "okay" => {
            accept_planet_seed_dialog(clock_seed, setup, preview, edit_focus, dialog, despawn)
        }
        _ => {}
    }
}

fn accept_planet_seed_dialog(
    clock_seed: u32,
    setup: &mut RandomGameSetup,
    preview: &mut RandomSetupPreview,
    edit_focus: &mut RandomSetupEditFocus,
    dialog: &mut PlanetSeedDialog,
    despawn: &mut MessageWriter<DespawnUiView>,
) {
    if !dialog.draft.is_empty() && dialog.draft != setup.planet_seed {
        setup.planet_seed.clone_from(&dialog.draft);
        update_random_setup_preview(
            preview,
            generate_random_setup_preview_with_clock_seed(
                setup.planet_seed.as_bytes(),
                setup.topology,
                clock_seed,
            ),
        );
    }
    dismiss_planet_seed_dialog(dialog, edit_focus, despawn);
}

fn update_random_setup_preview(
    preview: &mut RandomSetupPreview,
    generated: GeneratedRandomSetupPreview,
) {
    preview.preview = Some(generated);
}

fn dismiss_planet_seed_dialog(
    dialog: &mut PlanetSeedDialog,
    edit_focus: &mut RandomSetupEditFocus,
    despawn: &mut MessageWriter<DespawnUiView>,
) {
    if let Some(instance) = dialog.instance.take() {
        despawn.write(DespawnUiView(instance));
    }
    dialog.active = false;
    dialog.selected_on_open = false;
    edit_focus.0 = None;
}

fn edit_random_setup_text(
    mut keyboard: MessageReader<KeyboardInput>,
    state: Res<State<AppState>>,
    mut random_setup: RandomSetupTextInput,
) {
    if *state.get() != AppState::RandomSetup {
        return;
    }
    for input in keyboard.read() {
        if input.state != ButtonState::Pressed {
            continue;
        }
        let Some(target) = random_setup.edit_focus.0 else {
            continue;
        };
        match input.key_code {
            KeyCode::Backspace => match target {
                RandomSetupEditTarget::CountryName => {
                    random_setup.setup.country_name.pop();
                }
                RandomSetupEditTarget::PlanetSeed => {
                    if random_setup.dialog.selected_on_open {
                        random_setup.dialog.draft.clear();
                        random_setup.dialog.selected_on_open = false;
                    } else {
                        random_setup.dialog.draft.pop();
                    }
                }
            },
            KeyCode::Enter | KeyCode::NumpadEnter
                if target == RandomSetupEditTarget::PlanetSeed && random_setup.dialog.active =>
            {
                accept_planet_seed_dialog(
                    random_setup.clock_seed.0,
                    &mut random_setup.setup,
                    &mut random_setup.preview,
                    &mut random_setup.edit_focus,
                    &mut random_setup.dialog,
                    &mut random_setup.despawn,
                );
            }
            _ => {
                let Some(text) = input.text.as_deref() else {
                    continue;
                };
                match target {
                    RandomSetupEditTarget::CountryName => append_visible_text(
                        &mut random_setup.setup.country_name,
                        text,
                        COUNTRY_NAME_MAX_CHARS,
                    ),
                    RandomSetupEditTarget::PlanetSeed if random_setup.dialog.active => {
                        if random_setup.dialog.selected_on_open {
                            random_setup.dialog.draft.clear();
                            random_setup.dialog.selected_on_open = false;
                        }
                        append_visible_text(
                            &mut random_setup.dialog.draft,
                            text,
                            PLANET_SEED_MAX_CHARS,
                        )
                    }
                    RandomSetupEditTarget::PlanetSeed => {}
                }
            }
        }
    }
}

fn append_visible_text(destination: &mut String, text: &str, max_chars: usize) {
    for character in text.chars().filter(|character| !character.is_control()) {
        if destination.chars().count() == max_chars {
            break;
        }
        destination.push(character);
    }
}

fn sync_random_setup_edit_text(
    instances: Res<StartupScreenInstances>,
    setup: Res<RandomGameSetup>,
    dialog: Res<PlanetSeedDialog>,
    mut text_nodes: Query<(&ViewInstanceId, &WidgetTag, &mut Text)>,
) {
    for (instance, tag, mut text) in &mut text_nodes {
        let replacement = if instances.random_setup == Some(*instance) && tag.0.0 == "coun" {
            Some(&setup.country_name)
        } else if dialog.instance == Some(*instance) && tag.0.0 == "plan" {
            Some(&dialog.draft)
        } else {
            None
        };
        if let Some(replacement) = replacement
            && text.0 != *replacement
        {
            text.0.clone_from(replacement);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{PresentedViewId, UiCatalogResource, UiRuntimePlugin, UiViewRoot};
    use bevy::ecs::message::{MessageCursor, Messages};
    use bevy::input::keyboard::Key;
    use imperialism_formats::{FourCc, UiCatalog};
    use std::collections::HashMap;

    const CATALOG_JSON: &str = include_str!("../../../imperialism-formats/assets/ui_catalog.json");

    fn app() -> App {
        let catalog = serde_json::from_str::<UiCatalog>(CATALOG_JSON).unwrap();
        let mut app = App::new();
        app.insert_resource(UiCatalogResource::new(catalog))
            .insert_resource(RandomSetupClockSeed(1))
            .add_plugins(bevy::state::app::StatesPlugin)
            .init_state::<AppState>()
            .configure_sets(
                Update,
                (
                    GameLoopSet::TranslateUiIntents,
                    GameLoopSet::UpdatePresentation,
                )
                    .chain(),
            )
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

    fn enter_random_setup(app: &mut App) -> ViewInstanceId {
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
        app.world()
            .resource::<StartupScreenInstances>()
            .random_setup()
            .unwrap()
    }

    fn pressed_text(text: &str) -> KeyboardInput {
        KeyboardInput {
            key_code: KeyCode::KeyA,
            logical_key: Key::Character(text.into()),
            state: ButtonState::Pressed,
            text: Some(text.into()),
            repeat: false,
            window: Entity::PLACEHOLDER,
        }
    }

    fn pressed_key(key_code: KeyCode, logical_key: Key) -> KeyboardInput {
        KeyboardInput {
            key_code,
            logical_key,
            state: ButtonState::Pressed,
            text: None,
            repeat: false,
            window: Entity::PLACEHOLDER,
        }
    }

    #[test]
    fn main_menu_enables_only_random_and_quit_without_hiding_other_choices() {
        let mut app = app();
        let menu = app
            .world()
            .resource::<StartupScreenInstances>()
            .main_menu()
            .unwrap();
        let world = app.world_mut();
        let widgets = world
            .query::<(
                Entity,
                &ViewInstanceId,
                &WidgetTag,
                &Node,
                Option<&InteractionDisabled>,
            )>()
            .iter(world)
            .filter(|(_, instance, _, _, _)| **instance == menu)
            .map(|(entity, _, tag, node, disabled)| {
                (tag.0.0.clone(), (entity, node.display, disabled.is_some()))
            })
            .collect::<HashMap<_, _>>();
        for tag in ["rand", "quit"] {
            let (_, display, disabled) = widgets[tag];
            assert_eq!(display, Display::Flex);
            assert!(!disabled);
        }
        for tag in ["load", "mult", "high", "scen", "pref"] {
            let (_, display, disabled) = widgets[tag];
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
    fn random_setup_activated_intents_update_the_app_draft() {
        let mut app = app();
        let setup = enter_random_setup(&mut app);
        for tag in ["dif3", "hist", "okay"] {
            app.world_mut()
                .write_message(UiIntent::Activated {
                    view: setup,
                    tag: FourCc(tag.to_owned()),
                })
                .unwrap();
        }
        app.update();
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::RandomSetup
        );
        assert_eq!(
            app.world().resource::<RandomGameSetup>(),
            &RandomGameSetup {
                planet_seed: "Woopnist".to_owned(),
                topology: RetailTopologyByte::from_wraps_horizontally(true),
                nation: MajorNationId::new(6),
                country_name: "Purtast".to_owned(),
                difficulty: 3,
                localized_names: true,
            }
        );
    }

    #[test]
    fn random_setup_entry_uses_the_retail_clock_seeded_defaults() {
        let mut app = app();
        enter_random_setup(&mut app);

        let setup = app.world().resource::<RandomGameSetup>();
        assert_eq!(
            setup,
            &RandomGameSetup {
                planet_seed: "Woopnist".to_owned(),
                topology: RetailTopologyByte::from_wraps_horizontally(true),
                nation: MajorNationId::new(6),
                country_name: "Purtast".to_owned(),
                difficulty: 0,
                localized_names: true,
            }
        );
        assert_eq!(
            app.world().resource::<RandomSetupPreview>().preview,
            Some(generate_random_setup_preview_with_clock_seed(
                b"Woopnist",
                RetailTopologyByte::from_wraps_horizontally(true),
                1,
            ))
        );
    }

    #[test]
    fn globe_regenerates_the_planet_from_the_reset_clock_seed() {
        let mut app = app();
        let setup_view = enter_random_setup(&mut app);
        let globe_is_interactive = {
            let world = app.world_mut();
            world
                .query_filtered::<(&ViewInstanceId, &WidgetTag), With<InteractiveUiWidget>>()
                .iter(world)
                .any(|(instance, tag)| *instance == setup_view && tag.0.0 == "glob")
        };
        assert!(globe_is_interactive);
        {
            let mut setup = app.world_mut().resource_mut::<RandomGameSetup>();
            setup.planet_seed = "manual planet".to_owned();
            setup.nation = MajorNationId::new(2);
            setup.country_name = "Custom Name".to_owned();
            setup.difficulty = 4;
            setup.localized_names = false;
        }

        app.world_mut()
            .write_message(UiIntent::Activated {
                view: setup_view,
                tag: FourCc("glob".to_owned()),
            })
            .unwrap();
        app.update();

        assert_eq!(
            app.world().resource::<RandomGameSetup>(),
            &RandomGameSetup {
                // The completed preview reset retail's zone/status LCG, so
                // this is a fresh seed-1 draw rather than the next fallback
                // name after the country default.
                planet_seed: "Woopnist".to_owned(),
                topology: RetailTopologyByte::from_wraps_horizontally(true),
                nation: MajorNationId::new(2),
                country_name: "Custom Name".to_owned(),
                difficulty: 4,
                localized_names: false,
            }
        );
        assert_eq!(
            app.world().resource::<RandomSetupPreview>().preview,
            Some(generate_random_setup_preview_with_clock_seed(
                b"Woopnist",
                RetailTopologyByte::from_wraps_horizontally(true),
                1,
            ))
        );
    }

    #[test]
    fn country_name_editing_uses_the_retail_twelve_character_limit() {
        let mut app = app();
        let setup_view = enter_random_setup(&mut app);
        app.world_mut()
            .write_message(UiIntent::Activated {
                view: setup_view,
                tag: FourCc("coun".to_owned()),
            })
            .unwrap();
        app.update();
        app.world_mut()
            .write_message(pressed_text("abcdefghijklmnop"))
            .unwrap();
        app.update();
        assert_eq!(
            app.world().resource::<RandomGameSetup>().country_name,
            "Purtastabcde"
        );

        app.world_mut()
            .write_message(pressed_key(KeyCode::Backspace, Key::Backspace))
            .unwrap();
        app.update();
        assert_eq!(
            app.world().resource::<RandomGameSetup>().country_name,
            "Purtastabcd"
        );
    }

    #[test]
    fn random_setup_cancel_returns_to_the_main_menu() {
        let mut app = app();
        let setup_view = enter_random_setup(&mut app);
        let world = app.world_mut();
        let cancel_disabled = world
            .query::<(&ViewInstanceId, &WidgetTag, Option<&InteractionDisabled>)>()
            .iter(world)
            .find(|(instance, tag, _)| **instance == setup_view && tag.0.0 == "cncl")
            .map(|(_, _, disabled)| disabled.is_some())
            .unwrap();
        assert!(!cancel_disabled);

        app.world_mut()
            .write_message(UiIntent::Activated {
                view: setup_view,
                tag: FourCc("cncl".to_owned()),
            })
            .unwrap();
        app.update();
        app.update();

        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::MainMenu
        );
        let roots = startup_roots(&mut app);
        assert!(roots.contains_key(&main_menu_view_id()));
        assert!(!roots.contains_key(&random_setup_view_id()));
    }

    #[test]
    fn planet_seed_dialog_accepts_a_changed_nonempty_seed_and_updates_the_preview() {
        let mut app = app();
        let setup_view = enter_random_setup(&mut app);
        app.world_mut()
            .resource_mut::<RandomGameSetup>()
            .planet_seed = "previous".to_owned();
        let world = app.world_mut();
        let key_disabled = world
            .query::<(&ViewInstanceId, &WidgetTag, Option<&InteractionDisabled>)>()
            .iter(world)
            .find(|(instance, tag, _)| **instance == setup_view && tag.0.0 == "key ")
            .map(|(_, _, disabled)| disabled.is_some())
            .unwrap();
        assert!(!key_disabled);

        app.world_mut()
            .write_message(UiIntent::Activated {
                view: setup_view,
                tag: FourCc("key ".to_owned()),
            })
            .unwrap();
        app.update();
        app.update();
        let dialog_view = app.world().resource::<PlanetSeedDialog>().instance.unwrap();
        assert!(app.world().resource::<PlanetSeedDialog>().active);
        assert_eq!(app.world().resource::<PlanetSeedDialog>().draft, "previous");
        assert!(startup_roots(&mut app).contains_key(&planet_seed_dialog_view_id()));

        app.world_mut()
            .write_message(pressed_key(KeyCode::Escape, Key::Escape))
            .unwrap();
        app.update();
        assert!(app.world().resource::<PlanetSeedDialog>().active);

        app.world_mut()
            .write_message(pressed_text("ordinary"))
            .unwrap();
        app.update();
        assert_eq!(app.world().resource::<PlanetSeedDialog>().draft, "ordinary");

        app.world_mut()
            .write_message(UiIntent::Activated {
                view: dialog_view,
                tag: FourCc("okay".to_owned()),
            })
            .unwrap();
        app.update();
        assert_eq!(
            app.world().resource::<RandomGameSetup>().planet_seed,
            "ordinary"
        );
        let preview = app.world().resource::<RandomSetupPreview>();
        assert!(preview.preview.is_some());
        assert!(!app.world().resource::<PlanetSeedDialog>().active);
    }

    #[test]
    fn empty_or_unchanged_planet_seed_does_not_generate_a_preview() {
        let mut app = app();
        let setup_view = enter_random_setup(&mut app);
        let existing_preview = app.world().resource::<RandomSetupPreview>().clone();
        app.world_mut()
            .resource_mut::<RandomGameSetup>()
            .planet_seed = "ordinary".to_owned();
        app.world_mut()
            .write_message(UiIntent::Activated {
                view: setup_view,
                tag: FourCc("key ".to_owned()),
            })
            .unwrap();
        app.update();
        app.update();
        let dialog_view = app.world().resource::<PlanetSeedDialog>().instance.unwrap();
        app.world_mut()
            .write_message(UiIntent::Activated {
                view: dialog_view,
                tag: FourCc("okay".to_owned()),
            })
            .unwrap();
        app.update();

        assert_eq!(
            app.world().resource::<RandomGameSetup>().planet_seed,
            "ordinary"
        );
        assert_eq!(
            app.world().resource::<RandomSetupPreview>(),
            &existing_preview
        );

        app.world_mut()
            .write_message(UiIntent::Activated {
                view: setup_view,
                tag: FourCc("key ".to_owned()),
            })
            .unwrap();
        app.update();
        app.update();
        let dialog_view = app.world().resource::<PlanetSeedDialog>().instance.unwrap();
        for _ in "ordinary".chars() {
            app.world_mut()
                .write_message(pressed_key(KeyCode::Backspace, Key::Backspace))
                .unwrap();
        }
        app.update();
        assert!(app.world().resource::<PlanetSeedDialog>().draft.is_empty());
        app.world_mut()
            .write_message(UiIntent::Activated {
                view: dialog_view,
                tag: FourCc("okay".to_owned()),
            })
            .unwrap();
        app.update();
        assert_eq!(
            app.world().resource::<RandomGameSetup>().planet_seed,
            "ordinary"
        );
        assert_eq!(
            app.world().resource::<RandomSetupPreview>(),
            &existing_preview
        );
    }
}
