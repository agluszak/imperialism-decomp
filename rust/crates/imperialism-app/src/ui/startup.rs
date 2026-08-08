use crate::AppState;
use crate::ui::{SpawnedView, UiActivated, UiCatalogResource, UiPictureResources, spawn_view};
use bevy::app::AppExit;
use bevy::ecs::system::SystemParam;
use bevy::input::ButtonState;
use bevy::input::keyboard::KeyboardInput;
use bevy::prelude::*;
use bevy::ui::InteractionDisabled;
use imperialism_core::{
    Difficulty, GameState, MajorNationId, RandomSetupPreview as GeneratedRandomSetupPreview,
    RetailCrtRng, RetailLcg, RetailTopologyByte, create_random_game,
    generate_english_random_setup_name, generate_random_setup_preview_with_clock_seed,
};
use imperialism_formats::{ScopedViewId, UiView as CatalogView};
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
            difficulty: Difficulty::Introductory,
            localized_names: false,
        }
    }
}

/// Authoritative game state produced when Random Setup Accept/Okay succeeds.
#[derive(Resource, Clone, Debug, Eq, PartialEq)]
pub(crate) struct GameSession(pub GameState);

/// The generated map data owned by the setup screen.
#[derive(Resource, Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct RandomSetupPreview {
    pub(crate) preview: Option<GeneratedRandomSetupPreview>,
}

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
enum PlanetSeedDialog {
    #[default]
    Closed,
    Open {
        root: Entity,
        plan_text: Entity,
        draft: String,
        replace_on_next_input: bool,
    },
}

#[derive(Resource, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct StartupScreenInstances {
    main_menu: Option<Entity>,
    random_setup: Option<Entity>,
}

impl StartupScreenInstances {
    #[cfg(test)]
    pub(crate) const fn main_menu(self) -> Option<Entity> {
        self.main_menu
    }

    #[cfg(test)]
    pub(crate) const fn random_setup(self) -> Option<Entity> {
        self.random_setup
    }
}

#[derive(Resource, Clone, Copy, Debug, Eq, PartialEq)]
struct RandomSetupControls {
    key_button: Entity,
    cancel_button: Entity,
    country_text: Entity,
}

/// Set when Random Setup requests the planet-seed dialog; consumed by
/// [`open_planet_seed_dialog`], which needs retail picture/font binding.
#[derive(Resource, Clone, Copy, Debug, Default, Eq, PartialEq)]
struct OpenPlanetSeedPending;

#[derive(SystemParam)]
struct RandomSetupInteraction<'w, 's> {
    clock_seed: Res<'w, RandomSetupClockSeed>,
    setup: ResMut<'w, RandomGameSetup>,
    preview: ResMut<'w, RandomSetupPreview>,
    edit_focus: ResMut<'w, RandomSetupEditFocus>,
    dialog: ResMut<'w, PlanetSeedDialog>,
    controls: Option<Res<'w, RandomSetupControls>>,
    commands: Commands<'w, 's>,
}

#[derive(SystemParam)]
struct RandomSetupTextInput<'w, 's> {
    clock_seed: Res<'w, RandomSetupClockSeed>,
    setup: ResMut<'w, RandomGameSetup>,
    preview: ResMut<'w, RandomSetupPreview>,
    edit_focus: ResMut<'w, RandomSetupEditFocus>,
    dialog: ResMut<'w, PlanetSeedDialog>,
    controls: Option<Res<'w, RandomSetupControls>>,
    commands: Commands<'w, 's>,
}

pub(crate) struct StartupUiPlugin;

impl Plugin for StartupUiPlugin {
    fn build(&self, app: &mut App) {
        register_startup_logic(app);
        app.add_systems(OnEnter(AppState::MainMenu), enter_main_menu)
            .add_systems(OnExit(AppState::MainMenu), exit_main_menu)
            .add_systems(
                OnEnter(AppState::RandomSetup),
                (initialize_random_setup, enter_random_setup).chain(),
            )
            .add_systems(OnExit(AppState::RandomSetup), exit_random_setup);
    }
}

fn register_startup_logic(app: &mut App) {
    app.init_resource::<StartupScreenInstances>()
        .init_resource::<RandomGameSetup>()
        .init_resource::<RandomSetupPreview>()
        .init_resource::<RandomSetupClockSeed>()
        .init_resource::<RandomSetupEditFocus>()
        .init_resource::<PlanetSeedDialog>()
        .add_systems(
            Update,
            (
                translate_startup_activations,
                open_planet_seed_dialog.run_if(resource_exists::<OpenPlanetSeedPending>),
                edit_random_setup_text,
                sync_random_setup_edit_text,
            )
                .chain(),
        );
}

fn enter_main_menu(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut pictures: UiPictureResources,
    mut instances: ResMut<StartupScreenInstances>,
) {
    let Some(spawned) = spawn_view(
        &mut commands,
        catalog.catalog(),
        &main_menu_view_id(),
        &mut pictures,
    ) else {
        return;
    };
    let view = catalog
        .catalog()
        .views
        .iter()
        .find(|view| view.id == main_menu_view_id())
        .expect("main menu view was just spawned");
    apply_main_menu_availability(&mut commands, view, &spawned);
    instances.main_menu = Some(spawned.root);
}

fn exit_main_menu(mut commands: Commands, mut instances: ResMut<StartupScreenInstances>) {
    if let Some(root) = instances.main_menu.take() {
        commands.entity(root).despawn();
    }
}

fn initialize_random_setup(
    clock_seed: Res<RandomSetupClockSeed>,
    mut setup: ResMut<RandomGameSetup>,
    mut preview: ResMut<RandomSetupPreview>,
) {
    if !setup.planet_seed.is_empty() {
        return;
    }

    let mut crt_rng = RetailCrtRng::from_state(clock_seed.0);
    let nation = MajorNationId::new((crt_rng.next_rand() % i32::from(MajorNationId::COUNT)) as u8);
    let mut name_rng = RetailLcg::from_state(clock_seed.0);
    let planet_seed = generate_english_random_setup_name(&mut name_rng);
    let country_name = generate_english_random_setup_name(&mut name_rng);
    let topology = RetailTopologyByte::from_wraps_horizontally(true);

    *setup = RandomGameSetup {
        planet_seed,
        topology,
        nation,
        country_name,
        difficulty: Difficulty::Introductory,
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

fn enter_random_setup(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut pictures: UiPictureResources,
    mut instances: ResMut<StartupScreenInstances>,
) {
    let Some(spawned) = spawn_view(
        &mut commands,
        catalog.catalog(),
        &random_setup_view_id(),
        &mut pictures,
    ) else {
        return;
    };
    let view = catalog
        .catalog()
        .views
        .iter()
        .find(|view| view.id == random_setup_view_id())
        .expect("random setup view was just spawned");
    crate::ui::map_preview::attach_random_setup_widgets(&mut commands, view, &spawned);
    let Some(key_button) = spawned.tagged(view, "key ") else {
        return;
    };
    let Some(cancel_button) = spawned.tagged(view, "cncl") else {
        return;
    };
    let Some(country_text) = spawned.tagged(view, "coun") else {
        return;
    };
    let controls = RandomSetupControls {
        key_button,
        cancel_button,
        country_text,
    };
    set_random_setup_dialog_gates(&mut commands, &controls, false);
    commands.insert_resource(controls);
    instances.random_setup = Some(spawned.root);
}

fn exit_random_setup(
    mut commands: Commands,
    mut instances: ResMut<StartupScreenInstances>,
    mut dialog: ResMut<PlanetSeedDialog>,
    mut edit_focus: ResMut<RandomSetupEditFocus>,
) {
    if let Some(root) = instances.random_setup.take() {
        commands.entity(root).despawn();
    }
    dismiss_planet_seed_dialog(&mut commands, &mut dialog, &mut edit_focus);
    commands.remove_resource::<RandomSetupControls>();
}

fn apply_main_menu_availability(
    commands: &mut Commands,
    view: &CatalogView,
    spawned: &SpawnedView,
) {
    for node in &view.nodes {
        if !node.interactive {
            continue;
        }
        let entity = spawned.nodes[&node.id];
        if matches!(node.tag.0.as_str(), "rand" | "quit") {
            commands.entity(entity).remove::<InteractionDisabled>();
        } else {
            commands.entity(entity).insert(InteractionDisabled);
        }
    }
}

fn set_random_setup_dialog_gates(
    commands: &mut Commands,
    controls: &RandomSetupControls,
    open: bool,
) {
    for entity in [controls.key_button, controls.cancel_button] {
        if open {
            commands.entity(entity).insert(InteractionDisabled);
        } else {
            commands.entity(entity).remove::<InteractionDisabled>();
        }
    }
}

fn translate_startup_activations(
    mut activations: MessageReader<UiActivated>,
    instances: Res<StartupScreenInstances>,
    state: Res<State<AppState>>,
    mut next_state: ResMut<NextState<AppState>>,
    mut random_setup: RandomSetupInteraction,
    mut exit: MessageWriter<AppExit>,
) {
    for activation in activations.read() {
        if *state.get() == AppState::MainMenu && instances.main_menu == Some(activation.view) {
            match activation.tag.0.as_str() {
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
        if instances.random_setup == Some(activation.view) {
            if matches!(&*random_setup.dialog, PlanetSeedDialog::Closed) {
                if activation.tag.0 == "cncl" {
                    next_state.set(AppState::MainMenu);
                } else if activation.tag.0 == "okay" {
                    accept_random_setup(
                        &random_setup.setup,
                        &random_setup.preview,
                        &mut random_setup.commands,
                    );
                } else {
                    apply_random_setup_intent(&mut random_setup, activation.tag.0.as_str());
                }
            }
            continue;
        }
        if let PlanetSeedDialog::Open { root, .. } = &*random_setup.dialog
            && activation.view == *root
        {
            apply_planet_seed_dialog_intent(&mut random_setup, activation.tag.0.as_str());
        }
    }
}

fn apply_random_setup_intent(random_setup: &mut RandomSetupInteraction, tag: &str) {
    match tag {
        "dif0" => random_setup.setup.difficulty = Difficulty::Introductory,
        "dif1" => random_setup.setup.difficulty = Difficulty::Easy,
        "dif2" => random_setup.setup.difficulty = Difficulty::Normal,
        "dif3" => random_setup.setup.difficulty = Difficulty::Hard,
        "dif4" => random_setup.setup.difficulty = Difficulty::NighOnImpossible,
        "hist" => random_setup.setup.localized_names = true,
        "rand" => random_setup.setup.localized_names = false,
        "glob" => regenerate_random_setup_planet(
            random_setup.clock_seed.0,
            &mut random_setup.setup,
            &mut random_setup.preview,
        ),
        "coun" => random_setup.edit_focus.0 = Some(RandomSetupEditTarget::CountryName),
        "key " => {
            random_setup.commands.insert_resource(OpenPlanetSeedPending);
        }
        _ => {}
    }
}

fn accept_random_setup(
    setup: &RandomGameSetup,
    preview: &RandomSetupPreview,
    commands: &mut Commands,
) {
    let Some(generated) = preview.preview.as_ref() else {
        return;
    };
    commands.insert_resource(GameSession(create_random_game(
        generated,
        setup.nation,
        setup.difficulty,
    )));
}

fn regenerate_random_setup_planet(
    clock_seed: u32,
    setup: &mut RandomGameSetup,
    preview: &mut RandomSetupPreview,
) {
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
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut pictures: UiPictureResources,
    setup: Res<RandomGameSetup>,
    mut edit_focus: ResMut<RandomSetupEditFocus>,
    mut dialog: ResMut<PlanetSeedDialog>,
    controls: Option<Res<RandomSetupControls>>,
) {
    commands.remove_resource::<OpenPlanetSeedPending>();
    if !matches!(*dialog, PlanetSeedDialog::Closed) {
        return;
    }
    let Some(spawned) = spawn_view(
        &mut commands,
        catalog.catalog(),
        &planet_seed_dialog_view_id(),
        &mut pictures,
    ) else {
        return;
    };
    let view = catalog
        .catalog()
        .views
        .iter()
        .find(|view| view.id == planet_seed_dialog_view_id())
        .expect("planet seed dialog was just spawned");
    let Some(plan_text) = spawned.tagged(view, "plan") else {
        commands.entity(spawned.root).despawn();
        return;
    };
    if let Some(controls) = controls.as_deref() {
        set_random_setup_dialog_gates(&mut commands, controls, true);
    }
    edit_focus.0 = Some(RandomSetupEditTarget::PlanetSeed);
    *dialog = PlanetSeedDialog::Open {
        root: spawned.root,
        plan_text,
        draft: setup.planet_seed.clone(),
        replace_on_next_input: true,
    };
}

fn apply_planet_seed_dialog_intent(random_setup: &mut RandomSetupInteraction, tag: &str) {
    match tag {
        "plan" => random_setup.edit_focus.0 = Some(RandomSetupEditTarget::PlanetSeed),
        "okay" => accept_planet_seed_dialog(random_setup),
        _ => {}
    }
}

fn accept_planet_seed_dialog(random_setup: &mut RandomSetupInteraction) {
    let PlanetSeedDialog::Open { draft, .. } = &*random_setup.dialog else {
        return;
    };
    if !draft.is_empty() && draft != &random_setup.setup.planet_seed {
        random_setup.setup.planet_seed.clone_from(draft);
        update_random_setup_preview(
            &mut random_setup.preview,
            generate_random_setup_preview_with_clock_seed(
                random_setup.setup.planet_seed.as_bytes(),
                random_setup.setup.topology,
                random_setup.clock_seed.0,
            ),
        );
    }
    dismiss_planet_seed_dialog(
        &mut random_setup.commands,
        &mut random_setup.dialog,
        &mut random_setup.edit_focus,
    );
    if let Some(controls) = random_setup.controls.as_deref() {
        set_random_setup_dialog_gates(&mut random_setup.commands, controls, false);
    }
}

fn update_random_setup_preview(
    preview: &mut RandomSetupPreview,
    generated: GeneratedRandomSetupPreview,
) {
    preview.preview = Some(generated);
}

fn dismiss_planet_seed_dialog(
    commands: &mut Commands,
    dialog: &mut PlanetSeedDialog,
    edit_focus: &mut RandomSetupEditFocus,
) {
    if let PlanetSeedDialog::Open { root, .. } = dialog {
        commands.entity(*root).despawn();
    }
    *dialog = PlanetSeedDialog::Closed;
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
            KeyCode::Backspace => match (&mut *random_setup.dialog, target) {
                (_, RandomSetupEditTarget::CountryName) => {
                    random_setup.setup.country_name.pop();
                }
                (
                    PlanetSeedDialog::Open {
                        draft,
                        replace_on_next_input,
                        ..
                    },
                    RandomSetupEditTarget::PlanetSeed,
                ) => {
                    if *replace_on_next_input {
                        draft.clear();
                        *replace_on_next_input = false;
                    } else {
                        draft.pop();
                    }
                }
                _ => {}
            },
            KeyCode::Enter | KeyCode::NumpadEnter
                if target == RandomSetupEditTarget::PlanetSeed
                    && matches!(&*random_setup.dialog, PlanetSeedDialog::Open { .. }) =>
            {
                let mut interaction = AcceptDialogParams {
                    clock_seed: random_setup.clock_seed.0,
                    setup: &mut random_setup.setup,
                    preview: &mut random_setup.preview,
                    edit_focus: &mut random_setup.edit_focus,
                    dialog: &mut random_setup.dialog,
                    controls: random_setup.controls.as_deref(),
                    commands: &mut random_setup.commands,
                };
                accept_planet_seed_dialog_params(&mut interaction);
            }
            _ => {
                let Some(text) = input.text.as_deref() else {
                    continue;
                };
                match (&mut *random_setup.dialog, target) {
                    (_, RandomSetupEditTarget::CountryName) => append_visible_text(
                        &mut random_setup.setup.country_name,
                        text,
                        COUNTRY_NAME_MAX_CHARS,
                    ),
                    (
                        PlanetSeedDialog::Open {
                            draft,
                            replace_on_next_input,
                            ..
                        },
                        RandomSetupEditTarget::PlanetSeed,
                    ) => {
                        if *replace_on_next_input {
                            draft.clear();
                            *replace_on_next_input = false;
                        }
                        append_visible_text(draft, text, PLANET_SEED_MAX_CHARS);
                    }
                    _ => {}
                }
            }
        }
    }
}

struct AcceptDialogParams<'a, 'w, 's> {
    clock_seed: u32,
    setup: &'a mut RandomGameSetup,
    preview: &'a mut RandomSetupPreview,
    edit_focus: &'a mut RandomSetupEditFocus,
    dialog: &'a mut PlanetSeedDialog,
    controls: Option<&'a RandomSetupControls>,
    commands: &'a mut Commands<'w, 's>,
}

fn accept_planet_seed_dialog_params(params: &mut AcceptDialogParams<'_, '_, '_>) {
    let PlanetSeedDialog::Open { draft, .. } = &*params.dialog else {
        return;
    };
    if !draft.is_empty() && draft != &params.setup.planet_seed {
        params.setup.planet_seed.clone_from(draft);
        update_random_setup_preview(
            params.preview,
            generate_random_setup_preview_with_clock_seed(
                params.setup.planet_seed.as_bytes(),
                params.setup.topology,
                params.clock_seed,
            ),
        );
    }
    dismiss_planet_seed_dialog(params.commands, params.dialog, params.edit_focus);
    if let Some(controls) = params.controls {
        set_random_setup_dialog_gates(params.commands, controls, false);
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
    setup: Res<RandomGameSetup>,
    dialog: Res<PlanetSeedDialog>,
    controls: Option<Res<RandomSetupControls>>,
    mut texts: Query<&mut Text>,
) {
    if let Some(controls) = controls.as_deref()
        && let Ok(mut text) = texts.get_mut(controls.country_text)
        && text.0 != setup.country_name
    {
        text.0.clone_from(&setup.country_name);
    }
    if let PlanetSeedDialog::Open {
        plan_text, draft, ..
    } = &*dialog
        && let Ok(mut text) = texts.get_mut(*plan_text)
        && text.0 != *draft
    {
        text.0.clone_from(draft);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::{
        PresentedViewId, UiRuntimePlugin, UiViewRoot, ViewRoot, WidgetTag, spawn_view_nodes,
    };
    use bevy::ecs::message::{MessageCursor, Messages};
    use bevy::input::keyboard::Key;
    use imperialism_core::NationId;
    use imperialism_formats::{FourCc, UiCatalog};
    use std::collections::HashMap;

    const CATALOG_JSON: &str = include_str!("../../../imperialism-formats/assets/ui_catalog.json");

    fn app() -> App {
        let catalog = serde_json::from_str::<UiCatalog>(CATALOG_JSON).unwrap();
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_message::<KeyboardInput>()
            .add_message::<AppExit>()
            .insert_resource(UiCatalogResource::new(catalog))
            .insert_resource(RandomSetupClockSeed(1))
            .add_plugins(bevy::state::app::StatesPlugin)
            .init_state::<AppState>()
            .add_plugins(UiRuntimePlugin);
        register_startup_logic(&mut app);
        app.add_systems(OnEnter(AppState::MainMenu), enter_main_menu_structure_only)
            .add_systems(OnExit(AppState::MainMenu), exit_main_menu)
            .add_systems(
                OnEnter(AppState::RandomSetup),
                (initialize_random_setup, enter_random_setup_structure_only).chain(),
            )
            .add_systems(OnExit(AppState::RandomSetup), exit_random_setup);
        app.update();
        app
    }

    fn enter_main_menu_structure_only(
        mut commands: Commands,
        catalog: Res<UiCatalogResource>,
        mut instances: ResMut<StartupScreenInstances>,
    ) {
        let view_id = main_menu_view_id();
        let catalog = catalog.catalog();
        let view = catalog
            .views
            .iter()
            .find(|view| view.id == view_id)
            .unwrap();
        let spawned = spawn_view_nodes(&mut commands, catalog.logical_resolution, view);
        apply_main_menu_availability(&mut commands, view, &spawned);
        instances.main_menu = Some(spawned.root);
    }

    fn enter_random_setup_structure_only(
        mut commands: Commands,
        catalog: Res<UiCatalogResource>,
        mut instances: ResMut<StartupScreenInstances>,
    ) {
        let view_id = random_setup_view_id();
        let catalog = catalog.catalog();
        let view = catalog
            .views
            .iter()
            .find(|view| view.id == view_id)
            .unwrap();
        let spawned = spawn_view_nodes(&mut commands, catalog.logical_resolution, view);
        crate::ui::map_preview::attach_random_setup_widgets(&mut commands, view, &spawned);
        let controls = RandomSetupControls {
            key_button: spawned.tagged(view, "key ").unwrap(),
            cancel_button: spawned.tagged(view, "cncl").unwrap(),
            country_text: spawned.tagged(view, "coun").unwrap(),
        };
        set_random_setup_dialog_gates(&mut commands, &controls, false);
        commands.insert_resource(controls);
        instances.random_setup = Some(spawned.root);
    }

    fn open_planet_seed_dialog_structure(app: &mut App) {
        let catalog = app
            .world()
            .resource::<UiCatalogResource>()
            .catalog()
            .clone();
        let view = catalog
            .views
            .iter()
            .find(|view| view.id == planet_seed_dialog_view_id())
            .unwrap()
            .clone();
        let planet_seed = app
            .world()
            .resource::<RandomGameSetup>()
            .planet_seed
            .clone();
        let controls = *app.world().resource::<RandomSetupControls>();
        let world = app.world_mut();
        let mut commands = world.commands();
        let spawned = spawn_view_nodes(&mut commands, catalog.logical_resolution, &view);
        let plan_text = spawned.tagged(&view, "plan").unwrap();
        commands
            .entity(plan_text)
            .insert(Text::new(planet_seed.clone()));
        set_random_setup_dialog_gates(&mut commands, &controls, true);
        world.flush();
        world.resource_mut::<RandomSetupEditFocus>().0 = Some(RandomSetupEditTarget::PlanetSeed);
        *world.resource_mut::<PlanetSeedDialog>() = PlanetSeedDialog::Open {
            root: spawned.root,
            plan_text,
            draft: planet_seed,
            replace_on_next_input: true,
        };
    }

    fn startup_roots(app: &mut App) -> HashMap<ScopedViewId, Entity> {
        let world = app.world_mut();
        world
            .query_filtered::<(Entity, &PresentedViewId), With<UiViewRoot>>()
            .iter(world)
            .map(|(entity, view)| (view.0.clone(), entity))
            .collect()
    }

    #[derive(Resource)]
    struct PressOnce(Entity);

    fn press_once(pressed: Res<PressOnce>, mut interactions: Query<&mut Interaction>) {
        *interactions.get_mut(pressed.0).unwrap() = Interaction::Pressed;
    }

    fn enter_random_setup_screen(app: &mut App) -> Entity {
        let menu = app
            .world()
            .resource::<StartupScreenInstances>()
            .main_menu()
            .unwrap();
        app.world_mut()
            .write_message(UiActivated {
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
                &ViewRoot,
                &WidgetTag,
                &Node,
                Option<&InteractionDisabled>,
            )>()
            .iter(world)
            .filter(|(_, root, _, _, _)| root.0 == menu)
            .map(|(_, _, tag, node, disabled)| {
                (tag.0.0.clone(), (node.display, disabled.is_some()))
            })
            .collect::<HashMap<_, _>>();
        for tag in ["rand", "quit"] {
            let (display, disabled) = widgets[tag];
            assert_eq!(display, Display::Flex);
            assert!(!disabled);
        }
        for tag in ["load", "mult", "high", "scen", "pref"] {
            let (display, disabled) = widgets[tag];
            assert_eq!(display, Display::Flex);
            assert!(disabled);
        }
    }

    #[test]
    fn disabled_choice_emits_no_activation_and_random_setup_replaces_only_the_menu() {
        let mut app = app();
        let flag_view = {
            let catalog = app
                .world()
                .resource::<UiCatalogResource>()
                .catalog()
                .clone();
            let view_id = ScopedViewId {
                resource_file: "FlagView.rsrc".to_owned(),
                resource_id: 8451,
            };
            let view = catalog
                .views
                .iter()
                .find(|view| view.id == view_id)
                .unwrap();
            let world = app.world_mut();
            let mut commands = world.commands();
            let spawned = spawn_view_nodes(&mut commands, catalog.logical_resolution, view);
            world.flush();
            spawned.root
        };
        let menu = app
            .world()
            .resource::<StartupScreenInstances>()
            .main_menu()
            .unwrap();
        let load = app
            .world_mut()
            .query::<(Entity, &ViewRoot, &WidgetTag)>()
            .iter(app.world())
            .find(|(_, root, tag)| root.0 == menu && tag.0.0 == "load")
            .map(|(entity, _, _)| entity)
            .unwrap();
        app.insert_resource(PressOnce(load))
            .add_systems(PreUpdate, press_once);
        let mut cursor = MessageCursor::<UiActivated>::default();
        app.update();
        assert_eq!(
            cursor
                .read(app.world().resource::<Messages<UiActivated>>())
                .count(),
            0
        );

        app.world_mut()
            .write_message(UiActivated {
                view: menu,
                tag: FourCc("rand".to_owned()),
            })
            .unwrap();
        app.update();
        app.update();
        let roots = startup_roots(&mut app);
        assert!(!roots.contains_key(&main_menu_view_id()));
        assert!(roots.contains_key(&random_setup_view_id()));
        assert!(app.world().get_entity(flag_view).is_ok());
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
            .write_message(UiActivated {
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
        let setup = enter_random_setup_screen(&mut app);
        for tag in ["dif3", "hist", "okay"] {
            app.world_mut()
                .write_message(UiActivated {
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
                difficulty: Difficulty::Hard,
                localized_names: true,
            }
        );
        let session = app.world().resource::<GameSession>();
        assert_eq!(session.0.turn.difficulty, Difficulty::Hard);
        assert_eq!(session.0.turn.selected_nation, NationId::new(6));
        assert_eq!(session.0.turn.phase_code, 2);
    }

    #[test]
    fn random_setup_entry_uses_the_retail_clock_seeded_defaults() {
        let mut app = app();
        enter_random_setup_screen(&mut app);

        let setup = app.world().resource::<RandomGameSetup>();
        assert_eq!(
            setup,
            &RandomGameSetup {
                planet_seed: "Woopnist".to_owned(),
                topology: RetailTopologyByte::from_wraps_horizontally(true),
                nation: MajorNationId::new(6),
                country_name: "Purtast".to_owned(),
                difficulty: Difficulty::Introductory,
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
        let setup_view = enter_random_setup_screen(&mut app);
        let globe_is_interactive = {
            let world = app.world_mut();
            world
                .query_filtered::<(&ViewRoot, &WidgetTag), With<Button>>()
                .iter(world)
                .any(|(root, tag)| root.0 == setup_view && tag.0.0 == "glob")
        };
        assert!(globe_is_interactive);
        {
            let mut setup = app.world_mut().resource_mut::<RandomGameSetup>();
            setup.planet_seed = "manual planet".to_owned();
            setup.nation = MajorNationId::new(2);
            setup.country_name = "Custom Name".to_owned();
            setup.difficulty = Difficulty::NighOnImpossible;
            setup.localized_names = false;
        }

        app.world_mut()
            .write_message(UiActivated {
                view: setup_view,
                tag: FourCc("glob".to_owned()),
            })
            .unwrap();
        app.update();

        assert_eq!(
            app.world().resource::<RandomGameSetup>(),
            &RandomGameSetup {
                planet_seed: "Woopnist".to_owned(),
                topology: RetailTopologyByte::from_wraps_horizontally(true),
                nation: MajorNationId::new(2),
                country_name: "Custom Name".to_owned(),
                difficulty: Difficulty::NighOnImpossible,
                localized_names: false,
            }
        );
    }

    #[test]
    fn country_name_editing_uses_the_retail_twelve_character_limit() {
        let mut app = app();
        let setup_view = enter_random_setup_screen(&mut app);
        app.world_mut()
            .write_message(UiActivated {
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
        let setup_view = enter_random_setup_screen(&mut app);
        app.world_mut()
            .write_message(UiActivated {
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
        let setup_view = enter_random_setup_screen(&mut app);
        app.world_mut()
            .resource_mut::<RandomGameSetup>()
            .planet_seed = "previous".to_owned();
        let key_disabled = {
            let controls = *app.world().resource::<RandomSetupControls>();
            app.world()
                .get::<InteractionDisabled>(controls.key_button)
                .is_some()
        };
        assert!(!key_disabled);

        open_planet_seed_dialog_structure(&mut app);
        let dialog_root = match *app.world().resource::<PlanetSeedDialog>() {
            PlanetSeedDialog::Open { root, .. } => root,
            PlanetSeedDialog::Closed => panic!("dialog should be open"),
        };
        assert_eq!(
            match app.world().resource::<PlanetSeedDialog>() {
                PlanetSeedDialog::Open { draft, .. } => draft.as_str(),
                PlanetSeedDialog::Closed => "",
            },
            "previous"
        );
        assert!(startup_roots(&mut app).contains_key(&planet_seed_dialog_view_id()));
        let key_button = app.world().resource::<RandomSetupControls>().key_button;
        assert!(app.world().get::<InteractionDisabled>(key_button).is_some());

        app.world_mut()
            .write_message(pressed_key(KeyCode::Escape, Key::Escape))
            .unwrap();
        app.update();
        assert!(matches!(
            *app.world().resource::<PlanetSeedDialog>(),
            PlanetSeedDialog::Open { .. }
        ));

        app.world_mut()
            .write_message(pressed_text("ordinary"))
            .unwrap();
        app.update();
        assert_eq!(
            match app.world().resource::<PlanetSeedDialog>() {
                PlanetSeedDialog::Open { draft, .. } => draft.as_str(),
                PlanetSeedDialog::Closed => "",
            },
            "ordinary"
        );

        app.world_mut()
            .write_message(UiActivated {
                view: dialog_root,
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
        assert!(matches!(
            *app.world().resource::<PlanetSeedDialog>(),
            PlanetSeedDialog::Closed
        ));
        let _ = setup_view;
    }

    #[test]
    fn empty_or_unchanged_planet_seed_does_not_generate_a_preview() {
        let mut app = app();
        let setup_view = enter_random_setup_screen(&mut app);
        let existing_preview = app.world().resource::<RandomSetupPreview>().clone();
        app.world_mut()
            .resource_mut::<RandomGameSetup>()
            .planet_seed = "ordinary".to_owned();
        open_planet_seed_dialog_structure(&mut app);
        let dialog_root = match *app.world().resource::<PlanetSeedDialog>() {
            PlanetSeedDialog::Open { root, .. } => root,
            PlanetSeedDialog::Closed => panic!("dialog should be open"),
        };
        app.world_mut()
            .write_message(UiActivated {
                view: dialog_root,
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

        open_planet_seed_dialog_structure(&mut app);
        let dialog_root = match *app.world().resource::<PlanetSeedDialog>() {
            PlanetSeedDialog::Open { root, .. } => root,
            PlanetSeedDialog::Closed => panic!("dialog should be open"),
        };
        for _ in "ordinary".chars() {
            app.world_mut()
                .write_message(pressed_key(KeyCode::Backspace, Key::Backspace))
                .unwrap();
        }
        app.update();
        assert!(matches!(
            app.world().resource::<PlanetSeedDialog>(),
            PlanetSeedDialog::Open { draft, .. } if draft.is_empty()
        ));
        app.world_mut()
            .write_message(UiActivated {
                view: dialog_root,
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
        let _ = setup_view;
    }
}
