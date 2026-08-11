use crate::AppState;
use crate::ui::catalog::{
    ModalDialog, SpawnedView, UiAssetResources, UiCatalogResource, UiSpawner, spawn_view,
};
use crate::ui::random_setup_map;
use bevy::ecs::system::SystemParam;
use bevy::input::ButtonState;
use bevy::input::keyboard::KeyboardInput;
use bevy::input_focus::AutoFocus;
use bevy::input_focus::tab_navigation::TabIndex;
use bevy::prelude::*;
use bevy::text::{EditableText, TextEditChange};
use bevy::ui::{Checked, InteractionDisabled};
use bevy::ui_widgets::{Activate, SelectAllOnFocus, ValueChange};
use imperialism_core::*;
use imperialism_formats::{OKAY, ScopedViewId, fourcc};
use std::time::{SystemTime, UNIX_EPOCH};

const STARTUP_RESOURCE_FILE: &str = "Startup.rsrc";
const RANDOM_SETUP_RESOURCE_ID: i16 = 1501;
const PLANET_SEED_RESOURCE_FILE: &str = "Linger.rsrc";
const PLANET_SEED_RESOURCE_ID: i16 = 954;
const PLANET_SEED_MAX_CHARS: usize = 32;

pub(crate) fn random_setup_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: STARTUP_RESOURCE_FILE.to_owned(),
        resource_id: RANDOM_SETUP_RESOURCE_ID,
    }
}

pub(crate) fn planet_seed_dialog_view_id() -> ScopedViewId {
    ScopedViewId {
        resource_file: PLANET_SEED_RESOURCE_FILE.to_owned(),
        resource_id: PLANET_SEED_RESOURCE_ID,
    }
}

pub(crate) fn validate_application_bindings(catalog: &UiCatalogResource) -> Result<(), String> {
    catalog.require_unique_bindings(
        &random_setup_view_id(),
        &[
            OKAY,
            fourcc!("cncl"),
            fourcc!("glob"),
            fourcc!("key "),
            fourcc!("dif0"),
            fourcc!("dif1"),
            fourcc!("dif2"),
            fourcc!("dif3"),
            fourcc!("dif4"),
            fourcc!("hist"),
            fourcc!("rand"),
            fourcc!("coun"),
        ],
    )?;
    catalog.require_unique_bindings(&planet_seed_dialog_view_id(), &[fourcc!("plan"), OKAY])
}

/// Presentation-owned values edited by the random-game setup screen.
#[derive(Resource, Clone, Debug, Eq, PartialEq)]
pub(crate) struct RandomGameSetup {
    pub(crate) planet_seed: String,
    pub(crate) topology: MapTopology,
    pub(crate) nation: MajorNationId,
    pub(crate) country_name: String,
    pub(crate) difficulty: Difficulty,
    pub(crate) name_mode: NationNameMode,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NationNameMode {
    Historical,
    Random,
}

impl FromWorld for RandomGameSetup {
    fn from_world(world: &mut World) -> Self {
        let clock_seed = world.resource::<RandomSetupClockSeed>().0;
        let mut crt_rng = RetailCrtRng::from_state(clock_seed);
        let nation =
            MajorNationId::new((crt_rng.next_rand() % i32::from(MajorNationId::COUNT)) as u8);
        let mut name_rng = RetailLcg::from_state(clock_seed);
        Self {
            planet_seed: generate_english_random_setup_name(&mut name_rng),
            topology: MapTopology::Wrapping,
            nation,
            country_name: generate_english_random_setup_name(&mut name_rng),
            difficulty: Difficulty::Introductory,
            name_mode: NationNameMode::Historical,
        }
    }
}

/// Authoritative game state produced when Random Setup Accept/Okay succeeds.
#[derive(Resource, Clone, Debug, PartialEq)]
pub(crate) struct GameSession(pub(crate) GameState);

/// The generated map data owned by the setup screen.
#[derive(Resource, Clone, Debug, Eq, PartialEq)]
pub(crate) struct RandomSetupPreview(pub(crate) imperialism_core::RandomSetupPreview);

impl FromWorld for RandomSetupPreview {
    fn from_world(world: &mut World) -> Self {
        let clock = world.resource::<RandomSetupClockSeed>().0;
        let setup = world.resource::<RandomGameSetup>();
        let mut sea_zone_marker_crt = RetailCrtRng::from_state(clock);
        let _ = sea_zone_marker_crt.next_rand();
        Self(generate_random_setup_preview_with_clock_seed(
            setup.planet_seed.as_bytes(),
            setup.topology,
            clock,
            sea_zone_marker_crt,
        ))
    }
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

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum RandomSetupAction {
    Accept,
    Cancel,
    RegeneratePlanet,
    OpenPlanetSeed,
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
struct DifficultyChoice(Difficulty);

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
struct LocalizedNamesChoice(NationNameMode);

#[derive(Component)]
struct CountryNameField;

#[derive(Component)]
pub(crate) struct PlanetSeedDialogRoot;

#[derive(Component)]
struct PlanetSeedField;

#[derive(Component)]
struct PlanetSeedAccept;

pub(crate) struct RandomSetupPlugin;

pub(crate) fn register_random_setup_logic(app: &mut App) {
    app.init_resource::<RandomSetupClockSeed>()
        .init_resource::<RandomGameSetup>()
        .init_resource::<RandomSetupPreview>()
        .add_systems(
            Update,
            (
                sync_difficulty_checked,
                sync_localized_names_checked,
                sync_country_name_from_setup,
            )
                .run_if(in_state(AppState::RandomSetup)),
        )
        .add_observer(on_random_setup_activate)
        .add_observer(on_difficulty_selected)
        .add_observer(on_localized_names_selected)
        .add_observer(on_country_name_edited)
        .add_observer(on_planet_seed_accept)
        .add_observer(on_planet_seed_enter);
}

impl Plugin for RandomSetupPlugin {
    fn build(&self, app: &mut App) {
        register_random_setup_logic(app);
        // Asset-backed dialog open stays off the headless structure-only test path.
        app.add_observer(on_open_planet_seed);
        app.add_systems(OnEnter(AppState::RandomSetup), enter_random_setup);
    }
}

fn enter_random_setup(
    mut commands: Commands,
    catalog: Res<UiCatalogResource>,
    mut assets: UiAssetResources,
    setup: Res<RandomGameSetup>,
) {
    let view = catalog.required_view(&random_setup_view_id());
    let spawned = spawn_view(&mut commands, catalog.catalog(), view, &mut assets);
    bind_random_setup_controls(&mut commands, &spawned, &setup);
    random_setup_map::attach_random_setup_meanings(&mut commands, &spawned);
    commands
        .entity(spawned.root)
        .insert(DespawnOnExit(AppState::RandomSetup));
}

/// Attach screen meanings only; Bevy widget semantics come from catalog behaviors.
fn bind_random_setup_controls(
    commands: &mut Commands,
    spawned: &SpawnedView,
    setup: &RandomGameSetup,
) {
    for (tag, difficulty) in [
        (fourcc!("dif0"), Difficulty::Introductory),
        (fourcc!("dif1"), Difficulty::Easy),
        (fourcc!("dif2"), Difficulty::Normal),
        (fourcc!("dif3"), Difficulty::Hard),
        (fourcc!("dif4"), Difficulty::NighOnImpossible),
    ] {
        let entity = spawned.unique(tag);
        let mut entity_commands = commands.entity(entity);
        entity_commands.insert(DifficultyChoice(difficulty));
        if setup.difficulty == difficulty {
            entity_commands.insert(Checked);
        } else {
            entity_commands.remove::<Checked>();
        }
    }

    for (tag, localized) in [
        (fourcc!("hist"), NationNameMode::Historical),
        (fourcc!("rand"), NationNameMode::Random),
    ] {
        let entity = spawned.unique(tag);
        let mut entity_commands = commands.entity(entity);
        entity_commands.insert(LocalizedNamesChoice(localized));
        if setup.name_mode == localized {
            entity_commands.insert(Checked);
        } else {
            entity_commands.remove::<Checked>();
        }
    }

    let country = spawned.unique(fourcc!("coun"));
    commands.entity(country).insert((
        CountryNameField,
        SelectAllOnFocus,
        EditableText {
            max_characters: Some(COUNTRY_NAME_MAX_CHARS),
            allow_newlines: false,
            ..EditableText::new(setup.country_name.clone())
        },
    ));

    let okay = spawned.unique(OKAY);
    // Initialization and preview generation run before this screen is spawned;
    // bind the enabled Accept action only at that ready boundary.
    commands
        .entity(okay)
        .insert(RandomSetupAction::Accept)
        .remove::<InteractionDisabled>();

    for (tag, action) in [
        (fourcc!("cncl"), RandomSetupAction::Cancel),
        (fourcc!("glob"), RandomSetupAction::RegeneratePlanet),
        (fourcc!("key "), RandomSetupAction::OpenPlanetSeed),
    ] {
        let entity = spawned.unique(tag);
        commands.entity(entity).insert(action);
    }
}

fn sync_difficulty_checked(
    setup: Res<RandomGameSetup>,
    mut commands: Commands,
    radios: Query<(Entity, &DifficultyChoice, Has<Checked>)>,
) {
    if !setup.is_changed() {
        return;
    }
    for (entity, choice, checked) in &radios {
        let should_check = choice.0 == setup.difficulty;
        if should_check && !checked {
            commands.entity(entity).insert(Checked);
        } else if !should_check && checked {
            commands.entity(entity).remove::<Checked>();
        }
    }
}

fn sync_localized_names_checked(
    setup: Res<RandomGameSetup>,
    mut commands: Commands,
    radios: Query<(Entity, &LocalizedNamesChoice, Has<Checked>)>,
) {
    if !setup.is_changed() {
        return;
    }
    for (entity, choice, checked) in &radios {
        let should_check = choice.0 == setup.name_mode;
        if should_check && !checked {
            commands.entity(entity).insert(Checked);
        } else if !should_check && checked {
            commands.entity(entity).remove::<Checked>();
        }
    }
}

fn sync_country_name_from_setup(
    setup: Res<RandomGameSetup>,
    mut fields: Query<&mut EditableText, With<CountryNameField>>,
) {
    if !setup.is_changed() {
        return;
    }
    for mut editable in &mut fields {
        if editable.value().to_string() != setup.country_name {
            *editable = EditableText {
                max_characters: Some(COUNTRY_NAME_MAX_CHARS),
                allow_newlines: false,
                ..EditableText::new(setup.country_name.clone())
            };
        }
    }
}

#[derive(SystemParam)]
struct RandomSetupActivation<'w, 's> {
    actions: Query<'w, 's, &'static RandomSetupAction>,
    dialog_open: Query<'w, 's, (), With<ModalDialog>>,
    clock_seed: Res<'w, RandomSetupClockSeed>,
    setup: ResMut<'w, RandomGameSetup>,
    preview: ResMut<'w, RandomSetupPreview>,
    next_state: ResMut<'w, NextState<AppState>>,
    commands: Commands<'w, 's>,
}

fn on_random_setup_activate(activate: On<Activate>, mut random_setup: RandomSetupActivation) {
    let Ok(action) = random_setup.actions.get(activate.entity) else {
        return;
    };
    if !random_setup.dialog_open.is_empty() {
        return;
    }
    match *action {
        RandomSetupAction::Accept => {
            accept_random_setup(
                &random_setup.setup,
                &random_setup.preview,
                &mut random_setup.commands,
                &mut random_setup.next_state,
            );
        }
        RandomSetupAction::Cancel => random_setup.next_state.set(AppState::MainMenu),
        RandomSetupAction::RegeneratePlanet => {
            regenerate_random_setup_planet(
                random_setup.clock_seed.0,
                &mut random_setup.setup,
                &mut random_setup.preview,
            );
        }
        RandomSetupAction::OpenPlanetSeed => {
            // Handled by [`on_open_planet_seed`], which needs picture/font assets.
        }
    }
}

fn on_open_planet_seed(
    activate: On<Activate>,
    actions: Query<&RandomSetupAction>,
    dialog_open: Query<(), With<ModalDialog>>,
    mut ui: UiSpawner,
    setup: Res<RandomGameSetup>,
) {
    let Ok(RandomSetupAction::OpenPlanetSeed) = actions.get(activate.entity).copied() else {
        return;
    };
    if !dialog_open.is_empty() {
        return;
    }
    open_planet_seed_dialog(&mut ui, &setup);
}

fn on_difficulty_selected(
    change: On<ValueChange<bool>>,
    choices: Query<&DifficultyChoice>,
    mut setup: ResMut<RandomGameSetup>,
) {
    if !change.value {
        return;
    }
    let Ok(choice) = choices.get(change.source) else {
        return;
    };
    setup.difficulty = choice.0;
}

fn on_localized_names_selected(
    change: On<ValueChange<bool>>,
    choices: Query<&LocalizedNamesChoice>,
    mut setup: ResMut<RandomGameSetup>,
) {
    if !change.value {
        return;
    }
    let Ok(choice) = choices.get(change.source) else {
        return;
    };
    setup.name_mode = choice.0;
}

fn on_country_name_edited(
    change: On<TextEditChange>,
    fields: Query<&EditableText, With<CountryNameField>>,
    mut setup: ResMut<RandomGameSetup>,
) {
    let Ok(editable) = fields.get(change.event_target()) else {
        return;
    };
    let mut value = editable.value().to_string();
    if value.chars().count() > COUNTRY_NAME_MAX_CHARS {
        value = value.chars().take(COUNTRY_NAME_MAX_CHARS).collect();
    }
    if setup.country_name != value {
        setup.country_name = value;
    }
}

/// Country display name and localized-names policy are deliberately omitted: retail
/// stores them on `TCountry` / `TSimMgr` fields outside the semantic `GameState`
/// capture. Keep editing them in the setup UI only until those fields exist in
/// authoritative state — do not silently feed them into game construction.
fn accept_random_setup(
    setup: &RandomGameSetup,
    preview: &RandomSetupPreview,
    commands: &mut Commands,
    next_state: &mut NextState<AppState>,
) {
    // Live play still uses a fixed Accept CRT seed until wall-clock CRT wiring lands.
    let mut session = create_random_game(&preview.0, setup.nation, setup.difficulty, 1);
    if requires_capital_site_selection(setup.difficulty) {
        commands.insert_resource(GameSession(session));
        next_state.set(AppState::CitySite);
    } else {
        enter_strategic_map_without_capital_selection(&mut session, setup.nation);
        commands.insert_resource(GameSession(session));
        next_state.set(AppState::StrategicMap);
    }
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
            RetailCrtRng::from_state(clock_seed),
        ),
    );
}

fn open_planet_seed_dialog(ui: &mut UiSpawner, setup: &RandomGameSetup) {
    let spawned = ui.spawn_modal(planet_seed_dialog_view_id());
    ui.commands
        .entity(spawned.root)
        .insert(PlanetSeedDialogRoot);

    let plan = spawned.unique(fourcc!("plan"));
    ui.commands.entity(plan).insert((
        PlanetSeedField,
        SelectAllOnFocus,
        AutoFocus,
        TabIndex(0),
        EditableText {
            max_characters: Some(PLANET_SEED_MAX_CHARS),
            allow_newlines: false,
            ..EditableText::new(setup.planet_seed.clone())
        },
    ));

    let okay = spawned.unique(OKAY);
    ui.commands
        .entity(okay)
        .insert((PlanetSeedAccept, TabIndex(1)));
    // Retail cancel control stays disabled; Escape does not dismiss.
}

#[derive(SystemParam)]
struct PlanetSeedCommit<'w, 's> {
    fields: Query<'w, 's, &'static EditableText, With<PlanetSeedField>>,
    dialogs: Query<'w, 's, Entity, With<PlanetSeedDialogRoot>>,
    clock_seed: Res<'w, RandomSetupClockSeed>,
    setup: ResMut<'w, RandomGameSetup>,
    preview: ResMut<'w, RandomSetupPreview>,
    commands: Commands<'w, 's>,
}

fn on_planet_seed_accept(
    activate: On<Activate>,
    accepts: Query<(), With<PlanetSeedAccept>>,
    mut commit: PlanetSeedCommit,
) {
    if accepts.get(activate.entity).is_err() {
        return;
    }
    commit_planet_seed_dialog(&mut commit);
}

fn on_planet_seed_enter(
    mut input: On<bevy::input_focus::FocusedInput<KeyboardInput>>,
    mut commit: PlanetSeedCommit,
) {
    if commit.fields.get(input.focused_entity).is_err() {
        return;
    }
    let event = &input.input;
    if event.state != ButtonState::Pressed
        || event.repeat
        || (event.key_code != KeyCode::Enter && event.key_code != KeyCode::NumpadEnter)
    {
        return;
    }
    input.propagate(false);
    commit_planet_seed_dialog(&mut commit);
}

fn commit_planet_seed_dialog(commit: &mut PlanetSeedCommit<'_, '_>) {
    let Ok(editable) = commit.fields.single() else {
        return;
    };
    let draft = editable.value().to_string();
    if !draft.is_empty() && draft != commit.setup.planet_seed {
        commit.setup.planet_seed = draft;
        update_random_setup_preview(
            &mut commit.preview,
            generate_random_setup_preview_with_clock_seed(
                commit.setup.planet_seed.as_bytes(),
                commit.setup.topology,
                commit.clock_seed.0,
                RetailCrtRng::from_state(commit.clock_seed.0),
            ),
        );
    }
    for root in commit.dialogs.iter() {
        commit.commands.entity(root).despawn();
    }
}

fn update_random_setup_preview(
    preview: &mut RandomSetupPreview,
    generated: imperialism_core::RandomSetupPreview,
) {
    preview.0 = generated;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::catalog::spawn_view_nodes;
    use crate::ui::main_menu::{
        MainMenuAction, bind_main_menu_actions, main_menu_view_id, register_main_menu_logic,
    };
    use bevy::input_focus::tab_navigation::TabGroup;
    use bevy::ui_widgets::{Button as UiButton, ButtonPlugin};
    use imperialism_core::NationId;
    use imperialism_formats::UiCatalog;

    const CATALOG_JSON: &str = include_str!("../../../imperialism-formats/assets/ui_catalog.json");

    fn app() -> App {
        let catalog = serde_json::from_str::<UiCatalog>(CATALOG_JSON).unwrap();
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .insert_resource(UiCatalogResource::new(catalog).unwrap())
            .insert_resource(RandomSetupClockSeed(1))
            .add_plugins(bevy::state::app::StatesPlugin)
            .init_state::<AppState>()
            .add_plugins(ButtonPlugin)
            .add_plugins(bevy::ui_widgets::RadioGroupPlugin);
        register_main_menu_logic(&mut app);
        register_random_setup_logic(&mut app);
        app.add_systems(OnEnter(AppState::MainMenu), enter_main_menu_structure_only)
            .add_systems(
                OnEnter(AppState::RandomSetup),
                enter_random_setup_structure_only,
            );
        app.update();
        app
    }

    fn initial_seed_one_preview() -> imperialism_core::RandomSetupPreview {
        let mut sea_zone_marker_crt = RetailCrtRng::from_state(1);
        let _ = sea_zone_marker_crt.next_rand();
        generate_random_setup_preview_with_clock_seed(
            b"Woopnist",
            MapTopology::Wrapping,
            1,
            sea_zone_marker_crt,
        )
    }

    fn enter_main_menu_structure_only(mut commands: Commands, catalog: Res<UiCatalogResource>) {
        let view_id = main_menu_view_id();
        let Some(view) = catalog.view(&view_id) else {
            return;
        };
        let spawned = spawn_view_nodes(&mut commands, catalog.catalog().logical_resolution, view);
        bind_main_menu_actions(&mut commands, &catalog, &spawned);
        commands
            .entity(spawned.root)
            .insert(DespawnOnExit(AppState::MainMenu));
    }

    fn enter_random_setup_structure_only(
        mut commands: Commands,
        catalog: Res<UiCatalogResource>,
        setup: Res<RandomGameSetup>,
    ) {
        let view_id = random_setup_view_id();
        let Some(view) = catalog.view(&view_id) else {
            return;
        };
        let spawned = spawn_view_nodes(&mut commands, catalog.catalog().logical_resolution, view);
        bind_random_setup_controls(&mut commands, &spawned, &setup);
        random_setup_map::attach_random_setup_meanings(&mut commands, &spawned);
        commands
            .entity(spawned.root)
            .insert(DespawnOnExit(AppState::RandomSetup));
    }

    fn open_planet_seed_dialog_structure(app: &mut App) {
        let planet_seed = app
            .world()
            .resource::<RandomGameSetup>()
            .planet_seed
            .clone();
        let (logical_resolution, view) = {
            let catalog = app.world().resource::<UiCatalogResource>();
            let view = catalog.view(&planet_seed_dialog_view_id()).unwrap().clone();
            (catalog.catalog().logical_resolution, view)
        };
        let world = app.world_mut();
        let mut commands = world.commands();
        let spawned = spawn_view_nodes(&mut commands, logical_resolution, &view);
        commands.entity(spawned.root).insert((
            PlanetSeedDialogRoot,
            ModalDialog,
            TabGroup::modal(),
            ZIndex(10),
            Pickable::default(),
        ));
        world.flush();
        let plan = spawned.require_unique(fourcc!("plan")).unwrap();
        let okay = spawned.require_unique(fourcc!("okay")).unwrap();
        let mut commands = world.commands();
        commands.entity(plan).insert((
            PlanetSeedField,
            EditableText {
                max_characters: Some(PLANET_SEED_MAX_CHARS),
                allow_newlines: false,
                ..EditableText::new(planet_seed)
            },
            SelectAllOnFocus,
            AutoFocus,
            TabIndex(0),
        ));
        commands
            .entity(okay)
            .insert((UiButton, PlanetSeedAccept, TabIndex(1)));
        world.flush();
    }

    fn enter_random_setup_screen(app: &mut App) {
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
        app.update();
    }

    fn action_entity(app: &mut App, action: RandomSetupAction) -> Entity {
        app.world_mut()
            .query_filtered::<(Entity, &RandomSetupAction), ()>()
            .iter(app.world())
            .find(|(_, value)| **value == action)
            .map(|(entity, _)| entity)
            .unwrap()
    }

    #[test]
    fn random_setup_activated_intents_update_the_app_draft() {
        let mut app = app();
        enter_random_setup_screen(&mut app);
        let hard = app
            .world_mut()
            .query_filtered::<(Entity, &DifficultyChoice), ()>()
            .iter(app.world())
            .find(|(_, choice)| choice.0 == Difficulty::Hard)
            .map(|(entity, _)| entity)
            .unwrap();
        app.world_mut().commands().trigger(ValueChange {
            source: hard,
            value: true,
            is_final: true,
        });
        let hist = app
            .world_mut()
            .query_filtered::<(Entity, &LocalizedNamesChoice), ()>()
            .iter(app.world())
            .find(|(_, choice)| choice.0 == NationNameMode::Historical)
            .map(|(entity, _)| entity)
            .unwrap();
        app.world_mut().commands().trigger(ValueChange {
            source: hist,
            value: true,
            is_final: true,
        });
        let accept = action_entity(&mut app, RandomSetupAction::Accept);
        app.world_mut()
            .commands()
            .trigger(Activate { entity: accept });
        app.world_mut().flush();
        app.update();
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::CitySite
        );
        assert_eq!(
            app.world().resource::<RandomGameSetup>(),
            &RandomGameSetup {
                planet_seed: "Woopnist".to_owned(),
                topology: MapTopology::Wrapping,
                nation: MajorNationId::new(6),
                country_name: "Purtast".to_owned(),
                difficulty: Difficulty::Hard,
                name_mode: NationNameMode::Historical,
            }
        );
        let session = app.world().resource::<GameSession>();
        assert_eq!(session.0.turn().difficulty, Difficulty::Hard);
        assert_eq!(session.0.turn().selected_nation, NationId::new(6));
        assert_eq!(
            session.0.turn().phase(),
            imperialism_core::PhaseCode::CAPITAL_SELECTION
        );
        assert_eq!(
            session
                .0
                .nations()
                .major(MajorNationId::new(6))
                .common()
                .home_tile,
            None
        );
    }

    #[test]
    fn preview_is_concrete_and_okay_is_enabled_when_the_screen_spawns() {
        let mut app = app();
        enter_random_setup_screen(&mut app);
        assert_eq!(
            app.world().resource::<RandomSetupPreview>().0,
            initial_seed_one_preview()
        );
        let okay = action_entity(&mut app, RandomSetupAction::Accept);
        assert!(app.world().get::<InteractionDisabled>(okay).is_none());
    }

    #[test]
    fn random_setup_entry_uses_the_retail_clock_seeded_defaults() {
        let mut app = app();
        enter_random_setup_screen(&mut app);
        assert_eq!(
            app.world().resource::<RandomGameSetup>(),
            &RandomGameSetup {
                planet_seed: "Woopnist".to_owned(),
                topology: MapTopology::Wrapping,
                nation: MajorNationId::new(6),
                country_name: "Purtast".to_owned(),
                difficulty: Difficulty::Introductory,
                name_mode: NationNameMode::Historical,
            }
        );
        assert_eq!(
            app.world().resource::<RandomSetupPreview>().0,
            initial_seed_one_preview()
        );
    }

    #[test]
    fn globe_regenerates_the_planet_from_the_reset_clock_seed() {
        let mut app = app();
        enter_random_setup_screen(&mut app);
        {
            let mut setup = app.world_mut().resource_mut::<RandomGameSetup>();
            setup.planet_seed = "manual planet".to_owned();
            setup.nation = MajorNationId::new(2);
            setup.country_name = "Custom Name".to_owned();
            setup.difficulty = Difficulty::NighOnImpossible;
            setup.name_mode = NationNameMode::Random;
        }
        let globe = action_entity(&mut app, RandomSetupAction::RegeneratePlanet);
        app.world_mut()
            .commands()
            .trigger(Activate { entity: globe });
        app.world_mut().flush();
        app.update();
        assert_eq!(
            app.world().resource::<RandomGameSetup>(),
            &RandomGameSetup {
                planet_seed: "Woopnist".to_owned(),
                topology: MapTopology::Wrapping,
                nation: MajorNationId::new(2),
                country_name: "Custom Name".to_owned(),
                difficulty: Difficulty::NighOnImpossible,
                name_mode: NationNameMode::Random,
            }
        );
        assert_eq!(
            app.world()
                .resource::<RandomSetupPreview>()
                .0
                .sea_zone_marker_crt,
            RetailCrtRng::from_state(1)
        );
    }

    #[test]
    fn random_setup_cancel_returns_to_the_main_menu() {
        let mut app = app();
        enter_random_setup_screen(&mut app);
        let cancel = action_entity(&mut app, RandomSetupAction::Cancel);
        app.world_mut()
            .commands()
            .trigger(Activate { entity: cancel });
        app.world_mut().flush();
        app.update();
        app.update();
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::MainMenu
        );
    }

    #[test]
    fn planet_seed_dialog_accepts_a_changed_nonempty_seed_and_updates_the_preview() {
        let mut app = app();
        enter_random_setup_screen(&mut app);
        app.world_mut()
            .resource_mut::<RandomGameSetup>()
            .planet_seed = "previous".to_owned();
        open_planet_seed_dialog_structure(&mut app);
        assert!(
            app.world_mut()
                .query_filtered::<Entity, With<PlanetSeedDialogRoot>>()
                .iter(app.world())
                .next()
                .is_some()
        );

        let field = app
            .world_mut()
            .query_filtered::<Entity, With<PlanetSeedField>>()
            .iter(app.world())
            .next()
            .unwrap();
        if let Some(mut editable) = app.world_mut().get_mut::<EditableText>(field) {
            *editable = EditableText {
                max_characters: Some(PLANET_SEED_MAX_CHARS),
                allow_newlines: false,
                ..EditableText::new("ordinary")
            };
        }

        let accept = app
            .world_mut()
            .query_filtered::<Entity, With<PlanetSeedAccept>>()
            .iter(app.world())
            .next()
            .unwrap();
        app.world_mut()
            .commands()
            .trigger(Activate { entity: accept });
        app.world_mut().flush();
        app.update();
        assert_eq!(
            app.world().resource::<RandomGameSetup>().planet_seed,
            "ordinary"
        );
        assert!(
            app.world_mut()
                .query_filtered::<Entity, With<PlanetSeedDialogRoot>>()
                .iter(app.world())
                .next()
                .is_none()
        );
    }

    #[test]
    fn empty_or_unchanged_planet_seed_does_not_generate_a_preview() {
        let mut app = app();
        enter_random_setup_screen(&mut app);
        let existing_preview = app.world().resource::<RandomSetupPreview>().clone();
        app.world_mut()
            .resource_mut::<RandomGameSetup>()
            .planet_seed = "ordinary".to_owned();
        open_planet_seed_dialog_structure(&mut app);
        let accept = app
            .world_mut()
            .query_filtered::<Entity, With<PlanetSeedAccept>>()
            .iter(app.world())
            .next()
            .unwrap();
        app.world_mut()
            .commands()
            .trigger(Activate { entity: accept });
        app.world_mut().flush();
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
        let field = app
            .world_mut()
            .query_filtered::<Entity, With<PlanetSeedField>>()
            .iter(app.world())
            .next()
            .unwrap();
        if let Some(mut editable) = app.world_mut().get_mut::<EditableText>(field) {
            *editable = EditableText {
                max_characters: Some(PLANET_SEED_MAX_CHARS),
                allow_newlines: false,
                ..EditableText::new("")
            };
        }
        let accept = app
            .world_mut()
            .query_filtered::<Entity, With<PlanetSeedAccept>>()
            .iter(app.world())
            .next()
            .unwrap();
        app.world_mut()
            .commands()
            .trigger(Activate { entity: accept });
        app.world_mut().flush();
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

    #[test]
    fn setup_actions_are_ignored_while_planet_dialog_is_open() {
        let mut app = app();
        enter_random_setup_screen(&mut app);
        open_planet_seed_dialog_structure(&mut app);
        let before = app.world().resource::<RandomGameSetup>().clone();
        let globe = action_entity(&mut app, RandomSetupAction::RegeneratePlanet);
        app.world_mut()
            .resource_mut::<RandomGameSetup>()
            .planet_seed = "manual".to_owned();
        app.world_mut()
            .commands()
            .trigger(Activate { entity: globe });
        app.world_mut().flush();
        app.update();
        assert_eq!(
            app.world().resource::<RandomGameSetup>().planet_seed,
            "manual"
        );
        assert_ne!(
            app.world().resource::<RandomGameSetup>().planet_seed,
            before.planet_seed
        );
        // Globe activation must not regenerate while the dialog is open.
        assert_eq!(
            app.world().resource::<RandomGameSetup>().planet_seed,
            "manual"
        );
    }
}
