use crate::ui::GameSession;
use crate::ui::generated;
use crate::ui::hover_help::{
    HoverHelpBarStyle, bind_hover_help_bar, bind_hover_help_texts, ui_string,
};
use crate::ui::random_setup_map;
use crate::ui::retail::ModalDialog;
use crate::ui::retail::{RetailTag, RetailUiAssets, find_descendant};
use crate::ui::session::apply_turn_stop;
use crate::{AppState, RandomGameNamesResource, RetailAssetsResource};
use bevy::ecs::system::SystemParam;
use bevy::input::ButtonState;
use bevy::input::keyboard::KeyboardInput;
use bevy::input_focus::AutoFocus;
use bevy::input_focus::tab_navigation::{TabGroup, TabIndex};
use bevy::prelude::*;
use bevy::text::{EditableText, TextEditChange};
use bevy::ui::{Checked, InteractionDisabled};
use bevy::ui_widgets::{Activate, SelectAllOnFocus, ValueChange};
use imperialism_core::*;
use imperialism_formats::{OKAY, fourcc};
use std::time::{SystemTime, UNIX_EPOCH};

const PLANET_SEED_MAX_CHARS: usize = 32;

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
struct RandomSetupRoot;

#[derive(Component)]
pub(crate) struct PlanetSeedDialogRoot;

#[derive(Component)]
struct PlanetSeedField;

#[derive(Component)]
struct PlanetSeedAccept;

pub(crate) struct RandomSetupPlugin;

impl Plugin for RandomSetupPlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(OnEnter(AppState::MainMenu), drop_random_setup_draft)
            .add_systems(
                Update,
                (
                    sync_difficulty_checked,
                    sync_localized_names_checked,
                    sync_country_name_from_setup,
                )
                    .run_if(in_state(AppState::RandomSetup)),
            )
            .add_systems(
                OnEnter(AppState::RandomSetup),
                (
                    ensure_random_setup_draft,
                    enter_random_setup,
                    bind_random_setup,
                )
                    .chain(),
            )
            .add_systems(Update, bind_planet_seed_dialog);
    }
}

fn ensure_random_setup_draft(world: &mut World) {
    if world.contains_resource::<RandomGameSetup>() {
        return;
    }
    world.init_resource::<RandomSetupClockSeed>();
    world.init_resource::<RandomGameSetup>();
    world.init_resource::<RandomSetupPreview>();
}

fn drop_random_setup_draft(mut commands: Commands) {
    commands.remove_resource::<RandomGameSetup>();
    commands.remove_resource::<RandomSetupPreview>();
    commands.remove_resource::<RandomSetupClockSeed>();
}

fn enter_random_setup(mut commands: Commands) {
    let root = commands.spawn_scene(generated::startup_1501()).id();
    commands
        .entity(root)
        .insert((RandomSetupRoot, DespawnOnExit(AppState::RandomSetup)));
}

fn bind_random_setup(
    mut commands: Commands,
    root: Single<Entity, Added<RandomSetupRoot>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut nodes: Query<&mut Node>,
    setup: Res<RandomGameSetup>,
    mut assets: RetailUiAssets,
) {
    bind_random_setup_controls(&mut commands, *root, &children, &tags, &setup);
    random_setup_map::attach_random_setup_meanings(&mut commands, *root, &children, &tags);
    bind_random_setup_hover_help(
        &mut commands,
        *root,
        &children,
        &tags,
        &mut nodes,
        &mut assets,
    );
}

/// Attach screen meanings only; Bevy widget semantics come from generated components.
fn bind_random_setup_controls(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    setup: &RandomGameSetup,
) {
    for (tag, difficulty) in [
        (fourcc!("dif0"), Difficulty::Introductory),
        (fourcc!("dif1"), Difficulty::Easy),
        (fourcc!("dif2"), Difficulty::Normal),
        (fourcc!("dif3"), Difficulty::Hard),
        (fourcc!("dif4"), Difficulty::NighOnImpossible),
    ] {
        let entity = find_descendant(root, tag, children, tags);
        let mut entity_commands = commands.entity(entity);
        entity_commands
            .insert(DifficultyChoice(difficulty))
            .observe(on_difficulty_selected);
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
        let entity = find_descendant(root, tag, children, tags);
        let mut entity_commands = commands.entity(entity);
        entity_commands
            .insert(LocalizedNamesChoice(localized))
            .observe(on_localized_names_selected);
        if setup.name_mode == localized {
            entity_commands.insert(Checked);
        } else {
            entity_commands.remove::<Checked>();
        }
    }

    let country = find_descendant(root, fourcc!("coun"), children, tags);
    commands
        .entity(country)
        .insert((
            CountryNameField,
            SelectAllOnFocus,
            EditableText {
                max_characters: Some(COUNTRY_NAME_MAX_CHARS),
                allow_newlines: false,
                ..EditableText::new(setup.country_name.clone())
            },
        ))
        .observe(on_country_name_edited);

    let okay = find_descendant(root, OKAY, children, tags);
    // Retail rebuilds this screen from the main menu and keeps the draft when
    // capital selection cancels back into setup.
    commands
        .entity(okay)
        .insert(RandomSetupAction::Accept)
        .remove::<InteractionDisabled>()
        .observe(on_random_setup_activate);

    for (tag, action) in [
        (fourcc!("cncl"), RandomSetupAction::Cancel),
        (fourcc!("glob"), RandomSetupAction::RegeneratePlanet),
        (fourcc!("key "), RandomSetupAction::OpenPlanetSeed),
    ] {
        let entity = find_descendant(root, tag, children, tags);
        commands
            .entity(entity)
            .insert(action)
            .observe(on_random_setup_activate);
    }
}

fn bind_random_setup_hover_help(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    nodes: &mut Query<&mut Node>,
    assets: &mut RetailUiAssets,
) {
    let bar = find_descendant(root, fourcc!("hot!"), children, tags);
    bind_hover_help_bar(
        commands,
        assets,
        bar,
        &mut nodes
            .get_mut(bar)
            .expect("random-setup hover-help bar has Node"),
        HoverHelpBarStyle::RANDOM_SETUP,
    );
    let cancel = ui_string(assets, 0x2737, 0x14);
    bind_hover_help_texts(
        commands,
        root,
        children,
        tags,
        [
            (fourcc!("main"), String::new()),
            (fourcc!("key "), String::new()),
            (fourcc!("stuf"), String::new()),
            (fourcc!("name"), ui_string(assets, 0x2758, 0x1e)),
            (fourcc!("glob"), ui_string(assets, 0x2737, 0x13)),
            (fourcc!("canc"), cancel.clone()),
            (fourcc!("cncl"), cancel),
            (OKAY, ui_string(assets, 0x2737, 0x15)),
            (fourcc!("map "), ui_string(assets, 0x2758, 0x13)),
            (fourcc!("diff"), ui_string(assets, 0x2737, 0x17)),
            (fourcc!("coun"), ui_string(assets, 0x2737, 0x1a)),
            (fourcc!("flag"), ui_string(assets, 0x2737, 0x1b)),
            (fourcc!("coat"), ui_string(assets, 0x2737, 0x1c)),
        ],
    );
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
    names: Res<'w, RandomGameNamesResource>,
    retail: Res<'w, RetailAssetsResource>,
    next_state: ResMut<'w, NextState<AppState>>,
    commands: Commands<'w, 's>,
}

fn on_random_setup_activate(activate: On<Activate>, mut random_setup: RandomSetupActivation) {
    let action = random_setup
        .actions
        .get(activate.entity)
        .expect("random-setup Activate is bound on a RandomSetupAction control");
    if !random_setup.dialog_open.is_empty() {
        return;
    }
    match *action {
        RandomSetupAction::Accept => {
            accept_random_setup(
                &random_setup.setup,
                &random_setup.preview,
                &random_setup.names.0,
                random_setup.retail.assets(),
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
            open_planet_seed_dialog(&mut random_setup.commands);
        }
    }
}

fn on_difficulty_selected(
    change: On<ValueChange<bool>>,
    choices: Query<&DifficultyChoice>,
    mut setup: ResMut<RandomGameSetup>,
) {
    if !change.value {
        return;
    }
    let choice = choices
        .get(change.source)
        .expect("difficulty ValueChange is bound on a DifficultyChoice control");
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
    let choice = choices
        .get(change.source)
        .expect("name-mode ValueChange is bound on a LocalizedNamesChoice control");
    setup.name_mode = choice.0;
}

fn on_country_name_edited(
    change: On<TextEditChange>,
    fields: Query<&EditableText, With<CountryNameField>>,
    mut setup: ResMut<RandomGameSetup>,
) {
    let editable = fields
        .get(change.event_target())
        .expect("country-name TextEditChange is bound on the country name field");
    let mut value = editable.value().to_string();
    if value.chars().count() > COUNTRY_NAME_MAX_CHARS {
        value = value.chars().take(COUNTRY_NAME_MAX_CHARS).collect();
    }
    if setup.country_name != value {
        setup.country_name = value;
    }
}

fn accept_random_setup(
    setup: &RandomGameSetup,
    preview: &RandomSetupPreview,
    names: &RandomGameNames,
    assets: &imperialism_formats::RetailAssets,
    commands: &mut Commands,
    next_state: &mut NextState<AppState>,
) {
    // Live play still uses a fixed Accept CRT seed until wall-clock CRT wiring lands.
    let mut session = create_random_game(
        &preview.0,
        setup.nation,
        setup.difficulty,
        &setup.country_name,
        setup.name_mode == NationNameMode::Historical,
        1,
        names,
    );
    if requires_capital_site_selection(setup.difficulty) {
        commands.insert_resource(GameSession(session));
        next_state.set(AppState::CitySite);
    } else {
        let stop = enter_strategic_map_without_capital_selection(
            &mut session,
            setup.nation,
            assets.news_table().story_ids(),
        );
        apply_turn_stop(stop, next_state);
        commands.insert_resource(GameSession(session));
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

fn open_planet_seed_dialog(commands: &mut Commands) {
    let root = commands.spawn_scene(generated::linger_954()).id();
    commands.entity(root).insert((
        PlanetSeedDialogRoot,
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(20),
        Pickable::default(),
        DespawnOnExit(AppState::RandomSetup),
    ));
}

fn bind_planet_seed_dialog(
    mut commands: Commands,
    root: Single<Entity, Added<PlanetSeedDialogRoot>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    setup: Res<RandomGameSetup>,
) {
    let plan = find_descendant(*root, fourcc!("plan"), &children, &tags);
    commands
        .entity(plan)
        .insert((
            PlanetSeedField,
            SelectAllOnFocus,
            AutoFocus,
            TabIndex(0),
            EditableText {
                max_characters: Some(PLANET_SEED_MAX_CHARS),
                allow_newlines: false,
                ..EditableText::new(setup.planet_seed.clone())
            },
        ))
        .observe(on_planet_seed_enter);

    let okay = find_descendant(*root, OKAY, &children, &tags);
    commands
        .entity(okay)
        .insert((PlanetSeedAccept, TabIndex(1)))
        .observe(on_planet_seed_accept);
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

fn on_planet_seed_accept(_activate: On<Activate>, mut commit: PlanetSeedCommit) {
    commit_planet_seed_dialog(&mut commit);
}

fn on_planet_seed_enter(
    mut input: On<bevy::input_focus::FocusedInput<KeyboardInput>>,
    mut commit: PlanetSeedCommit,
) {
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

    fn spawn_binding_fixture(mut commands: Commands) {
        let root = commands.spawn((RandomSetupRoot, Node::default())).id();
        for tag in ["dif0", "dif1", "dif2", "dif3", "dif4", "hist", "rand"] {
            commands.spawn((
                RetailTag(imperialism_formats::FourCc::new(tag)),
                bevy::ui_widgets::RadioButton,
                ChildOf(root),
            ));
        }
        for tag in ["coun", "okay", "cncl", "glob", "key "] {
            commands.spawn((
                RetailTag(imperialism_formats::FourCc::new(tag)),
                Node::default(),
                ChildOf(root),
            ));
        }
    }

    #[test]
    fn random_setup_binds_native_radios_and_editable_text_to_typed_meanings() {
        let setup = RandomGameSetup {
            planet_seed: "Planet".to_owned(),
            topology: MapTopology::Wrapping,
            nation: MajorNationId::new(0),
            country_name: "Country".to_owned(),
            difficulty: Difficulty::Hard,
            name_mode: NationNameMode::Random,
        };
        let mut app = App::new();
        app.insert_resource(setup).add_systems(
            Update,
            (
                spawn_binding_fixture,
                |mut commands: Commands,
                 root: Single<Entity, Added<RandomSetupRoot>>,
                 children: Query<&Children>,
                 tags: Query<&RetailTag>,
                 setup: Res<RandomGameSetup>| {
                    bind_random_setup_controls(&mut commands, *root, &children, &tags, &setup);
                },
            )
                .chain(),
        );
        app.update();

        let mut difficulties = app.world_mut().query::<(
            &DifficultyChoice,
            Has<Checked>,
            Has<bevy::ui_widgets::RadioButton>,
        )>();
        assert!(
            difficulties
                .iter(app.world())
                .any(|(choice, checked, radio)| {
                    choice.0 == Difficulty::Hard && checked && radio
                })
        );
        let mut fields = app
            .world_mut()
            .query_filtered::<&EditableText, With<CountryNameField>>();
        let field = fields.single(app.world()).unwrap();
        assert_eq!(field.value(), "Country");
        assert_eq!(field.max_characters, Some(COUNTRY_NAME_MAX_CHARS));
    }

    #[test]
    fn leaving_random_setup_despawns_an_open_planet_seed_dialog() {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(bevy::state::app::StatesPlugin)
            .insert_state(AppState::RandomSetup);
        app.update();

        let dialog = app
            .world_mut()
            .spawn((
                PlanetSeedDialogRoot,
                ModalDialog,
                DespawnOnExit(AppState::RandomSetup),
            ))
            .id();
        app.update();
        assert!(app.world().get::<PlanetSeedDialogRoot>(dialog).is_some());

        app.world_mut()
            .resource_mut::<NextState<AppState>>()
            .set(AppState::MainMenu);
        app.update();
        assert!(app.world().get::<PlanetSeedDialogRoot>(dialog).is_none());
    }
}
