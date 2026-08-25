use crate::ui::generated;
use crate::ui::hover_help::{
    HoverHelpBarStyle, bind_hover_help_bar, bind_hover_help_texts, ui_string,
};
use crate::ui::random_setup_map;
use crate::ui::retail::{RADIO_CLUSTER_FRAME_PALETTE, RetailUiAssets};
use crate::ui::session::apply_turn_stop;
use crate::ui::window::{DismissWindow, ModalCancel, ModalDefault, ModalWindow};
use crate::ui::{insert_game_session, insert_loaded_game};
use crate::{AppState, RandomGameNamesResource, RetailAssetsResource};
use bevy::ecs::system::SystemParam;
use bevy::input_focus::AutoFocus;
use bevy::input_focus::tab_navigation::TabIndex;
use bevy::prelude::*;
use bevy::text::TextCursorStyle;
use bevy::text::{EditableText, TextEditChange};
use bevy::ui::{Checked, InteractionDisabled};
use bevy::ui_widgets::{Activate, ActivateOnPress, SelectAllOnFocus, ValueChange};
use imperialism_core::*;
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
    name_rng: RetailLcg,
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
            name_rng,
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
    OpenPlanetSeed,
}

#[derive(Component)]
struct RandomSetupGlobe;

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
    let ui = generated::spawn_startup_1501(&mut commands);
    commands
        .entity(ui.root)
        .insert((RandomSetupRoot, ui, DespawnOnExit(AppState::RandomSetup)));
}

fn bind_random_setup(
    mut commands: Commands,
    ui: Single<&generated::Startup1501, Added<RandomSetupRoot>>,
    mut nodes: Query<&mut Node>,
    setup: Res<RandomGameSetup>,
    mut assets: RetailUiAssets,
) {
    let ui = **ui;
    bind_random_setup_controls(&mut commands, ui, &setup);
    bind_random_setup_labels(&mut commands, ui, &mut nodes, &mut assets);
    random_setup_map::attach_random_setup_meanings(&mut commands, ui.map, ui.coat, ui.flag);
    bind_random_setup_hover_help(&mut commands, ui, &mut nodes, &mut assets);
}

/// Attach screen meanings only; Bevy widget semantics come from generated components.
fn bind_random_setup_controls(
    commands: &mut Commands,
    ui: generated::Startup1501,
    setup: &RandomGameSetup,
) {
    for (entity, difficulty) in [
        (ui.dif0, Difficulty::Introductory),
        (ui.dif1, Difficulty::Easy),
        (ui.dif2, Difficulty::Normal),
        (ui.dif3, Difficulty::Hard),
        (ui.dif4, Difficulty::NighOnImpossible),
    ] {
        let mut entity_commands = commands.entity(entity);
        entity_commands
            .insert((DifficultyChoice(difficulty), Pickable::default()))
            .observe(on_difficulty_selected);
        if setup.difficulty == difficulty {
            entity_commands.insert(Checked);
        } else {
            entity_commands.remove::<Checked>();
        }
    }

    for (entity, localized) in [
        (ui.hist, NationNameMode::Historical),
        (ui.rand, NationNameMode::Random),
    ] {
        let mut entity_commands = commands.entity(entity);
        entity_commands
            .insert((LocalizedNamesChoice(localized), Pickable::default()))
            .observe(on_localized_names_selected);
        if setup.name_mode == localized {
            entity_commands.insert(Checked);
        } else {
            entity_commands.remove::<Checked>();
        }
    }

    commands
        .entity(ui.coun)
        .insert((
            CountryNameField,
            SelectAllOnFocus,
            AutoFocus,
            TabIndex(0),
            Pickable::default(),
            TextCursorStyle {
                color: Color::BLACK,
                selected_text_color: Some(Color::BLACK),
                ..default()
            },
            EditableText {
                max_characters: Some(COUNTRY_NAME_MAX_CHARS),
                allow_newlines: false,
                ..EditableText::new(setup.country_name.clone())
            },
        ))
        .observe(on_country_name_edited);

    // Retail rebuilds this screen from the main menu and keeps the draft when
    // capital selection cancels back into setup.
    commands
        .entity(ui.okay)
        .insert(RandomSetupAction::Accept)
        .remove::<InteractionDisabled>()
        .observe(on_random_setup_activate);

    for (entity, action) in [
        (ui.cncl, RandomSetupAction::Cancel),
        (ui.key, RandomSetupAction::OpenPlanetSeed),
    ] {
        commands
            .entity(entity)
            .insert((action, ActivateOnPress))
            .observe(on_random_setup_activate);
    }
    commands
        .entity(ui.glob)
        .insert((RandomSetupGlobe, ActivateOnPress))
        .observe(on_random_setup_globe);
}

fn bind_random_setup_labels(
    commands: &mut Commands,
    ui: generated::Startup1501,
    nodes: &mut Query<&mut Node>,
    assets: &mut RetailUiAssets,
) {
    // TSetupRandomMapPicture::DoPostCreate overwrites Mac STR# captions from
    // the Windows string tables and frames the two TRadioTextCluster groups.
    for (entity, group, index) in [
        (ui.tcou, 0x2737, 0x1e),
        (ui.dift, 0x2758, 2),
        (ui.tnam, 0x2758, 3),
        (ui.hist, 0x2758, 4),
        (ui.rand, 0x2758, 5),
        (ui.dif0, 0x2737, 0x0e),
        (ui.dif1, 0x2737, 0x0f),
        (ui.dif2, 0x2737, 0x10),
        (ui.dif3, 0x2737, 0x11),
        (ui.dif4, 0x2737, 0x12),
    ] {
        commands
            .entity(entity)
            .insert((Text::new(ui_string(assets, group, index)), Label));
    }
    let title_color = TextColor(assets.palette_color(0x5c));
    let title_shadow = TextShadow {
        offset: Vec2::new(-1.0, -1.0),
        color: assets.palette_color(0x28),
    };
    for entity in [ui.tcou, ui.dift, ui.tnam] {
        commands.entity(entity).insert((title_color, title_shadow));
    }
    let option_color = TextColor(assets.palette_color(0xd2));
    let option_shadow = TextShadow {
        offset: Vec2::new(-1.0, -1.0),
        color: assets.palette_color(0x28),
    };
    for entity in [
        ui.hist, ui.rand, ui.dif0, ui.dif1, ui.dif2, ui.dif3, ui.dif4,
    ] {
        commands
            .entity(entity)
            .insert((option_color, option_shadow));
    }
    let frame = BorderColor::all(assets.palette_color(RADIO_CLUSTER_FRAME_PALETTE));
    for entity in [ui.diff, ui.name] {
        nodes
            .get_mut(entity)
            .expect("random-setup radio cluster has Node")
            .border = UiRect::all(px(1));
        commands.entity(entity).insert(frame);
    }
}

fn bind_random_setup_hover_help(
    commands: &mut Commands,
    ui: generated::Startup1501,
    nodes: &mut Query<&mut Node>,
    assets: &mut RetailUiAssets,
) {
    bind_hover_help_bar(
        commands,
        assets,
        ui.hot,
        &mut nodes
            .get_mut(ui.hot)
            .expect("random-setup hover-help bar has Node"),
        HoverHelpBarStyle::RANDOM_SETUP,
    );
    let cancel = ui_string(assets, 0x2737, 0x14);
    bind_hover_help_texts(
        commands,
        [
            (ui.main, String::new()),
            (ui.key, String::new()),
            (ui.stuf, String::new()),
            (ui.name, ui_string(assets, 0x2758, 0x1e)),
            (ui.glob, ui_string(assets, 0x2737, 0x13)),
            (ui.canc, cancel.clone()),
            (ui.cncl, cancel),
            (ui.okay, ui_string(assets, 0x2737, 0x15)),
            (ui.map, ui_string(assets, 0x2758, 0x13)),
            (ui.diff, ui_string(assets, 0x2737, 0x17)),
            (ui.coun, ui_string(assets, 0x2737, 0x1a)),
            (ui.flag, ui_string(assets, 0x2737, 0x1b)),
            (ui.coat, ui_string(assets, 0x2737, 0x1c)),
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
        RandomSetupAction::OpenPlanetSeed => {
            open_planet_seed_dialog(&mut random_setup.commands);
        }
    }
}

fn on_random_setup_globe(
    _activate: On<Activate>,
    clock_seed: Res<RandomSetupClockSeed>,
    mut setup: ResMut<RandomGameSetup>,
    mut preview: ResMut<RandomSetupPreview>,
) {
    regenerate_random_setup_planet(clock_seed.0, &mut setup, &mut preview);
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
    let mut game = create_random_game(
        &preview.0,
        setup.nation,
        setup.difficulty,
        &setup.country_name,
        setup.name_mode == NationNameMode::Historical,
        1,
        names,
    );
    game.set_game_data(GameData::from_news_story_ids(
        assets.news_table().story_ids().to_vec(),
    ));
    if requires_capital_site_selection(setup.difficulty) {
        let map_view_origin = capital_selection_view_origin(game.map(), setup.nation);
        insert_loaded_game(
            commands,
            imperialism_formats::LoadedGame {
                game,
                map_view_origin,
                city_windows: imperialism_formats::CityWindowLayout::default(),
                battle_report_text: Vec::new(),
            },
        );
        next_state.set(AppState::CitySite);
    } else {
        let stop = enter_strategic_map_without_capital_selection(&mut game, setup.nation);
        apply_turn_stop(stop, next_state);
        insert_game_session(commands, game);
    }
}

fn regenerate_random_setup_planet(
    clock_seed: u32,
    setup: &mut RandomGameSetup,
    preview: &mut RandomSetupPreview,
) {
    setup.planet_seed = generate_english_random_setup_name(&mut setup.name_rng);
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
    let ui = generated::spawn_linger_954(commands);
    commands.entity(ui.root).insert((
        PlanetSeedDialogRoot,
        ui,
        ModalWindow,
        DespawnOnExit(AppState::RandomSetup),
    ));
}

fn bind_planet_seed_dialog(
    mut commands: Commands,
    ui: Single<&generated::Linger954, Added<PlanetSeedDialogRoot>>,
    setup: Res<RandomGameSetup>,
) {
    commands.entity(ui.plan).insert((
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

    commands
        .entity(ui.okay)
        .insert((PlanetSeedAccept, ModalDefault, DismissWindow, TabIndex(1)))
        .observe(on_planet_seed_accept);
    // Retail cancel control stays disabled; Escape does not dismiss.
    commands.entity(ui.canc).insert(ModalCancel);
}

#[derive(SystemParam)]
struct PlanetSeedCommit<'w, 's> {
    fields: Query<'w, 's, &'static EditableText, With<PlanetSeedField>>,
    clock_seed: Res<'w, RandomSetupClockSeed>,
    setup: ResMut<'w, RandomGameSetup>,
    preview: ResMut<'w, RandomSetupPreview>,
}

fn on_planet_seed_accept(_activate: On<Activate>, mut commit: PlanetSeedCommit) {
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
        let radio = |commands: &mut Commands| {
            commands
                .spawn((bevy::ui_widgets::RadioButton, ChildOf(root)))
                .id()
        };
        let control =
            |commands: &mut Commands| commands.spawn((Node::default(), ChildOf(root))).id();
        let ui = generated::Startup1501 {
            root,
            base: root,
            main: root,
            hot: root,
            stuf: root,
            map: root,
            tcou: root,
            flag: root,
            coun: control(&mut commands),
            okay: control(&mut commands),
            diff: root,
            dif0: radio(&mut commands),
            dif1: radio(&mut commands),
            dif2: radio(&mut commands),
            dif3: radio(&mut commands),
            dif4: radio(&mut commands),
            dift: root,
            tnam: root,
            name: root,
            hist: radio(&mut commands),
            rand: radio(&mut commands),
            key: control(&mut commands),
            auto: root,
            canc: root,
            cncl: control(&mut commands),
            coat: root,
            glob: control(&mut commands),
        };
        commands.entity(root).insert(ui);
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
            name_rng: RetailLcg::from_state(1),
        };
        let mut app = App::new();
        app.insert_resource(setup).add_systems(
            Update,
            (
                spawn_binding_fixture,
                |mut commands: Commands,
                 ui: Single<&generated::Startup1501, Added<RandomSetupRoot>>,
                 setup: Res<RandomGameSetup>| {
                    bind_random_setup_controls(&mut commands, **ui, &setup);
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
            .query_filtered::<(&EditableText, Has<AutoFocus>, &TextCursorStyle), With<CountryNameField>>();
        let (field, auto_focus, cursor) = fields.single(app.world()).unwrap();
        assert_eq!(field.value(), "Country");
        assert_eq!(field.max_characters, Some(COUNTRY_NAME_MAX_CHARS));
        assert!(auto_focus);
        assert_eq!(cursor.selected_text_color, Some(Color::BLACK));
        let mut globe = app
            .world_mut()
            .query_filtered::<Has<ActivateOnPress>, With<RandomSetupGlobe>>();
        assert!(
            globe
                .iter(app.world())
                .any(|activate_on_press| activate_on_press)
        );
    }

    #[test]
    fn activating_globe_advances_name_stream_and_rebuilds_preview() {
        let clock_seed = 1;
        let setup = RandomGameSetup {
            planet_seed: "Initial".to_owned(),
            topology: MapTopology::Wrapping,
            nation: MajorNationId::new(0),
            country_name: "Country".to_owned(),
            difficulty: Difficulty::Hard,
            name_mode: NationNameMode::Random,
            name_rng: RetailLcg::from_state(clock_seed),
        };
        let preview = RandomSetupPreview(generate_random_setup_preview_with_clock_seed(
            setup.planet_seed.as_bytes(),
            setup.topology,
            clock_seed,
            RetailCrtRng::from_state(clock_seed),
        ));
        let initial_preview = preview.clone();
        let mut app = App::new();
        app.insert_resource(RandomSetupClockSeed(clock_seed))
            .insert_resource(setup)
            .insert_resource(preview);
        let globe = app
            .world_mut()
            .spawn(RandomSetupGlobe)
            .observe(on_random_setup_globe)
            .id();

        app.world_mut()
            .commands()
            .trigger(Activate { entity: globe });
        app.world_mut().flush();
        assert_eq!(
            app.world().resource::<RandomGameSetup>().planet_seed,
            "Woopnist"
        );
        assert_ne!(
            app.world().resource::<RandomSetupPreview>().clone(),
            initial_preview
        );

        app.world_mut()
            .commands()
            .trigger(Activate { entity: globe });
        app.world_mut().flush();
        assert_eq!(
            app.world().resource::<RandomGameSetup>().planet_seed,
            "Purtast"
        );
    }
}
