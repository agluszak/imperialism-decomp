use super::*;
use imperialism_formats::{LegacySaveV62, load_game_from_path};

const BEGINNING_OF_GAME: &[u8] =
    include_bytes!("../../../../../../fixtures/retail/beginning_of_game.imp");

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

fn test_app(initial: AppState) -> App {
    let mut app = App::new();
    app.add_plugins(MinimalPlugins)
        .add_plugins(bevy::state::app::StatesPlugin)
        .add_message::<AppExit>()
        .insert_state(initial)
        .init_resource::<LoadSaveReturn>();
    register_load_save_logic(&mut app);
    app.add_systems(
        OnEnter(AppState::LoadSave),
        (spawn_test_load_save, bind_test_load_save).chain(),
    );
    app
}

fn spawn_test_load_save(mut commands: Commands, request: Res<LoadSaveRequest>) {
    let root = commands
        .spawn((
            LoadSaveRoot {
                mode: request.0,
                selected: None,
                renaming: false,
            },
            Node::default(),
            DespawnOnExit(AppState::LoadSave),
        ))
        .id();
    for tag in SLOT_TAGS {
        commands.spawn((RetailTag(tag), Text::new(String::new()), ChildOf(root)));
    }
    commands.spawn((RetailTag(fourcc!("okay")), Node::default(), ChildOf(root)));
    commands.spawn((RetailTag(fourcc!("cncl")), Node::default(), ChildOf(root)));
    commands.spawn((RetailTag(fourcc!("otto")), Node::default(), ChildOf(root)));
    commands.spawn((
        RetailTag(fourcc!("info")),
        LoadSaveInfo,
        Text::new(String::new()),
        ChildOf(root),
    ));
}

fn bind_test_load_save(
    mut commands: Commands,
    root: Single<(Entity, &LoadSaveRoot), Added<LoadSaveRoot>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
) {
    let (entity, screen) = root.into_inner();
    bind_load_save_actions(&mut commands, entity, &children, &tags, screen.mode);
}

#[test]
fn cancel_restores_the_previous_application_state() {
    let mut app = test_app(AppState::MainMenu);
    app.insert_resource(LoadSaveReturn(AppState::MainMenu));
    app.insert_resource(LoadSaveRequest(LoadSaveMode::Load));
    app.world_mut()
        .resource_mut::<NextState<AppState>>()
        .set(AppState::LoadSave);
    app.update();
    assert_eq!(
        app.world().resource::<State<AppState>>().get(),
        &AppState::LoadSave
    );

    let cancel = app
        .world_mut()
        .query_filtered::<Entity, With<LoadSaveAction>>()
        .iter(app.world())
        .find(|entity| app.world().get::<LoadSaveAction>(*entity) == Some(&LoadSaveAction::Cancel))
        .unwrap();
    app.world_mut()
        .commands()
        .trigger(Activate { entity: cancel });
    app.world_mut().flush();
    app.update();
    assert_eq!(
        app.world().resource::<State<AppState>>().get(),
        &AppState::MainMenu
    );
}

#[test]
fn successful_load_replaces_the_session_and_enters_the_saved_phase() {
    let original = fixture_state();
    let dir = tempfile::tempdir().unwrap();
    save_current_game(dir.path(), SaveSlot::Numbered(1), &original, "England").unwrap();
    let bytes = std::fs::read(retail_save_path(dir.path(), SaveSlot::Numbered(1))).unwrap();
    let selected = peek_save_header(&bytes)
        .and_then(|header| NationId::try_new(header.active_nation))
        .expect("saved header names a nation in range");
    let game =
        load_game_from_bytes(&bytes, runtime_context_for_load(Some(&original), selected)).unwrap();
    assert_eq!(game, original);
    assert_eq!(loaded_game_destination(&game), AppState::StrategicMap);
}

#[test]
fn save_helper_overwrites_an_existing_slot_file() {
    let original = fixture_state();
    let dir = tempfile::tempdir().unwrap();
    save_current_game(dir.path(), SaveSlot::Numbered(0), &original, "First").unwrap();
    save_current_game(dir.path(), SaveSlot::Numbered(0), &original, "Second").unwrap();
    let loaded = load_game_from_path(
        retail_save_path(dir.path(), SaveSlot::Numbered(0)),
        runtime_context_for_load(Some(&original), original.turn().selected_nation),
    )
    .unwrap();
    assert_eq!(loaded, original);
    let bytes = std::fs::read(retail_save_path(dir.path(), SaveSlot::Numbered(0))).unwrap();
    assert_eq!(
        peek_save_header(&bytes).map(|header| header.label),
        Some("Second".to_owned())
    );
}

#[test]
fn save_header_owners_compose_the_retail_satellite_preview() {
    let original = fixture_state();
    let dir = tempfile::tempdir().unwrap();
    save_current_game(dir.path(), SaveSlot::Numbered(0), &original, "Preview").unwrap();
    let bytes = std::fs::read(retail_save_path(dir.path(), SaveSlot::Numbered(0))).unwrap();
    let owners = peek_save_preview_owners(&bytes).expect("written save has preview tiles");
    for (index, owner) in owners.iter().enumerate() {
        assert_eq!(
            *owner,
            original.map()[TileId::new(index as u16)].owner_nation
        );
    }
    let pixels = satellite_preview_indices(
        |tile| owners.get(usize::from(tile.get())).copied().flatten(),
        original.turn().active_nation,
    );
    assert_eq!(pixels.len(), 324 * 180);
    assert!(
        pixels.iter().any(|&index| index != 0x10),
        "satellite preview should paint claimed land, not only the off-map key"
    );
}

#[test]
fn in_game_load_inherits_the_live_session_rng() {
    let original = fixture_state();
    let dir = tempfile::tempdir().unwrap();
    save_current_game(dir.path(), SaveSlot::Numbered(0), &original, "England").unwrap();
    let loaded = load_game_from_path(
        retail_save_path(dir.path(), SaveSlot::Numbered(0)),
        runtime_context_for_load(Some(&original), original.turn().selected_nation),
    )
    .unwrap();
    assert_eq!(loaded.rng(), original.rng());
}

#[test]
fn main_menu_load_uses_retail_startup_rng_context() {
    let original = fixture_state();
    let dir = tempfile::tempdir().unwrap();
    save_current_game(dir.path(), SaveSlot::Numbered(0), &original, "England").unwrap();
    let loaded = load_game_from_path(
        retail_save_path(dir.path(), SaveSlot::Numbered(0)),
        runtime_context_for_load(None, original.turn().selected_nation),
    )
    .unwrap();
    assert_eq!(
        loaded.rng().map_generation.state(),
        0,
        "main-menu load leaves the map LCG at its BSS-zero startup value"
    );
    assert_ne!(
        loaded.rng().crt_rand,
        original.rng().crt_rand,
        ".imp does not persist CRT rand; a main-menu load uses the clock-seeded stream"
    );
    assert_ne!(
        loaded.rng().zone_status,
        original.rng().zone_status,
        ".imp does not persist the zone LCG; a main-menu load uses the tick-derived stream"
    );
}
