use crate::RetailAssetsResource;
use crate::ui::battle_reports::battle_report_texts_for_save;
use crate::ui::generated;
use crate::ui::linger::{bind_linger_dialog, spawn_linger_dialog};
use crate::ui::retail::{RetailPictureSwap, RetailTree, RetailUiAssets};
use crate::ui::satellite_preview::SatellitePreview;
use crate::ui::window::{ModalWindow, bind_modal_keys, dismiss_on_activate};
use crate::ui::{
    BattleReportPresentation, CityWindows, GameSession, StrategicMapSession, insert_loaded_game,
    remove_game_session,
};
use crate::{AppState, ReturnTo};
use bevy::app::AppExit;
use bevy::input_focus::AutoFocus;
use bevy::prelude::*;
use bevy::text::{EditableText, EditableTextFilter, TextCursorStyle};
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, Button, SelectAllOnFocus};
use imperialism_core::{GameState, NationId, PhaseCode, TileId, TileOwnerTag};
use imperialism_formats::{
    BattleReportText, CityWindowLayout, FourCc, LegacyGameStateContext, LoadGameError,
    NUMBERED_SAVE_SLOT_COUNT, OverwritePolicy, PictureId, SAVE_LABEL_MAX_CHARS,
    SaveDirectoryListing, SaveFileError, SaveHeaderInfo, SaveSlot, fourcc, list_save_slots,
    load_game_from_bytes, normalize_save_label, peek_save_header, peek_save_preview_owners,
    retail_save_path, write_game_state, write_save_file,
};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const SLOT_TAGS: [FourCc; NUMBERED_SAVE_SLOT_COUNT as usize] = [
    fourcc!("slt0"),
    fourcc!("slt1"),
    fourcc!("slt2"),
    fourcc!("slt3"),
    fourcc!("slt4"),
    fourcc!("slt5"),
    fourcc!("slt6"),
    fourcc!("slt7"),
];
const AUTOSAVE_SESSION_SLOT: i32 = 0xa1;
const LOAD_OKAY_IDLE_PICTURE: PictureId = PictureId::new(4524);
const LOAD_OKAY_ACTIVE_PICTURE: PictureId = PictureId::new(4525);
const EMPTY_SLOT_STRING_GROUP: u16 = 0x2737;
const EMPTY_SLOT_STRING_INDEX: u16 = 0xd;
const DIFFICULTY_STRING_GROUP: u16 = 0x2737;
const DIFFICULTY_STRING_BASE: u16 = 0xd;
const CONFIRM_LOAD_STRING_GROUP: u16 = 0x2737;
const CONFIRM_LOAD_STRING_INDEX: u16 = 0x33;
const PICK_SLOT_STRING_GROUP: u16 = 0x2758;
const PICK_SLOT_STRING_INDEX: u16 = 0x17;
const FLAG_MENU_STRING_GROUP: u16 = 0x2743;
const FLAG_MENU_ROWS: [(FourCc, Option<FourCc>, Option<FlagMenuAction>); 8] = [
    (fourcc!("txt0"), None, None),
    (
        fourcc!("txt1"),
        Some(fourcc!("save")),
        Some(FlagMenuAction::Save),
    ),
    (
        fourcc!("txt2"),
        Some(fourcc!("load")),
        Some(FlagMenuAction::Load),
    ),
    (
        fourcc!("txt3"),
        Some(fourcc!("newg")),
        Some(FlagMenuAction::NewGame),
    ),
    (
        fourcc!("txt4"),
        Some(fourcc!("pref")),
        Some(FlagMenuAction::Preferences),
    ),
    (
        fourcc!("txt5"),
        Some(fourcc!("cred")),
        Some(FlagMenuAction::Credits),
    ),
    (
        fourcc!("txt6"),
        Some(fourcc!("quit")),
        Some(FlagMenuAction::Quit),
    ),
    (fourcc!("txt7"), Some(fourcc!("cncl")), None),
];

/// Directory that holds retail `slotN.imp` / `slotA.imp` files.
#[derive(Resource, Clone, Debug, Eq, PartialEq)]
pub(crate) struct SaveDirectory(pub(crate) PathBuf);

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
struct OpenFlagMenu;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LoadSaveMode {
    Load,
    Save,
}

/// Mode to use when entering `AppState::LoadSave`.
#[derive(Resource, Clone, Copy, Debug, Eq, PartialEq)]
struct LoadSaveRequest(LoadSaveMode);

pub(crate) fn open_load_save(
    commands: &mut Commands,
    next_state: &mut NextState<AppState>,
    mode: LoadSaveMode,
    return_to: AppState,
) {
    commands.insert_resource(LoadSaveRequest(mode));
    commands.insert_resource(ReturnTo(return_to));
    next_state.set(AppState::LoadSave);
}

#[derive(Component)]
struct PendingLoadSave(LoadSaveMode);

#[derive(Component)]
struct LoadSaveRoot {
    mode: LoadSaveMode,
    selected: Option<SaveSlot>,
    renaming: bool,
    info: Entity,
    map: Entity,
    name_field: Option<Entity>,
    presentation: LoadSavePresentation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoadSavePreviewKey {
    CurrentGame,
    Slot(SaveSlot),
}

#[derive(Component, Default)]
struct LoadSaveMapPreview {
    shown: Option<LoadSavePreviewKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SlotPresentation {
    label: String,
    info: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LoadSavePresentation {
    slots: [Option<SlotPresentation>; NUMBERED_SAVE_SLOT_COUNT as usize],
    autosave: Option<SlotPresentation>,
    empty_label: String,
}

#[derive(Component)]
enum LoadSaveNotice {
    PickSlot,
    ConfirmLoad,
    Error(String),
}

#[derive(Component)]
struct FlagMenuRoot;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FlagMenuAction {
    Save,
    Load,
    NewGame,
    Preferences,
    Credits,
    Quit,
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

pub(crate) struct LoadSavePlugin;

impl Plugin for LoadSavePlugin {
    fn build(&self, app: &mut App) {
        app.add_systems(
            OnEnter(AppState::LoadSave),
            (enter_load_save, bind_load_save).chain(),
        )
        .add_systems(
            Update,
            (bind_load_save_notice, sync_load_save_preview).run_if(in_state(AppState::LoadSave)),
        )
        .add_systems(
            Update,
            (bind_flag_menu, bind_flag_menu_prompt).run_if(in_state(AppState::StrategicMap)),
        )
        .add_systems(
            OnExit(AppState::LoadSave),
            crate::ui::session::clear_return_to,
        );
    }
}

/// Retail `DoRead` never stores or reseeds these streams. CRT `rand()` is a process
/// global seeded by `TSimMgr::ISimMgr` via `srand(time(0))`; the map LCG is BSS-zero
/// until map generation; the zone LCG starts as `GetTickCountDiv16()`. A later load
/// leaves whatever the process currently has.
fn runtime_context_for_load(existing: Option<&GameState>) -> LegacyGameStateContext {
    if let Some(state) = existing {
        let rng = state.rng();
        return LegacyGameStateContext {
            crt_rand_state: rng.crt_rand.state(),
            map_generation_lcg: rng.map_generation.state(),
            zone_status_lcg: rng.zone_status.state(),
        };
    }
    LegacyGameStateContext {
        crt_rand_state: clock_derived_crt_seed(),
        map_generation_lcg: 0,
        zone_status_lcg: tick_derived_zone_seed(),
    }
}

fn clock_derived_crt_seed() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs() as u32)
}

fn tick_derived_zone_seed() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| (duration.as_millis() / 16) as u32)
}

pub(crate) fn save_current_game(
    directory: &Path,
    slot: SaveSlot,
    session: &GameSession,
    origin: TileId,
    city_windows: &CityWindowLayout,
    captured_reports: &[BattleReportText],
    assets: Option<&RetailUiAssets>,
    label: &str,
) -> Result<(), SaveFileError> {
    let label = normalize_save_label(label);
    let session_slot = match slot {
        SaveSlot::Numbered(index) => i32::from(index),
        SaveSlot::Autosave => AUTOSAVE_SESSION_SLOT,
    };
    let battle_report_text = battle_report_texts_for_save(assets, session, captured_reports);
    let bytes = write_game_state(
        &session.game,
        origin,
        city_windows,
        &battle_report_text,
        &label,
        session_slot,
    );
    write_save_file(
        retail_save_path(directory, slot),
        &bytes,
        OverwritePolicy::Replace,
    )
}

fn loaded_game_destination(game: &GameState) -> AppState {
    match game.phase() {
        PhaseCode::STRATEGIC_MAP => AppState::StrategicMap,
        PhaseCode::CAPITAL_SELECTION => AppState::CitySite,
        phase => {
            panic!("load_game_from_bytes must reject phase {phase:?} before replacing the session")
        }
    }
}

fn enter_load_save(mut commands: Commands, request: Res<LoadSaveRequest>) {
    let root = commands.spawn_scene(generated::linger_1502()).id();
    commands.entity(root).insert((
        PendingLoadSave(request.0),
        DespawnOnExit(AppState::LoadSave),
    ));
}

fn bind_load_save(
    mut commands: Commands,
    pending: Query<(Entity, &PendingLoadSave), Added<PendingLoadSave>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    save_dir: Res<SaveDirectory>,
) {
    let Ok((root_entity, pending)) = pending.single() else {
        return;
    };
    let mode = pending.0;
    let info = tree.find(root_entity, fourcc!("info"));
    let map = tree.find(root_entity, fourcc!("map "));
    bind_load_save_actions(&mut commands, root_entity, &tree, mode);
    let listing = list_save_slots(&save_dir.0);
    let empty_label = assets.ui_string(EMPTY_SLOT_STRING_GROUP, EMPTY_SLOT_STRING_INDEX);
    let presentation = presentation_from_listing(&listing, &empty_label, &assets);
    populate_load_save_slots(&mut commands, root_entity, &tree, mode, &presentation);
    if mode == LoadSaveMode::Load {
        apply_load_okay_pictures(&mut commands, &mut assets, root_entity, &tree);
        commands
            .entity(tree.find(root_entity, fourcc!("otto")))
            .remove::<InteractionDisabled>();
    }
    commands.entity(info).insert(Text::new(String::new()));
    let preview_image = assets.add_image(Image::transparent());
    commands
        .entity(map)
        .insert((LoadSaveMapPreview::default(), ImageNode::new(preview_image)));
    commands.entity(root_entity).insert(LoadSaveRoot {
        mode,
        selected: None,
        renaming: false,
        info,
        map,
        name_field: None,
        presentation,
    });
    commands.entity(root_entity).remove::<PendingLoadSave>();
}

fn bind_load_save_actions(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    mode: LoadSaveMode,
) {
    for (index, tag) in SLOT_TAGS.iter().copied().enumerate() {
        let entity = tree.find(root, tag);
        let slot = SaveSlot::numbered(index as u8).expect("slot tags are numbered 0..=7");
        commands.entity(entity).insert(Button);
        observe_select_slot(commands, entity, slot);
    }
    commands
        .entity(tree.find(root, fourcc!("okay")))
        .remove::<InteractionDisabled>()
        .observe(on_okay);
    commands
        .entity(tree.find(root, fourcc!("cncl")))
        .remove::<InteractionDisabled>()
        .observe(on_cancel);
    let otto = tree.find(root, fourcc!("otto"));
    observe_select_slot(commands, otto, SaveSlot::Autosave);
    if mode == LoadSaveMode::Save {
        commands.entity(otto).insert(InteractionDisabled);
    }
}

fn observe_select_slot(commands: &mut Commands, entity: Entity, slot: SaveSlot) {
    commands.entity(entity).observe(
        move |activate: On<Activate>,
              notices: Query<(), With<LoadSaveNotice>>,
              mut roots: Query<&mut LoadSaveRoot>,
              mut texts: Query<&mut Text>,
              mut commands: Commands| {
            if !notices.is_empty() {
                return;
            }
            let Ok(mut root) = roots.single_mut() else {
                return;
            };
            select_slot(&mut commands, &mut root, activate.entity, slot, &mut texts);
        },
    );
}

fn presentation_from_listing(
    listing: &SaveDirectoryListing,
    empty_label: &str,
    assets: &RetailUiAssets,
) -> LoadSavePresentation {
    LoadSavePresentation {
        slots: std::array::from_fn(|index| {
            listing.slots[index]
                .as_ref()
                .map(|header| slot_presentation(header, assets))
        }),
        autosave: listing
            .autosave
            .as_ref()
            .map(|header| slot_presentation(header, assets)),
        empty_label: empty_label.to_owned(),
    }
}

fn slot_presentation(header: &SaveHeaderInfo, assets: &RetailUiAssets) -> SlotPresentation {
    let difficulty = assets.ui_string(
        DIFFICULTY_STRING_GROUP,
        DIFFICULTY_STRING_BASE + u16::from(header.difficulty),
    );
    SlotPresentation {
        label: header.label.clone(),
        info: format!(
            "{}, {difficulty}",
            i32::from(header.economic_year_offset) + 1815
        ),
    }
}

fn populate_load_save_slots(
    commands: &mut Commands,
    root: Entity,
    tree: &RetailTree,
    mode: LoadSaveMode,
    presentation: &LoadSavePresentation,
) {
    for (index, tag) in SLOT_TAGS.iter().copied().enumerate() {
        let entity = tree.find(root, tag);
        match presentation.slots[index].as_ref() {
            Some(slot) => {
                commands
                    .entity(entity)
                    .insert((Text::new(slot.label.clone()), Visibility::Visible))
                    .remove::<InteractionDisabled>();
            }
            None if mode == LoadSaveMode::Load => {
                commands.entity(entity).insert((
                    Text::new(String::new()),
                    Visibility::Hidden,
                    InteractionDisabled,
                ));
            }
            None => {
                commands
                    .entity(entity)
                    .insert((
                        Text::new(presentation.empty_label.clone()),
                        Visibility::Visible,
                    ))
                    .remove::<InteractionDisabled>();
            }
        }
    }
}

fn apply_load_okay_pictures(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    root: Entity,
    tree: &RetailTree,
) {
    let okay = tree.find(root, fourcc!("okay"));
    let idle = assets.picture(LOAD_OKAY_IDLE_PICTURE);
    let active = assets.picture(LOAD_OKAY_ACTIVE_PICTURE);
    commands.entity(okay).insert((
        RetailPictureSwap {
            idle: idle.clone(),
            active,
        },
        ImageNode::new(idle),
    ));
}

fn satellite_preview(
    owners: impl Fn(TileId) -> Option<TileOwnerTag>,
    selected_nation: NationId,
) -> SatellitePreview {
    let mut preview = SatellitePreview::compose(owners);
    preview.enhance(selected_nation);
    preview
}

fn apply_satellite_preview(
    assets: &mut RetailUiAssets,
    image_node: &mut ImageNode,
    preview: &SatellitePreview,
) {
    assets.replace_image(
        &image_node.image,
        preview.to_image(assets.default_dib_palette()),
    );
}

fn sync_load_save_preview(
    mut assets: RetailUiAssets,
    roots: Query<&LoadSaveRoot>,
    mut maps: Query<(&mut ImageNode, &mut LoadSaveMapPreview)>,
    save_dir: Res<SaveDirectory>,
    session: Option<Res<GameSession>>,
) {
    let Ok(root) = roots.single() else {
        return;
    };
    let Ok((mut image_node, mut preview)) = maps.get_mut(root.map) else {
        return;
    };
    let key = match root.mode {
        LoadSaveMode::Save => LoadSavePreviewKey::CurrentGame,
        LoadSaveMode::Load => match root.selected {
            Some(slot) => LoadSavePreviewKey::Slot(slot),
            None => return,
        },
    };
    if preview.shown == Some(key) {
        return;
    }
    preview.shown = Some(key);
    match key {
        LoadSavePreviewKey::CurrentGame => {
            let Some(session) = session else {
                return;
            };
            let selected = session.game.turn().active_nation;
            let preview = satellite_preview(|tile| session.game.map()[tile].owner_nation, selected);
            apply_satellite_preview(&mut assets, &mut image_node, &preview);
        }
        LoadSavePreviewKey::Slot(slot) => {
            let path = retail_save_path(&save_dir.0, slot);
            let Ok(bytes) = std::fs::read(path) else {
                return;
            };
            let Some(owners) = peek_save_preview_owners(&bytes) else {
                return;
            };
            let Some(selected) =
                peek_save_header(&bytes).and_then(|header| NationId::try_new(header.active_nation))
            else {
                return;
            };
            let preview = satellite_preview(
                |tile| owners.get(usize::from(tile.get())).copied().flatten(),
                selected,
            );
            apply_satellite_preview(&mut assets, &mut image_node, &preview);
        }
    }
}

fn on_cancel(
    _activate: On<Activate>,
    notices: Query<(), With<LoadSaveNotice>>,
    returning: Res<ReturnTo>,
    mut next_state: ResMut<NextState<AppState>>,
) {
    if !notices.is_empty() {
        return;
    }
    next_state.set(returning.0);
}

#[allow(clippy::too_many_arguments)]
fn on_okay(
    _activate: On<Activate>,
    notices: Query<(), With<LoadSaveNotice>>,
    roots: Query<&LoadSaveRoot>,
    editables: Query<&EditableText>,
    save_dir: Option<Res<SaveDirectory>>,
    returning: Res<ReturnTo>,
    session: Option<Res<GameSession>>,
    map: Option<Res<StrategicMapSession>>,
    city_windows: Option<Res<CityWindows>>,
    battle_reports: Option<Res<BattleReportPresentation>>,
    assets: Option<RetailUiAssets>,
    mut next_state: ResMut<NextState<AppState>>,
    mut commands: Commands,
) {
    if !notices.is_empty() {
        return;
    }
    let Ok(root) = roots.single() else {
        return;
    };
    let Some(save_dir) = save_dir else {
        return;
    };
    confirm_or_apply(
        &mut commands,
        root,
        &editables,
        &save_dir.0,
        session.as_deref(),
        map.as_deref(),
        city_windows.as_deref(),
        battle_reports.as_deref(),
        assets.as_ref(),
        returning.0,
        &mut next_state,
    );
}

fn select_slot(
    commands: &mut Commands,
    root: &mut LoadSaveRoot,
    entity: Entity,
    slot: SaveSlot,
    texts: &mut Query<&mut Text>,
) {
    if root.selected == Some(slot) {
        return;
    }
    if root.mode == LoadSaveMode::Save && root.renaming {
        return;
    }
    root.selected = Some(slot);
    if root.mode == LoadSaveMode::Load {
        if let Some(caption) = slot_info(&root.presentation, slot)
            && let Ok(mut text) = texts.get_mut(root.info)
        {
            text.0 = caption.to_owned();
        }
        return;
    }
    if slot == SaveSlot::Autosave {
        return;
    }
    let caption = texts
        .get(entity)
        .map(|text| text.0.clone())
        .unwrap_or_default();
    commands.entity(entity).insert((
        SelectAllOnFocus,
        AutoFocus,
        TextCursorStyle::default(),
        EditableTextFilter::new(|character| !character.is_control()),
        EditableText {
            max_characters: Some(SAVE_LABEL_MAX_CHARS),
            allow_newlines: false,
            ..EditableText::new(caption)
        },
    ));
    root.name_field = Some(entity);
    root.renaming = true;
}

fn slot_info(presentation: &LoadSavePresentation, slot: SaveSlot) -> Option<&str> {
    match slot {
        SaveSlot::Numbered(index) => presentation.slots[usize::from(index)]
            .as_ref()
            .map(|slot| slot.info.as_str()),
        SaveSlot::Autosave => presentation
            .autosave
            .as_ref()
            .map(|slot| slot.info.as_str()),
    }
}

#[allow(clippy::too_many_arguments)]
fn confirm_or_apply(
    commands: &mut Commands,
    root: &LoadSaveRoot,
    editables: &Query<&EditableText>,
    save_dir: &Path,
    session: Option<&GameSession>,
    map: Option<&StrategicMapSession>,
    city_windows: Option<&CityWindows>,
    battle_reports: Option<&BattleReportPresentation>,
    assets: Option<&RetailUiAssets>,
    returning: AppState,
    next_state: &mut NextState<AppState>,
) {
    let Some(slot) = root.selected else {
        if root.mode == LoadSaveMode::Save {
            spawn_notice(commands, LoadSaveNotice::PickSlot);
        }
        return;
    };
    match root.mode {
        LoadSaveMode::Load => {
            if returning != AppState::MainMenu {
                spawn_notice(commands, LoadSaveNotice::ConfirmLoad);
                return;
            }
            apply_load(
                commands,
                save_dir,
                slot,
                session.map(|session| &session.game),
                next_state,
                None,
            );
        }
        LoadSaveMode::Save => {
            let Some(session) = session else {
                return;
            };
            let typed = root
                .name_field
                .and_then(|entity| editables.get(entity).ok())
                .map(|editable| editable.value().to_string())
                .unwrap_or_default();
            let label = if typed.is_empty() {
                root.presentation.empty_label.clone()
            } else {
                typed
            };
            apply_save(
                commands,
                save_dir,
                slot,
                session,
                map,
                city_windows,
                battle_reports,
                assets,
                &label,
                returning,
                next_state,
            );
        }
    }
}

fn apply_load(
    commands: &mut Commands,
    save_dir: &Path,
    slot: SaveSlot,
    existing: Option<&GameState>,
    next_state: &mut NextState<AppState>,
    assets: Option<&RetailAssetsResource>,
) {
    let path = retail_save_path(save_dir, slot);
    if !path.is_file() {
        return;
    }
    let load = (|| {
        let bytes = std::fs::read(&path)?;
        let context = runtime_context_for_load(existing);
        load_game_from_bytes(&bytes, context)
    })();
    match load {
        Ok(mut loaded) => {
            if let Some(assets) = assets {
                loaded
                    .game
                    .set_game_data(crate::ui::retail_game_data(assets));
            }
            let destination = loaded_game_destination(&loaded.game);
            insert_loaded_game(commands, loaded);
            next_state.set(destination);
        }
        Err(error) => spawn_notice(
            commands,
            LoadSaveNotice::Error(
                assets
                    .map(|assets| load_error_text(assets, &error))
                    .unwrap_or_else(|| error.to_string()),
            ),
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_save(
    commands: &mut Commands,
    save_dir: &Path,
    slot: SaveSlot,
    session: &GameSession,
    map: Option<&StrategicMapSession>,
    city_windows: Option<&CityWindows>,
    battle_reports: Option<&BattleReportPresentation>,
    assets: Option<&RetailUiAssets>,
    label: &str,
    returning: AppState,
    next_state: &mut NextState<AppState>,
) {
    let origin = map
        .expect("saving a game requires StrategicMapSession")
        .view
        .detailed_origin(&session.game);
    let city_windows = &city_windows.expect("saving a game requires CityWindows").0;
    let captured = battle_reports
        .expect("saving a game requires BattleReportPresentation")
        .0
        .as_slice();
    match save_current_game(
        save_dir,
        slot,
        session,
        origin,
        city_windows,
        captured,
        assets,
        label,
    ) {
        Ok(()) => next_state.set(returning),
        Err(error) => spawn_notice(commands, LoadSaveNotice::Error(error.to_string())),
    }
}

fn load_error_text(assets: &RetailAssetsResource, error: &LoadGameError) -> String {
    let retail = match error {
        LoadGameError::InvalidMagic | LoadGameError::Truncated => Some(assets.ui_string(0x2737, 7)),
        LoadGameError::UnsupportedVersion(_) => Some(assets.ui_string(0x2737, 8)),
        _ => None,
    };
    retail.unwrap_or_else(|| error.to_string())
}

fn spawn_notice(commands: &mut Commands, notice: LoadSaveNotice) {
    spawn_linger_dialog(commands, notice, AppState::LoadSave);
}

fn bind_load_save_notice(
    mut commands: Commands,
    notice: Single<(Entity, &LoadSaveNotice), Added<LoadSaveNotice>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
) {
    let (root, notice) = notice.into_inner();
    let linger = bind_linger_dialog(&mut commands, root, &tree);
    let body = match notice {
        LoadSaveNotice::PickSlot => {
            assets.ui_string(PICK_SLOT_STRING_GROUP, PICK_SLOT_STRING_INDEX)
        }
        LoadSaveNotice::ConfirmLoad => {
            assets.ui_string(CONFIRM_LOAD_STRING_GROUP, CONFIRM_LOAD_STRING_INDEX)
        }
        LoadSaveNotice::Error(body) => body.clone(),
    };
    linger.set_body(&mut commands, &mut assets, &body);
    commands.entity(linger.okay).remove::<InteractionDisabled>();
    match notice {
        LoadSaveNotice::ConfirmLoad => {
            commands.entity(linger.okay).observe(on_confirm_load_notice);
            commands
                .entity(linger.cancel)
                .remove::<InteractionDisabled>();
        }
        LoadSaveNotice::PickSlot | LoadSaveNotice::Error(_) => {
            commands.entity(linger.cancel).insert(Visibility::Hidden);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn on_confirm_load_notice(
    _activate: On<Activate>,
    roots: Query<&LoadSaveRoot>,
    save_dir: Res<SaveDirectory>,
    session: Option<Res<GameSession>>,
    mut next_state: ResMut<NextState<AppState>>,
    mut commands: Commands,
    assets: Res<RetailAssetsResource>,
) {
    let Ok(root) = roots.single() else {
        return;
    };
    let Some(slot) = root.selected else {
        return;
    };
    apply_load(
        &mut commands,
        &save_dir.0,
        slot,
        session.as_deref().map(|session| &session.game),
        &mut next_state,
        Some(&*assets),
    );
}

pub(crate) fn bind_open_flag_menu(commands: &mut Commands, flag: Entity) {
    commands
        .entity(flag)
        .insert(OpenFlagMenu)
        .remove::<InteractionDisabled>()
        .observe(on_open_flag_menu);
}

fn on_open_flag_menu(_activate: On<Activate>, mut commands: Commands) {
    let root = commands.spawn_scene(generated::linger_4140()).id();
    commands.entity(root).insert((
        FlagMenuRoot,
        ModalWindow,
        DespawnOnExit(AppState::StrategicMap),
    ));
}

fn bind_flag_menu(
    mut commands: Commands,
    root: Single<Entity, Added<FlagMenuRoot>>,
    tree: RetailTree,
    assets: RetailUiAssets,
) {
    let root = *root;
    for (index, (label_tag, control, action)) in FLAG_MENU_ROWS.iter().copied().enumerate() {
        let entity = tree.find(root, label_tag);
        let (font, layout, line_height, _) =
            assets.text_style(imperialism_formats::RetailTextStylePreset::explicit(
                1,
                0,
                if index == 0 { 12 } else { 14 },
                if index > 1 { -2 } else { 1 },
            ));
        let (text_palette, shadow_palette) = if index == 0 {
            (0x5c, 0x28)
        } else {
            (0x28, 0xd2)
        };
        let caption = assets.get_string(FLAG_MENU_STRING_GROUP, index as u16);
        commands.entity(entity).insert((
            Text::new(caption.clone()),
            Label,
            font,
            layout,
            line_height,
            TextColor(assets.palette_color(text_palette)),
            TextShadow {
                offset: Vec2::ONE,
                color: assets.palette_color(shadow_palette),
            },
        ));
        let Some(control_tag) = control else {
            continue;
        };
        let control_entity = tree.find(root, control_tag);
        let mut control = commands.entity(control_entity);
        control
            .insert(AccessibleLabel::new(caption))
            .remove::<InteractionDisabled>();
        if let Some(action) = action {
            control.observe(
                move |_: On<Activate>,
                      prompts: Query<(), With<FlagMenuPrompt>>,
                      mut next_state: ResMut<NextState<AppState>>,
                      mut commands: Commands| {
                    if !prompts.is_empty() {
                        return;
                    }
                    apply_flag_menu_action(action, &mut commands, &mut next_state);
                },
            );
        } else {
            dismiss_on_activate(&mut commands, control_entity, root);
            bind_modal_keys(&mut commands, root, None, Some(control_entity));
        }
    }
}

fn apply_flag_menu_action(
    action: FlagMenuAction,
    commands: &mut Commands,
    next_state: &mut NextState<AppState>,
) {
    match action {
        FlagMenuAction::Save => {
            open_load_save(
                commands,
                next_state,
                LoadSaveMode::Save,
                AppState::StrategicMap,
            );
        }
        FlagMenuAction::Load => {
            open_load_save(
                commands,
                next_state,
                LoadSaveMode::Load,
                AppState::StrategicMap,
            );
        }
        FlagMenuAction::Preferences => {
            commands.insert_resource(ReturnTo(AppState::StrategicMap));
            next_state.set(AppState::Preferences);
        }
        FlagMenuAction::Credits => {
            commands.insert_resource(ReturnTo(AppState::StrategicMap));
            next_state.set(AppState::Credits);
        }
        FlagMenuAction::NewGame => {
            open_flag_menu_prompt(commands, FlagMenuPending::NewGame);
        }
        FlagMenuAction::Quit => {
            open_flag_menu_prompt(commands, FlagMenuPending::Quit);
        }
    }
}

fn open_flag_menu_prompt(commands: &mut Commands, pending: FlagMenuPending) {
    spawn_linger_dialog(
        commands,
        FlagMenuPrompt { kind: pending },
        AppState::StrategicMap,
    );
}

fn bind_flag_menu_prompt(
    mut commands: Commands,
    prompt: Single<(Entity, &FlagMenuPrompt), Added<FlagMenuPrompt>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
) {
    let (root, prompt) = prompt.into_inner();
    // `TViewMgr::DispatchGameStateEventIfLocalizedPromptAccepted` for single-player.
    let index = match prompt.kind {
        FlagMenuPending::NewGame => 0x2b,
        FlagMenuPending::Quit => 0x2a,
    };
    let body = assets.ui_string(0x2737, index);
    let linger = bind_linger_dialog(&mut commands, root, &tree);
    linger.set_body(&mut commands, &mut assets, body);
    commands
        .entity(linger.okay)
        .remove::<InteractionDisabled>()
        .observe(on_flag_menu_prompt_activate);
    commands
        .entity(linger.cancel)
        .remove::<InteractionDisabled>();
}

fn on_flag_menu_prompt_activate(
    _activate: On<Activate>,
    prompts: Query<&FlagMenuPrompt>,
    menus: Query<Entity, With<FlagMenuRoot>>,
    mut next_state: ResMut<NextState<AppState>>,
    mut exit: MessageWriter<AppExit>,
    mut commands: Commands,
) {
    let Ok(prompt) = prompts.single() else {
        return;
    };
    for entity in &menus {
        commands.entity(entity).try_despawn();
    }
    match prompt.kind {
        FlagMenuPending::NewGame => {
            remove_game_session(&mut commands);
            next_state.set(AppState::MainMenu);
        }
        FlagMenuPending::Quit => {
            exit.write(AppExit::Success);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::insert_game_session_world;
    use crate::ui::retail::RetailTag;
    use crate::ui::test_support::beginning_of_game;
    use imperialism_formats::load_game_from_path;

    fn fixture_state() -> GameState {
        beginning_of_game()
    }

    fn save_fixture(directory: &Path, slot: SaveSlot, session: &GameSession, label: &str) {
        save_current_game(
            directory,
            slot,
            session,
            TileId::new(1),
            &CityWindowLayout::default(),
            &[],
            None,
            label,
        )
        .unwrap();
    }

    fn test_app(initial: AppState) -> App {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(bevy::state::app::StatesPlugin)
            .add_plugins(bevy::ui_widgets::ButtonPlugin)
            .add_plugins(crate::ui::UiWindowPlugin)
            .add_message::<AppExit>()
            .insert_state(initial)
            .insert_resource(ReturnTo(AppState::MainMenu));
        app.add_systems(
            OnEnter(AppState::LoadSave),
            (spawn_test_load_save, bind_test_load_save).chain(),
        );
        app
    }

    fn spawn_test_load_save(mut commands: Commands, request: Res<LoadSaveRequest>) {
        let root = commands
            .spawn((
                PendingLoadSave(request.0),
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
            Text::new(String::new()),
            ChildOf(root),
        ));
    }

    fn bind_test_load_save(
        mut commands: Commands,
        pending: Query<(Entity, &PendingLoadSave), Added<PendingLoadSave>>,
        tree: RetailTree,
    ) {
        let Ok((entity, pending)) = pending.single() else {
            return;
        };
        let info = tree.find(entity, fourcc!("info"));
        bind_load_save_actions(&mut commands, entity, &tree, pending.0);
        commands.entity(entity).insert(LoadSaveRoot {
            mode: pending.0,
            selected: None,
            renaming: false,
            info,
            map: info,
            name_field: None,
            presentation: LoadSavePresentation {
                slots: std::array::from_fn(|_| None),
                autosave: None,
                empty_label: String::new(),
            },
        });
        commands.entity(entity).remove::<PendingLoadSave>();
    }

    fn populate_test_save_labels(
        mut commands: Commands,
        root: Single<Entity, With<LoadSaveRoot>>,
        tree: RetailTree,
    ) {
        let presentation = LoadSavePresentation {
            slots: std::array::from_fn(|index| {
                (index == 0).then(|| SlotPresentation {
                    label: "England".to_owned(),
                    info: "1815, Easy".to_owned(),
                })
            }),
            autosave: None,
            empty_label: "Empty Slot".to_owned(),
        };
        populate_load_save_slots(
            &mut commands,
            *root,
            &tree,
            LoadSaveMode::Load,
            &presentation,
        );
    }

    fn tagged(app: &mut App, tag: FourCc) -> Entity {
        app.world_mut()
            .query::<(Entity, &RetailTag)>()
            .iter(app.world())
            .find(|(_, retail)| retail.0 == tag)
            .map(|(entity, _)| entity)
            .expect("tagged control")
    }

    #[test]
    fn selecting_a_save_slot_starts_editing_its_label_and_saves() {
        let mut app = test_app(AppState::StrategicMap);
        let game = fixture_state();
        let directory = tempfile::tempdir().unwrap();
        insert_game_session_world(app.world_mut(), game.clone());
        app.insert_resource(SaveDirectory(directory.path().to_owned()));
        app.insert_resource(LoadSaveRequest(LoadSaveMode::Save));
        app.world_mut()
            .resource_mut::<NextState<AppState>>()
            .set(AppState::LoadSave);
        app.update();

        let slot = tagged(&mut app, fourcc!("slt0"));
        app.world_mut()
            .commands()
            .trigger(Activate { entity: slot });
        app.world_mut().flush();

        let root = app
            .world_mut()
            .query::<&LoadSaveRoot>()
            .single(app.world())
            .unwrap();
        assert_eq!(root.selected, Some(SaveSlot::Numbered(0)));
        assert!(root.renaming);
        assert_eq!(root.name_field, Some(slot));
        assert!(app.world().get::<EditableText>(slot).is_some());

        let okay = tagged(&mut app, fourcc!("okay"));
        app.world_mut()
            .commands()
            .trigger(Activate { entity: okay });
        app.world_mut().flush();
        app.update();

        let bytes = std::fs::read(retail_save_path(directory.path(), SaveSlot::Numbered(0)))
            .expect("clicking okay writes the selected save slot");
        let loaded = load_game_from_bytes(&bytes, runtime_context_for_load(Some(&game))).unwrap();
        assert_eq!(loaded.game, game);
    }

    #[test]
    fn populated_save_slot_displays_its_header_label() {
        let mut app = test_app(AppState::MainMenu);
        app.insert_resource(LoadSaveRequest(LoadSaveMode::Load));
        app.world_mut()
            .resource_mut::<NextState<AppState>>()
            .set(AppState::LoadSave);
        app.update();

        app.add_systems(Update, populate_test_save_labels);
        app.update();

        let slot = tagged(&mut app, fourcc!("slt0"));
        assert_eq!(app.world().get::<Text>(slot).unwrap().0, "England");
        for (index, tag) in SLOT_TAGS.iter().copied().enumerate().skip(1) {
            let entity = tagged(&mut app, tag);
            assert_eq!(
                app.world().get::<Text>(entity).unwrap().0,
                "",
                "empty load slot {index} keeps an empty caption"
            );
        }
    }

    #[test]
    fn successful_load_replaces_the_session_and_enters_the_saved_phase() {
        let original = fixture_state();
        let session = GameSession::new(original.clone());
        let dir = tempfile::tempdir().unwrap();
        save_fixture(dir.path(), SaveSlot::Numbered(1), &session, "England");
        let bytes = std::fs::read(retail_save_path(dir.path(), SaveSlot::Numbered(1))).unwrap();
        let loaded =
            load_game_from_bytes(&bytes, runtime_context_for_load(Some(&original))).unwrap();
        assert_eq!(loaded.game, original);
        assert_eq!(
            loaded_game_destination(&loaded.game),
            AppState::StrategicMap
        );
    }

    #[test]
    fn save_helper_overwrites_an_existing_slot_file() {
        let original = fixture_state();
        let session = GameSession::new(original.clone());
        let dir = tempfile::tempdir().unwrap();
        save_fixture(dir.path(), SaveSlot::Numbered(0), &session, "First");
        save_fixture(dir.path(), SaveSlot::Numbered(0), &session, "Second");
        let loaded = load_game_from_path(
            retail_save_path(dir.path(), SaveSlot::Numbered(0)),
            runtime_context_for_load(Some(&original)),
        )
        .unwrap();
        assert_eq!(loaded.game, original);
        let bytes = std::fs::read(retail_save_path(dir.path(), SaveSlot::Numbered(0))).unwrap();
        assert_eq!(
            peek_save_header(&bytes).map(|header| header.label),
            Some("Second".to_owned())
        );
    }

    #[test]
    fn in_game_load_inherits_the_live_session_rng() {
        let original = fixture_state();
        let session = GameSession::new(original.clone());
        let dir = tempfile::tempdir().unwrap();
        save_fixture(dir.path(), SaveSlot::Numbered(0), &session, "England");
        let loaded = load_game_from_path(
            retail_save_path(dir.path(), SaveSlot::Numbered(0)),
            runtime_context_for_load(Some(&original)),
        )
        .unwrap();
        assert_eq!(loaded.game.rng(), original.rng());
    }

    #[test]
    fn main_menu_load_uses_retail_startup_rng_context() {
        let original = fixture_state();
        let session = GameSession::new(original.clone());
        let dir = tempfile::tempdir().unwrap();
        save_fixture(dir.path(), SaveSlot::Numbered(0), &session, "England");
        let loaded = load_game_from_path(
            retail_save_path(dir.path(), SaveSlot::Numbered(0)),
            runtime_context_for_load(None),
        )
        .unwrap();
        assert_eq!(
            loaded.game.rng().map_generation.state(),
            0,
            "main-menu load leaves the map LCG at its BSS-zero startup value"
        );
        assert_ne!(
            loaded.game.rng().crt_rand,
            original.rng().crt_rand,
            ".imp does not persist CRT rand; a main-menu load uses the clock-seeded stream"
        );
        assert_ne!(
            loaded.game.rng().zone_status,
            original.rng().zone_status,
            ".imp does not persist the zone LCG; a main-menu load uses the tick-derived stream"
        );
    }
}
