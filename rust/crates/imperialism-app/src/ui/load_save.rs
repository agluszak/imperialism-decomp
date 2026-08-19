use crate::RetailAssetsResource;
use crate::ui::GameSession;
use crate::ui::battle_reports::battle_report_texts_for_save;
use crate::ui::generated;
use crate::ui::hover_help::get_string;
use crate::ui::linger::{bind_linger_dialog, spawn_linger_dialog};
use crate::ui::retail::{ModalDialog, RetailPictureSwap, RetailTree, RetailUiAssets};
use crate::ui::satellite_preview::SatellitePreview;
use crate::ui::retail::{RetailPictureSwap, RetailTree, RetailUiAssets};
use crate::ui::window::{DismissWindow, ModalCancel, ModalWindow};
use crate::{AppState, ReturnTo};
use bevy::app::AppExit;
use bevy::input_focus::AutoFocus;
use bevy::prelude::*;
use bevy::text::{EditableText, EditableTextFilter, TextCursorStyle};
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, SelectAllOnFocus};
use imperialism_core::{GameState, NationId, PhaseCode, TileId, TileOwnerTag};
use imperialism_formats::{
    FourCc, LegacyGameStateContext, LoadGameError, NUMBERED_SAVE_SLOT_COUNT, OverwritePolicy,
    PictureId, SAVE_LABEL_MAX_CHARS, SaveDirectoryListing, SaveFileError, SaveHeaderInfo, SaveSlot,
    fourcc, list_save_slots, load_game_from_bytes, normalize_save_label, peek_save_header,
    peek_save_preview_owners, retail_save_path, write_game_state, write_save_file,
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
const LOAD_OKAY_IDLE_PICTURE: i16 = 4524;
const LOAD_OKAY_ACTIVE_PICTURE: i16 = 4525;
const EMPTY_SLOT_STRING_GROUP: i16 = 0x2737;
const EMPTY_SLOT_STRING_INDEX: i16 = 0xd;
const DIFFICULTY_STRING_GROUP: i16 = 0x2737;
const DIFFICULTY_STRING_BASE: i16 = 0xd;
const CONFIRM_LOAD_STRING_GROUP: i16 = 0x2737;
const CONFIRM_LOAD_STRING_INDEX: i16 = 0x33;
const PICK_SLOT_STRING_GROUP: i16 = 0x2758;
const PICK_SLOT_STRING_INDEX: i16 = 0x17;
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
struct LoadSaveRoot {
    mode: LoadSaveMode,
    selected: Option<SaveSlot>,
    renaming: bool,
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum LoadSaveAction {
    SelectSlot(SaveSlot),
    Okay,
    Cancel,
}

#[derive(Component)]
struct SaveNameField;

#[derive(Component)]
struct LoadSaveInfo;

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

#[derive(Component, Clone, Debug, Eq, PartialEq)]
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
struct ConfirmLoadNotice;

#[derive(Component)]
struct FlagMenuRoot;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Component)]
struct AcceptFlagMenuPrompt;

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
    label: &str,
) -> Result<(), SaveFileError> {
    let label = normalize_save_label(label);
    let session_slot = match slot {
        SaveSlot::Numbered(index) => i32::from(index),
        SaveSlot::Autosave => AUTOSAVE_SESSION_SLOT,
    };
    let battle_report_text = battle_report_texts_for_save(session);
    let bytes = write_game_state(
        &session.game,
        session.map_view_origin,
        &session.city_windows,
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
    match game.turn().phase() {
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
        LoadSaveRoot {
            mode: request.0,
            selected: None,
            renaming: false,
        },
        DespawnOnExit(AppState::LoadSave),
    ));
}

fn bind_load_save(
    mut commands: Commands,
    root: Single<(Entity, &LoadSaveRoot), Added<LoadSaveRoot>>,
    tree: RetailTree,
    mut assets: RetailUiAssets,
    save_dir: Res<SaveDirectory>,
) {
    let (root_entity, screen) = root.into_inner();
    let mode = screen.mode;
    bind_load_save_actions(&mut commands, root_entity, &tree, mode);
    let listing = list_save_slots(&save_dir.0);
    let empty_label = assets
        .string(EMPTY_SLOT_STRING_GROUP, EMPTY_SLOT_STRING_INDEX)
        .unwrap_or_default();
    let presentation = presentation_from_listing(&listing, &empty_label, &assets);
    populate_load_save_slots(&mut commands, root_entity, &tree, mode, &presentation);
    if mode == LoadSaveMode::Load {
        apply_load_okay_pictures(&mut commands, &mut assets, root_entity, &tree);
        commands
            .entity(tree.find(root_entity, fourcc!("otto")))
            .remove::<InteractionDisabled>();
    }
    commands
        .entity(tree.find(root_entity, fourcc!("info")))
        .insert(Text::new(String::new()));
    commands
        .entity(tree.find(root_entity, fourcc!("map ")))
        .insert(LoadSaveMapPreview::default());
    commands.entity(root_entity).insert(presentation);
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
        commands
            .entity(entity)
            .insert((Button, LoadSaveAction::SelectSlot(slot)))
            .observe(on_load_save_activate);
    }
    commands
        .entity(tree.find(root, fourcc!("info")))
        .insert(LoadSaveInfo);
    commands
        .entity(tree.find(root, fourcc!("okay")))
        .insert(LoadSaveAction::Okay)
        .remove::<InteractionDisabled>()
        .observe(on_load_save_activate);
    commands
        .entity(tree.find(root, fourcc!("cncl")))
        .insert(LoadSaveAction::Cancel)
        .remove::<InteractionDisabled>()
        .observe(on_load_save_activate);
    let otto = tree.find(root, fourcc!("otto"));
    let mut otto_commands = commands.entity(otto);
    otto_commands.insert(LoadSaveAction::SelectSlot(SaveSlot::Autosave));
    otto_commands.observe(on_load_save_activate);
    if mode == LoadSaveMode::Save {
        otto_commands.insert(InteractionDisabled);
    }
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
    let difficulty = assets
        .string(
            DIFFICULTY_STRING_GROUP,
            DIFFICULTY_STRING_BASE + i16::from(header.difficulty),
        )
        .unwrap_or_default();
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
    let idle = match assets.picture(PictureId::new(LOAD_OKAY_IDLE_PICTURE)) {
        Ok(handle) => handle,
        Err(error) => {
            warn!("could not load Load Game okay picture: {error}");
            return;
        }
    };
    let active = match assets.picture(PictureId::new(LOAD_OKAY_ACTIVE_PICTURE)) {
        Ok(handle) => handle,
        Err(error) => {
            warn!("could not load Load Game okay pressed picture: {error}");
            idle.clone()
        }
    };
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
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    entity: Entity,
    image_node: Option<&ImageNode>,
    preview: &SatellitePreview,
) {
    let image = preview.to_image(assets.default_dib_palette());
    if let Some(image_node) = image_node {
        assets.replace_image(&image_node.image, image);
    } else {
        let handle = assets.add_image(image);
        commands.entity(entity).insert(ImageNode::new(handle));
    }
}

fn sync_load_save_preview(
    mut commands: Commands,
    mut assets: RetailUiAssets,
    roots: Query<&LoadSaveRoot>,
    mut maps: Query<(Entity, Option<&ImageNode>, &mut LoadSaveMapPreview)>,
    save_dir: Res<SaveDirectory>,
    session: Option<Res<GameSession>>,
) {
    let Ok(root) = roots.single() else {
        return;
    };
    let Ok((entity, image_node, mut preview)) = maps.single_mut() else {
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
            apply_satellite_preview(&mut commands, &mut assets, entity, image_node, &preview);
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
            apply_satellite_preview(&mut commands, &mut assets, entity, image_node, &preview);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn on_load_save_activate(
    activate: On<Activate>,
    actions: Query<&LoadSaveAction>,
    notices: Query<(), With<LoadSaveNotice>>,
    mut roots: Query<(&mut LoadSaveRoot, Option<&LoadSavePresentation>)>,
    names: Query<&EditableText, With<SaveNameField>>,
    mut texts: Query<&mut Text>,
    info: Query<Entity, With<LoadSaveInfo>>,
    save_dir: Option<Res<SaveDirectory>>,
    returning: Res<ReturnTo>,
    session: Option<Res<GameSession>>,
    mut next_state: ResMut<NextState<AppState>>,
    mut commands: Commands,
) {
    if !notices.is_empty() {
        return;
    }
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let Ok((mut root, presentation)) = roots.single_mut() else {
        return;
    };
    match *action {
        LoadSaveAction::Cancel => {
            next_state.set(returning.0);
        }
        LoadSaveAction::SelectSlot(slot) => select_slot(
            &mut commands,
            &mut root,
            activate.entity,
            slot,
            presentation,
            &mut texts,
            info.single().ok(),
        ),
        LoadSaveAction::Okay => {
            let Some(save_dir) = save_dir else {
                return;
            };
            confirm_or_apply(
                &mut commands,
                &root,
                &names,
                presentation,
                &save_dir.0,
                session.as_deref(),
                returning.0,
                &mut next_state,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn select_slot(
    commands: &mut Commands,
    root: &mut LoadSaveRoot,
    entity: Entity,
    slot: SaveSlot,
    presentation: Option<&LoadSavePresentation>,
    texts: &mut Query<&mut Text>,
    info: Option<Entity>,
) {
    if root.selected == Some(slot) {
        return;
    }
    if root.mode == LoadSaveMode::Save && root.renaming {
        return;
    }
    root.selected = Some(slot);
    if root.mode == LoadSaveMode::Load {
        if let Some(caption) = presentation.and_then(|listing| slot_info(listing, slot))
            && let Some(info) = info
            && let Ok(mut text) = texts.get_mut(info)
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
        SaveNameField,
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
    names: &Query<&EditableText, With<SaveNameField>>,
    presentation: Option<&LoadSavePresentation>,
    save_dir: &Path,
    session: Option<&GameSession>,
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
            let typed = names
                .single()
                .map(|editable| editable.value().to_string())
                .unwrap_or_default();
            let empty_label = presentation
                .map(|listing| listing.empty_label.as_str())
                .unwrap_or_default();
            let label = if typed.is_empty() {
                empty_label.to_owned()
            } else {
                typed
            };
            apply_save(
                commands, save_dir, slot, session, &label, returning, next_state,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
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
        Ok(loaded) => {
            let destination = loaded_game_destination(&loaded.game);
            commands.insert_resource(GameSession::from_loaded(loaded));
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
    label: &str,
    returning: AppState,
    next_state: &mut NextState<AppState>,
) {
    match save_current_game(save_dir, slot, session, label) {
        Ok(()) => next_state.set(returning),
        Err(error) => spawn_notice(commands, LoadSaveNotice::Error(error.to_string())),
    }
}

fn load_error_text(assets: &RetailAssetsResource, error: &LoadGameError) -> String {
    let retail = match error {
        LoadGameError::InvalidMagic | LoadGameError::Truncated => assets.string(0x2737, 7).ok(),
        LoadGameError::UnsupportedVersion(_) => assets.string(0x2737, 8).ok(),
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
        LoadSaveNotice::PickSlot => assets
            .string(PICK_SLOT_STRING_GROUP, PICK_SLOT_STRING_INDEX)
            .unwrap_or_default(),
        LoadSaveNotice::ConfirmLoad => assets
            .string(CONFIRM_LOAD_STRING_GROUP, CONFIRM_LOAD_STRING_INDEX)
            .unwrap_or_default(),
        LoadSaveNotice::Error(body) => body.clone(),
    };
    linger.set_body(&mut commands, &mut assets, &body);
    commands.entity(linger.okay).remove::<InteractionDisabled>();
    match notice {
        LoadSaveNotice::ConfirmLoad => {
            commands
                .entity(linger.okay)
                .insert(ConfirmLoadNotice)
                .observe(on_confirm_load_notice);
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
        .observe(on_open_flag_menu.run_if(not(any_with_component::<ModalWindow>)));
}

fn on_open_flag_menu(
    activate: On<Activate>,
    openers: Query<&OpenFlagMenu>,
    existing: Query<(), With<FlagMenuRoot>>,
    mut commands: Commands,
) {
    if openers.get(activate.entity).is_err() || !existing.is_empty() {
        return;
    }
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
    mut assets: RetailUiAssets,
) {
    let root = *root;
    for (index, tag) in FLAG_LABEL_TAGS.iter().copied().enumerate() {
        let entity = tree.find(root, tag);
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
        (fourcc!("newg"), FlagMenuAction::NewGame),
        (fourcc!("pref"), FlagMenuAction::Preferences),
        (fourcc!("cred"), FlagMenuAction::Credits),
        (fourcc!("quit"), FlagMenuAction::Quit),
    ] {
        let control = tree.find(root, tag);
        commands
            .entity(control)
            .insert(action)
            .remove::<InteractionDisabled>()
            .observe(on_flag_menu_activate);
    }
    commands
        .entity(tree.find(root, fourcc!("cncl")))
        .insert((ModalCancel, DismissWindow))
        .remove::<InteractionDisabled>();
}

fn on_flag_menu_activate(
    activate: On<Activate>,
    actions: Query<&FlagMenuAction>,
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
    match *action {
        FlagMenuAction::Save => {
            open_load_save(
                &mut commands,
                &mut next_state,
                LoadSaveMode::Save,
                AppState::StrategicMap,
            );
        }
        FlagMenuAction::Load => {
            open_load_save(
                &mut commands,
                &mut next_state,
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
            open_flag_menu_prompt(&mut commands, FlagMenuPending::NewGame);
        }
        FlagMenuAction::Quit => {
            open_flag_menu_prompt(&mut commands, FlagMenuPending::Quit);
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
    let body = assets
        .string(0x2737, index)
        .expect("retail flag-menu confirm string");
    let linger = bind_linger_dialog(&mut commands, root, &tree);
    linger.set_body(&mut commands, &mut assets, body);
    commands
        .entity(linger.okay)
        .insert(AcceptFlagMenuPrompt)
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
            commands.remove_resource::<GameSession>();
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
    use crate::ui::retail::RetailTag;
    use crate::ui::test_support::beginning_of_game;
    use imperialism_formats::{DibPalette, load_game_from_path};

    fn fixture_state() -> GameState {
        beginning_of_game()
    }

    fn test_app(initial: AppState) -> App {
        let mut app = App::new();
        app.add_plugins(MinimalPlugins)
            .add_plugins(bevy::state::app::StatesPlugin)
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
        tree: RetailTree,
    ) {
        let (entity, screen) = root.into_inner();
        bind_load_save_actions(&mut commands, entity, &tree, screen.mode);
    }

    fn spawn_test_flag_menu(mut commands: Commands) {
        commands.spawn((FlagMenuRoot, ModalWindow, Node::default()));
    }

    fn spawn_test_flag_prompt(mut commands: Commands, kind: FlagMenuPending) {
        let root = commands
            .spawn((FlagMenuPrompt { kind }, ModalWindow, Node::default()))
            .id();
        commands
            .spawn((AcceptFlagMenuPrompt, DismissWindow, ChildOf(root)))
            .observe(on_flag_menu_prompt_activate);
        commands.spawn((ModalCancel, DismissWindow, ChildOf(root)));
    }

    #[test]
    fn cancel_restores_the_previous_application_state() {
        let mut app = test_app(AppState::MainMenu);
        app.insert_resource(ReturnTo(AppState::MainMenu));
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
            .find(|entity| {
                app.world().get::<LoadSaveAction>(*entity) == Some(&LoadSaveAction::Cancel)
            })
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
    fn accepting_new_game_drops_the_session_and_returns_to_the_main_menu() {
        let mut app = test_app(AppState::StrategicMap);
        app.insert_resource(GameSession::new(fixture_state()));
        app.add_systems(Startup, spawn_test_flag_menu);
        app.add_systems(Startup, |commands: Commands| {
            spawn_test_flag_prompt(commands, FlagMenuPending::NewGame)
        });
        app.update();

        let accept = app
            .world_mut()
            .query_filtered::<Entity, With<AcceptFlagMenuPrompt>>()
            .iter(app.world())
            .next()
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
        let mut app = test_app(AppState::StrategicMap);
        app.add_systems(Startup, |commands: Commands| {
            spawn_test_flag_prompt(commands, FlagMenuPending::Quit)
        });
        app.update();

        let accept = app
            .world_mut()
            .query_filtered::<Entity, With<AcceptFlagMenuPrompt>>()
            .iter(app.world())
            .next()
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
        let mut app = test_app(AppState::StrategicMap);
        app.add_systems(Startup, spawn_test_flag_menu);
        app.add_systems(Startup, |commands: Commands| {
            spawn_test_flag_prompt(commands, FlagMenuPending::NewGame)
        });
        app.update();

        let dismiss = app
            .world_mut()
            .query_filtered::<Entity, With<ModalCancel>>()
            .iter(app.world())
            .next()
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

    #[test]
    fn successful_load_replaces_the_session_and_enters_the_saved_phase() {
        let original = fixture_state();
        let session = GameSession::new(original.clone());
        let dir = tempfile::tempdir().unwrap();
        save_current_game(dir.path(), SaveSlot::Numbered(1), &session, "England").unwrap();
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
        save_current_game(dir.path(), SaveSlot::Numbered(0), &session, "First").unwrap();
        save_current_game(dir.path(), SaveSlot::Numbered(0), &session, "Second").unwrap();
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
    fn save_header_owners_compose_the_retail_satellite_preview() {
        let original = fixture_state();
        let session = GameSession::new(original.clone());
        let dir = tempfile::tempdir().unwrap();
        save_current_game(dir.path(), SaveSlot::Numbered(0), &session, "Preview").unwrap();
        let bytes = std::fs::read(retail_save_path(dir.path(), SaveSlot::Numbered(0))).unwrap();
        let owners = peek_save_preview_owners(&bytes).expect("written save has preview tiles");
        for (index, owner) in owners.iter().enumerate() {
            assert_eq!(
                *owner,
                original.map()[TileId::new(index as u16)].owner_nation
            );
        }
        let preview = satellite_preview(
            |tile| owners.get(usize::from(tile.get())).copied().flatten(),
            original.turn().active_nation,
        );
        let image = preview.to_image(&DibPalette::default());
        assert_eq!(image.texture_descriptor.size.width, 324);
        assert_eq!(image.texture_descriptor.size.height, 180);
        assert!(
            image
                .data
                .as_ref()
                .unwrap()
                .chunks_exact(4)
                .any(|pixel| pixel[3] != 0),
            "satellite preview should paint claimed land, not only the off-map key"
        );
    }

    #[test]
    fn in_game_load_inherits_the_live_session_rng() {
        let original = fixture_state();
        let session = GameSession::new(original.clone());
        let dir = tempfile::tempdir().unwrap();
        save_current_game(dir.path(), SaveSlot::Numbered(0), &session, "England").unwrap();
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
        save_current_game(dir.path(), SaveSlot::Numbered(0), &session, "England").unwrap();
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
