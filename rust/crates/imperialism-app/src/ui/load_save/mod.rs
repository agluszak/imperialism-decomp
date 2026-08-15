use crate::AppState;
use crate::RetailAssetsResource;
use crate::ui::GameSession;
use crate::ui::generated;
use crate::ui::map_preview::{compose_owner_preview_indices, preview_image_from_indices};
use crate::ui::retail::{
    ModalDialog, RetailPictureSwap, RetailTag, RetailUiAssets, find_descendant,
};
use bevy::input_focus::AutoFocus;
use bevy::input_focus::tab_navigation::TabGroup;
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

/// Directory that holds retail `slotN.imp` / `slotA.imp` files.
#[derive(Resource, Clone, Debug, Eq, PartialEq)]
pub(crate) struct SaveDirectory(pub(crate) PathBuf);

/// Screen to restore when Load/Save is cancelled.
#[derive(Resource, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct LoadSaveReturn(pub(crate) AppState);

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
    commands.insert_resource(LoadSaveReturn(return_to));
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
    Autosave,
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
    pick_slot_prompt: String,
    confirm_load_prompt: String,
}

#[derive(Component)]
struct LoadSaveNotice {
    kind: LoadSaveNoticeKind,
    body: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum LoadSaveNoticeKind {
    PickSlot,
    ConfirmLoad,
    Error,
}

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum LoadSaveNoticeAction {
    Accept,
    Dismiss,
}

pub(crate) struct LoadSavePlugin;

impl Plugin for LoadSavePlugin {
    fn build(&self, app: &mut App) {
        register_load_save_logic(app);
        app.init_resource::<LoadSaveReturn>()
            .add_observer(on_load_save_notice_activate.run_if(in_state(AppState::LoadSave)))
            .add_systems(
                OnEnter(AppState::LoadSave),
                (enter_load_save, bind_load_save).chain(),
            )
            .add_systems(
                Update,
                (bind_load_save_notice, sync_load_save_preview)
                    .run_if(in_state(AppState::LoadSave)),
            );
    }
}

pub(crate) fn register_load_save_logic(app: &mut App) {
    app.add_observer(on_load_save_activate.run_if(in_state(AppState::LoadSave)));
}

/// Retail `DoRead` never stores or reseeds these streams. CRT `rand()` is a process
/// global seeded by `TSimMgr::ISimMgr` via `srand(time(0))`; the map LCG is BSS-zero
/// until map generation; the zone LCG starts as `GetTickCountDiv16()`. A later load
/// leaves whatever the process currently has.
fn runtime_context_for_load(
    existing: Option<&GameState>,
    selected_nation: NationId,
) -> LegacyGameStateContext {
    if let Some(state) = existing {
        let rng = state.rng();
        return LegacyGameStateContext {
            crt_rand_state: rng.crt_rand.state(),
            map_generation_lcg: rng.map_generation.state(),
            zone_status_lcg: rng.zone_status.state(),
            selected_nation,
        };
    }
    LegacyGameStateContext {
        crt_rand_state: clock_derived_crt_seed(),
        map_generation_lcg: 0,
        zone_status_lcg: tick_derived_zone_seed(),
        selected_nation,
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
    state: &GameState,
    label: &str,
) -> Result<(), SaveFileError> {
    let label = normalize_save_label(label);
    let session_slot = match slot {
        SaveSlot::Numbered(index) => i32::from(index),
        SaveSlot::Autosave => AUTOSAVE_SESSION_SLOT,
    };
    let bytes = write_game_state(state, &label, session_slot);
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
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
    save_dir: Res<SaveDirectory>,
) {
    let (root_entity, screen) = root.into_inner();
    let mode = screen.mode;
    bind_load_save_actions(&mut commands, root_entity, &children, &tags, mode);
    let listing = list_save_slots(&save_dir.0);
    let empty_label = assets
        .string(EMPTY_SLOT_STRING_GROUP, EMPTY_SLOT_STRING_INDEX)
        .unwrap_or_default();
    let presentation = presentation_from_listing(&listing, &empty_label, &assets);
    populate_load_save_slots(
        &mut commands,
        root_entity,
        &children,
        &tags,
        mode,
        &presentation,
    );
    if mode == LoadSaveMode::Load {
        apply_load_okay_pictures(&mut commands, &mut assets, root_entity, &children, &tags);
        commands
            .entity(find_descendant(
                root_entity,
                fourcc!("otto"),
                &children,
                &tags,
            ))
            .remove::<InteractionDisabled>();
    }
    commands
        .entity(find_descendant(
            root_entity,
            fourcc!("info"),
            &children,
            &tags,
        ))
        .insert(Text::new(String::new()));
    commands
        .entity(find_descendant(
            root_entity,
            fourcc!("map "),
            &children,
            &tags,
        ))
        .insert(LoadSaveMapPreview::default());
    commands.entity(root_entity).insert(presentation);
}

fn bind_load_save_actions(
    commands: &mut Commands,
    root: Entity,
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    mode: LoadSaveMode,
) {
    for (index, tag) in SLOT_TAGS.iter().copied().enumerate() {
        let entity = find_descendant(root, tag, children, tags);
        let slot = SaveSlot::numbered(index as u8).expect("slot tags are numbered 0..=7");
        commands
            .entity(entity)
            .insert((Button, LoadSaveAction::SelectSlot(slot)));
    }
    commands
        .entity(find_descendant(root, fourcc!("info"), children, tags))
        .insert(LoadSaveInfo);
    commands
        .entity(find_descendant(root, fourcc!("okay"), children, tags))
        .insert(LoadSaveAction::Okay)
        .remove::<InteractionDisabled>();
    commands
        .entity(find_descendant(root, fourcc!("cncl"), children, tags))
        .insert(LoadSaveAction::Cancel)
        .remove::<InteractionDisabled>();
    let otto = find_descendant(root, fourcc!("otto"), children, tags);
    let mut otto_commands = commands.entity(otto);
    otto_commands.insert(LoadSaveAction::Autosave);
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
        pick_slot_prompt: assets
            .string(PICK_SLOT_STRING_GROUP, PICK_SLOT_STRING_INDEX)
            .unwrap_or_default(),
        confirm_load_prompt: assets
            .string(CONFIRM_LOAD_STRING_GROUP, CONFIRM_LOAD_STRING_INDEX)
            .unwrap_or_default(),
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
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
    mode: LoadSaveMode,
    presentation: &LoadSavePresentation,
) {
    for (index, tag) in SLOT_TAGS.iter().copied().enumerate() {
        let entity = find_descendant(root, tag, children, tags);
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
    children: &Query<&Children>,
    tags: &Query<&RetailTag>,
) {
    let okay = find_descendant(root, fourcc!("okay"), children, tags);
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

fn satellite_preview_indices(
    owners: impl Fn(TileId) -> Option<TileOwnerTag>,
    selected_nation: NationId,
) -> Vec<u8> {
    compose_owner_preview_indices(owners, selected_nation)
}

fn apply_satellite_preview(
    commands: &mut Commands,
    assets: &mut RetailUiAssets,
    entity: Entity,
    image_node: Option<&ImageNode>,
    pixels: &[u8],
) {
    let image = preview_image_from_indices(pixels, assets.default_dib_palette());
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
            let pixels =
                satellite_preview_indices(|tile| session.game.map()[tile].owner_nation, selected);
            apply_satellite_preview(&mut commands, &mut assets, entity, image_node, &pixels);
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
            let pixels = satellite_preview_indices(
                |tile| owners.get(usize::from(tile.get())).copied().flatten(),
                selected,
            );
            apply_satellite_preview(&mut commands, &mut assets, entity, image_node, &pixels);
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
    returning: Res<LoadSaveReturn>,
    session: Option<Res<GameSession>>,
    state: Res<State<AppState>>,
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
        LoadSaveAction::Autosave => select_slot(
            &mut commands,
            &mut root,
            activate.entity,
            SaveSlot::Autosave,
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
                *state.get(),
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
    screen_state: AppState,
    next_state: &mut NextState<AppState>,
) {
    let Some(slot) = root.selected else {
        if root.mode == LoadSaveMode::Save {
            spawn_notice(
                commands,
                LoadSaveNoticeKind::PickSlot,
                presentation
                    .map(|listing| listing.pick_slot_prompt.clone())
                    .unwrap_or_default(),
                screen_state,
            );
        }
        return;
    };
    match root.mode {
        LoadSaveMode::Load => {
            if returning != AppState::MainMenu {
                spawn_notice(
                    commands,
                    LoadSaveNoticeKind::ConfirmLoad,
                    presentation
                        .map(|listing| listing.confirm_load_prompt.clone())
                        .unwrap_or_default(),
                    screen_state,
                );
                return;
            }
            apply_load(
                commands,
                save_dir,
                slot,
                session.map(|session| &session.game),
                next_state,
                screen_state,
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
                commands,
                save_dir,
                slot,
                &session.game,
                &label,
                returning,
                next_state,
                screen_state,
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
    screen_state: AppState,
    assets: Option<&RetailAssetsResource>,
) {
    let path = retail_save_path(save_dir, slot);
    if !path.is_file() {
        return;
    }
    let load = (|| {
        let bytes = std::fs::read(&path)?;
        let selected = peek_save_header(&bytes)
            .and_then(|header| NationId::try_new(header.active_nation))
            .ok_or(LoadGameError::Truncated)?;
        let context = runtime_context_for_load(existing, selected);
        load_game_from_bytes(&bytes, context)
    })();
    match load {
        Ok(game) => {
            let destination = loaded_game_destination(&game);
            commands.insert_resource(GameSession { game });
            next_state.set(destination);
        }
        Err(error) => spawn_notice(
            commands,
            LoadSaveNoticeKind::Error,
            assets
                .map(|assets| load_error_text(assets, &error))
                .unwrap_or_else(|| error.to_string()),
            screen_state,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_save(
    commands: &mut Commands,
    save_dir: &Path,
    slot: SaveSlot,
    state: &GameState,
    label: &str,
    returning: AppState,
    next_state: &mut NextState<AppState>,
    screen_state: AppState,
) {
    match save_current_game(save_dir, slot, state, label) {
        Ok(()) => next_state.set(returning),
        Err(error) => spawn_notice(
            commands,
            LoadSaveNoticeKind::Error,
            error.to_string(),
            screen_state,
        ),
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

fn spawn_notice(
    commands: &mut Commands,
    kind: LoadSaveNoticeKind,
    body: String,
    screen_state: AppState,
) {
    let root = commands.spawn_scene(generated::linger_2020()).id();
    commands.entity(root).insert((
        LoadSaveNotice { kind, body },
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(20),
        Pickable::default(),
        DespawnOnExit(screen_state),
    ));
}

fn bind_load_save_notice(
    mut commands: Commands,
    notice: Single<(Entity, &LoadSaveNotice), Added<LoadSaveNotice>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    mut assets: RetailUiAssets,
) {
    let (root, notice) = notice.into_inner();
    let body = find_descendant(root, fourcc!("info"), &children, &tags);
    let (body_font, body_layout, body_line_height, _) = assets
        .text_style(imperialism_formats::RetailTextStylePreset {
            font_family: 1,
            face_flags: 0,
            point_size: 12,
            alignment: 0,
        })
        .expect("retail load/save notice body style");
    commands.entity(body).insert((
        Text::new(notice.body.clone()),
        body_font,
        body_layout,
        body_line_height,
        TextColor(assets.palette_color(0)),
    ));
    let okay = find_descendant(root, fourcc!("okay"), &children, &tags);
    commands
        .entity(okay)
        .insert(LoadSaveNoticeAction::Accept)
        .remove::<InteractionDisabled>();
    let cancel = find_descendant(root, fourcc!("cncl"), &children, &tags);
    match notice.kind {
        LoadSaveNoticeKind::ConfirmLoad => {
            commands
                .entity(cancel)
                .insert(LoadSaveNoticeAction::Dismiss)
                .remove::<InteractionDisabled>();
        }
        LoadSaveNoticeKind::PickSlot | LoadSaveNoticeKind::Error => {
            commands.entity(cancel).insert(Visibility::Hidden);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn on_load_save_notice_activate(
    activate: On<Activate>,
    actions: Query<&LoadSaveNoticeAction>,
    notices: Query<(Entity, &LoadSaveNotice)>,
    roots: Query<&LoadSaveRoot>,
    save_dir: Res<SaveDirectory>,
    session: Option<Res<GameSession>>,
    mut next_state: ResMut<NextState<AppState>>,
    state: Res<State<AppState>>,
    mut commands: Commands,
    assets: Res<RetailAssetsResource>,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    let Ok((notice_entity, notice)) = notices.single() else {
        return;
    };
    match (*action, &notice.kind) {
        (LoadSaveNoticeAction::Accept, LoadSaveNoticeKind::ConfirmLoad) => {
            commands.entity(notice_entity).despawn();
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
                *state.get(),
                Some(&*assets),
            );
        }
        (LoadSaveNoticeAction::Accept, _) | (LoadSaveNoticeAction::Dismiss, _) => {
            commands.entity(notice_entity).despawn();
        }
    }
}

#[cfg(test)]
mod tests;
