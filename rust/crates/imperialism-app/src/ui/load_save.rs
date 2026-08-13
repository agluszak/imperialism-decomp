use crate::AppState;
use crate::ui::generated;
use crate::ui::random_setup::GameSession;
use crate::ui::retail::{
    ModalDialog, RetailPictureSwap, RetailTag, RetailUiAssets, find_descendant,
};
use bevy::input_focus::AutoFocus;
use bevy::input_focus::tab_navigation::TabGroup;
use bevy::prelude::*;
use bevy::text::{EditableText, EditableTextFilter, TextCursorStyle};
use bevy::ui::InteractionDisabled;
use bevy::ui_widgets::{Activate, SelectAllOnFocus};
use imperialism_core::{GameState, NationId, PhaseCode};
use imperialism_formats::{
    FourCc, LegacyGameStateContext, LoadGameError, NUMBERED_SAVE_SLOT_COUNT, OverwritePolicy,
    PictureId, SAVE_LABEL_MAX_CHARS, SaveDirectoryListing, SaveFileError, SaveHeaderInfo, SaveSlot,
    fourcc, list_save_slots, load_game_from_bytes, normalize_save_label, peek_save_header,
    retail_save_path, write_game_state, write_save_file,
};
use std::path::{Path, PathBuf};

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

/// Screen to restore when Load/Save is cancelled.
#[derive(Resource, Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct LoadSaveReturn(pub(crate) AppState);

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OpenFlagMenu;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoadSaveMode {
    Load,
    Save,
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

#[derive(Clone, Debug, Eq, PartialEq)]
struct SlotPresentation {
    label: String,
    info: String,
}

#[derive(Resource, Clone, Debug, Eq, PartialEq)]
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

#[derive(Component)]
struct FlagMenuRoot;

#[derive(Component, Clone, Copy, Debug, Eq, PartialEq)]
enum FlagMenuAction {
    Save,
    Load,
    Cancel,
}

pub(crate) struct LoadSavePlugin;

impl Plugin for LoadSavePlugin {
    fn build(&self, app: &mut App) {
        register_load_save_logic(app);
        app.init_resource::<LoadSaveReturn>()
            .add_observer(
                on_load_save_notice_activate
                    .run_if(in_state(AppState::LoadGame).or_else(in_state(AppState::SaveGame))),
            )
            .add_systems(
                OnEnter(AppState::LoadGame),
                (enter_load_save, bind_load_save).chain(),
            )
            .add_systems(
                OnEnter(AppState::SaveGame),
                (enter_load_save, bind_load_save).chain(),
            )
            .add_systems(
                Update,
                bind_load_save_notice
                    .run_if(in_state(AppState::LoadGame).or_else(in_state(AppState::SaveGame))),
            )
            .add_systems(
                Update,
                bind_flag_menu.run_if(in_state(AppState::StrategicMap)),
            );
    }
}

pub(crate) fn register_load_save_logic(app: &mut App) {
    app.add_observer(
        on_load_save_activate
            .run_if(in_state(AppState::LoadGame).or_else(in_state(AppState::SaveGame))),
    )
    .add_observer(on_open_flag_menu.run_if(in_state(AppState::StrategicMap)))
    .add_observer(on_flag_menu_activate.run_if(in_state(AppState::StrategicMap)));
}

pub(crate) fn load_slot(directory: &Path, slot: SaveSlot) -> Result<GameState, LoadGameError> {
    let path = retail_save_path(directory, slot);
    let bytes = std::fs::read(&path)?;
    let selected_nation = peek_save_header(&bytes)
        .and_then(|header| NationId::try_new(header.active_nation))
        .unwrap_or(NationId::new(0));
    load_game_from_bytes(
        &bytes,
        LegacyGameStateContext {
            crt_rand_state: 1,
            map_generation_lcg: 0,
            zone_status_lcg: 0,
            selected_nation,
        },
    )
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

pub(crate) fn commit_loaded_game(
    loaded: Result<GameState, LoadGameError>,
) -> Result<(GameSession, AppState), LoadGameError> {
    let game = loaded?;
    let destination = loaded_game_destination(&game);
    Ok((GameSession(game), destination))
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

fn enter_load_save(mut commands: Commands, state: Res<State<AppState>>) {
    let mode = match *state.get() {
        AppState::LoadGame => LoadSaveMode::Load,
        AppState::SaveGame => LoadSaveMode::Save,
        other => panic!("Load/Save screen entered from {other:?}"),
    };
    let root = commands.spawn_scene(generated::linger_1502()).id();
    commands.entity(root).insert((
        LoadSaveRoot {
            mode,
            selected: None,
            renaming: false,
        },
        DespawnOnExit(*state.get()),
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
    commands.insert_resource(presentation);
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

#[allow(clippy::too_many_arguments)]
fn on_load_save_activate(
    activate: On<Activate>,
    actions: Query<&LoadSaveAction>,
    notices: Query<(), With<LoadSaveNotice>>,
    mut roots: Query<&mut LoadSaveRoot>,
    names: Query<&EditableText, With<SaveNameField>>,
    mut texts: Query<&mut Text>,
    info: Query<Entity, With<LoadSaveInfo>>,
    presentation: Option<Res<LoadSavePresentation>>,
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
    let Ok(mut root) = roots.single_mut() else {
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
            presentation.as_deref(),
            &mut texts,
            info.single().ok(),
        ),
        LoadSaveAction::Autosave => select_slot(
            &mut commands,
            &mut root,
            activate.entity,
            SaveSlot::Autosave,
            presentation.as_deref(),
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
                presentation.as_deref(),
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
            apply_load(commands, save_dir, slot, next_state, screen_state, None);
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
                &session.0,
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
    next_state: &mut NextState<AppState>,
    screen_state: AppState,
    assets: Option<&RetailUiAssets>,
) {
    if !retail_save_path(save_dir, slot).is_file() {
        return;
    }
    match commit_loaded_game(load_slot(save_dir, slot)) {
        Ok((session, destination)) => {
            commands.insert_resource(session);
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

fn load_error_text(assets: &RetailUiAssets, error: &LoadGameError) -> String {
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
    let (body_font, body_layout, _) = assets
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
    mut next_state: ResMut<NextState<AppState>>,
    state: Res<State<AppState>>,
    mut commands: Commands,
    assets: RetailUiAssets,
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
                &mut next_state,
                *state.get(),
                Some(&assets),
            );
        }
        (LoadSaveNoticeAction::Accept, _) | (LoadSaveNoticeAction::Dismiss, _) => {
            commands.entity(notice_entity).despawn();
        }
    }
}

fn on_open_flag_menu(
    activate: On<Activate>,
    openers: Query<&OpenFlagMenu>,
    existing: Query<(), With<FlagMenuRoot>>,
    dialogs: Query<(), With<ModalDialog>>,
    mut commands: Commands,
) {
    if openers.get(activate.entity).is_err() || !existing.is_empty() || !dialogs.is_empty() {
        return;
    }
    let root = commands.spawn_scene(generated::linger_4140()).id();
    commands.entity(root).insert((
        FlagMenuRoot,
        ModalDialog,
        TabGroup::modal(),
        GlobalZIndex(20),
        Pickable::default(),
        DespawnOnExit(AppState::StrategicMap),
    ));
}

fn bind_flag_menu(
    mut commands: Commands,
    root: Single<Entity, Added<FlagMenuRoot>>,
    children: Query<&Children>,
    tags: Query<&RetailTag>,
    assets: RetailUiAssets,
) {
    let root = *root;
    for (index, tag) in FLAG_LABEL_TAGS.iter().copied().enumerate() {
        let entity = find_descendant(root, tag, &children, &tags);
        if let Ok(label) = assets.string(FLAG_MENU_STRING_GROUP, index as i16) {
            commands.entity(entity).insert(Text::new(label));
        }
    }
    for (tag, action) in [
        (fourcc!("save"), FlagMenuAction::Save),
        (fourcc!("load"), FlagMenuAction::Load),
        (fourcc!("cncl"), FlagMenuAction::Cancel),
    ] {
        commands
            .entity(find_descendant(root, tag, &children, &tags))
            .insert(action)
            .remove::<InteractionDisabled>();
    }
    for tag in [
        fourcc!("newg"),
        fourcc!("pref"),
        fourcc!("cred"),
        fourcc!("quit"),
    ] {
        commands
            .entity(find_descendant(root, tag, &children, &tags))
            .insert(InteractionDisabled);
    }
}

fn on_flag_menu_activate(
    activate: On<Activate>,
    actions: Query<&FlagMenuAction>,
    menus: Query<Entity, With<FlagMenuRoot>>,
    mut next_state: ResMut<NextState<AppState>>,
    mut commands: Commands,
) {
    let Ok(action) = actions.get(activate.entity) else {
        return;
    };
    match *action {
        FlagMenuAction::Cancel => {
            for entity in &menus {
                commands.entity(entity).despawn();
            }
        }
        FlagMenuAction::Save => {
            commands.insert_resource(LoadSaveReturn(AppState::StrategicMap));
            next_state.set(AppState::SaveGame);
        }
        FlagMenuAction::Load => {
            commands.insert_resource(LoadSaveReturn(AppState::StrategicMap));
            next_state.set(AppState::LoadGame);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use imperialism_formats::{LegacySaveV62, write_save_file};

    const BEGINNING_OF_GAME: &[u8] =
        include_bytes!("../../../../../fixtures/retail/beginning_of_game.imp");

    fn fixture_state() -> GameState {
        let selected_nation = peek_save_header(BEGINNING_OF_GAME)
            .and_then(|header| NationId::try_new(header.active_nation))
            .unwrap_or(NationId::new(0));
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
            .insert_state(initial)
            .init_resource::<LoadSaveReturn>();
        register_load_save_logic(&mut app);
        app.add_systems(
            OnEnter(AppState::LoadGame),
            (spawn_test_load_save, bind_test_load_save).chain(),
        );
        app.add_systems(
            OnEnter(AppState::SaveGame),
            (spawn_test_load_save, bind_test_load_save).chain(),
        );
        app
    }

    fn spawn_test_load_save(mut commands: Commands, state: Res<State<AppState>>) {
        let mode = match *state.get() {
            AppState::LoadGame => LoadSaveMode::Load,
            AppState::SaveGame => LoadSaveMode::Save,
            other => panic!("unexpected test state {other:?}"),
        };
        let root = commands
            .spawn((
                LoadSaveRoot {
                    mode,
                    selected: None,
                    renaming: false,
                },
                Node::default(),
                DespawnOnExit(*state.get()),
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

    fn spawn_test_flag_menu(mut commands: Commands) {
        let root = commands.spawn((FlagMenuRoot, Node::default())).id();
        commands.spawn((
            RetailTag(fourcc!("save")),
            FlagMenuAction::Save,
            ChildOf(root),
        ));
        commands.spawn((
            RetailTag(fourcc!("load")),
            FlagMenuAction::Load,
            ChildOf(root),
        ));
        commands.spawn((
            RetailTag(fourcc!("cncl")),
            FlagMenuAction::Cancel,
            ChildOf(root),
        ));
    }

    #[test]
    fn cancel_restores_the_previous_application_state() {
        let mut app = test_app(AppState::MainMenu);
        app.insert_resource(LoadSaveReturn(AppState::MainMenu));
        app.world_mut()
            .resource_mut::<NextState<AppState>>()
            .set(AppState::LoadGame);
        app.update();
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::LoadGame
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
    fn flag_save_and_load_enter_the_matching_load_save_mode() {
        let mut app = test_app(AppState::StrategicMap);
        app.add_systems(Startup, spawn_test_flag_menu);
        app.update();

        let save = app
            .world_mut()
            .query_filtered::<Entity, With<FlagMenuAction>>()
            .iter(app.world())
            .find(|entity| {
                app.world().get::<FlagMenuAction>(*entity) == Some(&FlagMenuAction::Save)
            })
            .unwrap();
        app.world_mut()
            .commands()
            .trigger(Activate { entity: save });
        app.world_mut().flush();
        app.update();
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::SaveGame
        );
        assert_eq!(
            app.world().resource::<LoadSaveReturn>().0,
            AppState::StrategicMap
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
            &AppState::StrategicMap
        );
    }

    #[test]
    fn flag_load_enters_load_game() {
        let mut app = test_app(AppState::StrategicMap);
        app.add_systems(Startup, spawn_test_flag_menu);
        app.update();

        let load = app
            .world_mut()
            .query_filtered::<Entity, With<FlagMenuAction>>()
            .iter(app.world())
            .find(|entity| {
                app.world().get::<FlagMenuAction>(*entity) == Some(&FlagMenuAction::Load)
            })
            .unwrap();
        app.world_mut()
            .commands()
            .trigger(Activate { entity: load });
        app.world_mut().flush();
        app.update();
        assert_eq!(
            app.world().resource::<State<AppState>>().get(),
            &AppState::LoadGame
        );
    }

    #[test]
    fn failed_load_does_not_replace_the_current_session() {
        let original = fixture_state();
        let dir = tempfile::tempdir().unwrap();
        write_save_file(
            retail_save_path(dir.path(), SaveSlot::Numbered(0)),
            b"not a retail save",
            OverwritePolicy::CreateNew,
        )
        .unwrap();
        let session = GameSession(original.clone());
        let result = commit_loaded_game(load_slot(dir.path(), SaveSlot::Numbered(0)));
        assert!(result.is_err());
        assert_eq!(session.0, original);
    }

    #[test]
    fn successful_load_replaces_the_session_and_enters_the_saved_phase() {
        let original = fixture_state();
        let dir = tempfile::tempdir().unwrap();
        save_current_game(dir.path(), SaveSlot::Numbered(1), &original, "England").unwrap();
        let (session, destination) =
            commit_loaded_game(load_slot(dir.path(), SaveSlot::Numbered(1))).unwrap();
        assert_eq!(session.0, original);
        assert_eq!(destination, AppState::StrategicMap);
    }

    #[test]
    fn save_helper_overwrites_an_existing_slot_file() {
        let original = fixture_state();
        let dir = tempfile::tempdir().unwrap();
        save_current_game(dir.path(), SaveSlot::Numbered(0), &original, "First").unwrap();
        save_current_game(dir.path(), SaveSlot::Numbered(0), &original, "Second").unwrap();
        let loaded = load_slot(dir.path(), SaveSlot::Numbered(0)).unwrap();
        assert_eq!(loaded, original);
        let bytes = std::fs::read(retail_save_path(dir.path(), SaveSlot::Numbered(0))).unwrap();
        assert_eq!(
            peek_save_header(&bytes).map(|header| header.label),
            Some("Second".to_owned())
        );
    }
}
