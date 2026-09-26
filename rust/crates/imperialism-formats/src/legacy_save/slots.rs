use super::{ACTIVE_NATION_NAME_LENGTH, SAVE_LABEL_LENGTH};
use super::{
    BattleReportText, CityWindowLayout, LegacyGameStateContext, LegacySaveV62, LoadedGame,
};
use imperialism_core::{GameState, PhaseCode, STRATEGIC_TILE_COUNT, TileId, TileOwnerTag};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub const SAVE_MAGIC: u32 = 0x414d_4249;
pub const SAVE_FORMAT_VERSION: u32 = 0x3e;
pub const SAVE_LABEL_MAX_CHARS: usize = 0x1f;
pub const NUMBERED_SAVE_SLOT_COUNT: u8 = 8;
const SINGLE_PLAYER_SLOT_PREFIX: &str = "slot";
const SAVE_EXTENSION: &str = ".imp";
const HEADER_LABEL_OFFSET: usize = 0x0c;
const HEADER_OWNERS_OFFSET: usize = HEADER_LABEL_OFFSET + SAVE_LABEL_LENGTH;
const HEADER_SUMMARY_OFFSET: usize = HEADER_OWNERS_OFFSET + STRATEGIC_TILE_COUNT;

/// One of the eight numbered retail slots, or the autosave slot `slotA.imp`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SaveSlot {
    Numbered(u8),
    Autosave,
}

impl SaveSlot {
    pub fn numbered(index: u8) -> Option<Self> {
        (index < NUMBERED_SAVE_SLOT_COUNT).then_some(Self::Numbered(index))
    }

    pub fn all_numbered() -> impl Iterator<Item = Self> {
        (0..NUMBERED_SAVE_SLOT_COUNT).map(Self::Numbered)
    }

    fn file_stem(self) -> String {
        match self {
            Self::Numbered(index) => format!("{SINGLE_PLAYER_SLOT_PREFIX}{index}"),
            Self::Autosave => format!("{SINGLE_PLAYER_SLOT_PREFIX}A"),
        }
    }
}

/// Browser metadata retail reads from the save header without loading the game.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SaveHeaderInfo {
    pub label: String,
    pub economic_year_offset: i16,
    pub difficulty: u8,
    pub active_nation: u8,
    pub active_nation_name: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SaveDirectoryListing {
    pub slots: [Option<SaveHeaderInfo>; NUMBERED_SAVE_SLOT_COUNT as usize],
    pub autosave: Option<SaveHeaderInfo>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverwritePolicy {
    CreateNew,
    Replace,
}

#[derive(Debug, thiserror::Error)]
pub enum SaveFileError {
    #[error("a save already exists at {}", .0.display())]
    AlreadyExists(PathBuf),
    #[error(transparent)]
    Io(#[from] io::Error),
}

#[derive(Debug, thiserror::Error)]
pub enum LoadGameError {
    #[error("save file is too short to be a retail .imp")]
    Truncated,
    #[error("save file is not a retail Imperialism document")]
    InvalidMagic,
    #[error("unsupported save format version {0:#x}")]
    UnsupportedVersion(u32),
    #[error(
        "this save is in phase {phase:?}; retail cannot create a single-player save in that phase"
    )]
    UnsupportedPhase { phase: PhaseCode },
    #[error(transparent)]
    Io(#[from] io::Error),
}

pub fn retail_save_path(directory: impl AsRef<Path>, slot: SaveSlot) -> PathBuf {
    directory
        .as_ref()
        .join(format!("{}{SAVE_EXTENSION}", slot.file_stem()))
}

pub fn normalize_save_label(label: &str) -> String {
    let mut bytes = label.as_bytes();
    if bytes.len() > SAVE_LABEL_MAX_CHARS {
        bytes = &bytes[..SAVE_LABEL_MAX_CHARS];
        while !bytes.is_empty() && std::str::from_utf8(bytes).is_err() {
            bytes = &bytes[..bytes.len() - 1];
        }
    }
    String::from_utf8_lossy(bytes).into_owned()
}

pub fn peek_save_header(bytes: &[u8]) -> Option<SaveHeaderInfo> {
    if bytes.len() < HEADER_LABEL_OFFSET + SAVE_LABEL_LENGTH {
        return None;
    }
    let label = fixed_text(&bytes[HEADER_LABEL_OFFSET..HEADER_LABEL_OFFSET + SAVE_LABEL_LENGTH]);
    if bytes.len() < HEADER_SUMMARY_OFFSET + 2 + 1 + 1 + ACTIVE_NATION_NAME_LENGTH {
        return Some(SaveHeaderInfo {
            label,
            economic_year_offset: 0,
            difficulty: 0,
            active_nation: 0,
            active_nation_name: String::new(),
        });
    }
    let summary = &bytes[HEADER_SUMMARY_OFFSET..];
    Some(SaveHeaderInfo {
        label,
        economic_year_offset: i16::from_le_bytes([summary[0], summary[1]]),
        difficulty: summary[2],
        active_nation: summary[3],
        active_nation_name: fixed_text(&summary[4..4 + ACTIVE_NATION_NAME_LENGTH]),
    })
}

/// Tile-owner tags the Load/Save satellite preview reads from the save header.
pub fn peek_save_preview_owners(bytes: &[u8]) -> Option<Vec<Option<TileOwnerTag>>> {
    let end = HEADER_OWNERS_OFFSET + STRATEGIC_TILE_COUNT;
    if bytes.len() < end {
        return None;
    }
    Some(
        bytes[HEADER_OWNERS_OFFSET..end]
            .iter()
            .map(|&byte| {
                let value = byte as i8;
                (value != -1).then(|| TileOwnerTag::new(value as u8))
            })
            .collect(),
    )
}

pub fn list_save_slots(directory: impl AsRef<Path>) -> SaveDirectoryListing {
    let directory = directory.as_ref();
    let mut slots = std::array::from_fn(|_| None);
    for (index, slot) in SaveSlot::all_numbered().enumerate() {
        slots[index] = read_slot_header(directory, slot);
    }
    SaveDirectoryListing {
        slots,
        autosave: read_slot_header(directory, SaveSlot::Autosave),
    }
}

fn read_slot_header(directory: &Path, slot: SaveSlot) -> Option<SaveHeaderInfo> {
    let path = retail_save_path(directory, slot);
    let bytes = std::fs::read(path).ok()?;
    peek_save_header(&bytes).or_else(|| {
        Some(SaveHeaderInfo {
            label: String::new(),
            economic_year_offset: 0,
            difficulty: 0,
            active_nation: 0,
            active_nation_name: String::new(),
        })
    })
}

pub fn write_save_file(
    path: impl AsRef<Path>,
    bytes: &[u8],
    policy: OverwritePolicy,
) -> Result<(), SaveFileError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut options = OpenOptions::new();
    options.write(true);
    match policy {
        OverwritePolicy::CreateNew => {
            options.create_new(true);
        }
        OverwritePolicy::Replace => {
            options.create(true).truncate(true);
        }
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            return Err(SaveFileError::AlreadyExists(path.to_path_buf()));
        }
        Err(error) => return Err(error.into()),
    };
    file.write_all(bytes)?;
    Ok(())
}

pub fn load_game_from_bytes(
    bytes: &[u8],
    context: LegacyGameStateContext,
) -> Result<LoadedGame, LoadGameError> {
    if bytes.len() < 8 {
        return Err(LoadGameError::Truncated);
    }
    let magic = u32::from_le_bytes(bytes[0..4].try_into().expect("length checked"));
    if magic != SAVE_MAGIC {
        return Err(LoadGameError::InvalidMagic);
    }
    let version = u32::from_le_bytes(bytes[4..8].try_into().expect("length checked"));
    if version != SAVE_FORMAT_VERSION {
        return Err(LoadGameError::UnsupportedVersion(version));
    }
    let save = LegacySaveV62::parse(bytes);
    // Manual saves are written while the optional save screen has phase 4; the
    // newspaper autosave is written after case 0xf sets phase 0x12. Retail cannot
    // create a single-player save in any other phase.
    let phase = PhaseCode::from_retail(i32::from(save.simulation.turn_state_code));
    if !matches!(
        phase,
        PhaseCode::STRATEGIC_MAP
            | PhaseCode::CAPITAL_SELECTION
            | PhaseCode::HOME_PLACEMENT
            | PhaseCode::RETURN_TO_MAP
    ) {
        return Err(LoadGameError::UnsupportedPhase { phase });
    }
    let map_view_origin = save.map_view_origin();
    let city_windows = save.city_window_layout();
    let battle_report_text = save.battle_report_text();
    let mut game = save.game_state(context);
    // `TSimMgr::ReadFrom` resumes the autosave through phase 4 onto the strategic map.
    if phase == PhaseCode::RETURN_TO_MAP {
        game.resume_retail_save_on_strategic_map();
    }
    Ok(LoadedGame {
        game,
        map_view_origin,
        city_windows,
        battle_report_text,
    })
}

pub fn load_game_from_path(
    path: impl AsRef<Path>,
    context: LegacyGameStateContext,
) -> Result<LoadedGame, LoadGameError> {
    let bytes = std::fs::read(path)?;
    load_game_from_bytes(&bytes, context)
}

pub fn write_game_state(
    state: &GameState,
    map_view_origin: TileId,
    city_windows: &CityWindowLayout,
    battle_report_text: &[BattleReportText],
    label: &str,
    session_slot: i32,
) -> Vec<u8> {
    LegacySaveV62::from_game_state(
        state,
        map_view_origin,
        city_windows,
        battle_report_text,
        label,
        session_slot,
    )
    .to_bytes()
}

fn fixed_text(bytes: &[u8]) -> String {
    let length = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..length]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbered_slot_paths_use_the_retail_single_player_names() {
        let dir = Path::new("saves");
        assert_eq!(
            retail_save_path(dir, SaveSlot::numbered(0).unwrap()),
            PathBuf::from("saves/slot0.imp")
        );
        assert_eq!(
            retail_save_path(dir, SaveSlot::numbered(7).unwrap()),
            PathBuf::from("saves/slot7.imp")
        );
        assert_eq!(
            retail_save_path(dir, SaveSlot::Autosave),
            PathBuf::from("saves/slotA.imp")
        );
        assert!(SaveSlot::numbered(8).is_none());
    }

    #[test]
    fn normalize_save_label_truncates_to_the_retail_edit_limit() {
        assert_eq!(normalize_save_label(""), "");
        assert_eq!(normalize_save_label("England"), "England");
        let long = "abcdefghijklmnopqrstuvwxyz0123456789";
        assert_eq!(normalize_save_label(long).len(), SAVE_LABEL_MAX_CHARS);
        assert_eq!(&normalize_save_label(long), &long[..SAVE_LABEL_MAX_CHARS]);
    }

    #[test]
    fn overwrite_policy_create_new_fails_when_the_file_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slot0.imp");
        write_save_file(&path, b"first", OverwritePolicy::CreateNew).unwrap();
        let error = write_save_file(&path, b"second", OverwritePolicy::CreateNew).unwrap_err();
        assert!(matches!(error, SaveFileError::AlreadyExists(_)));
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
    }

    #[test]
    fn overwrite_policy_replace_overwrites_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("slot0.imp");
        write_save_file(&path, b"first", OverwritePolicy::CreateNew).unwrap();
        write_save_file(&path, b"second", OverwritePolicy::Replace).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"second");
    }

    #[test]
    fn list_save_slots_reads_header_labels_from_existing_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut header = vec![0; HEADER_LABEL_OFFSET + SAVE_LABEL_LENGTH];
        header[HEADER_LABEL_OFFSET..HEADER_LABEL_OFFSET + 5].copy_from_slice(b"Alpha");
        write_save_file(
            retail_save_path(dir.path(), SaveSlot::Numbered(0)),
            &header,
            OverwritePolicy::CreateNew,
        )
        .unwrap();
        let listing = list_save_slots(dir.path());
        assert_eq!(
            listing.slots[0].as_ref().map(|info| info.label.as_str()),
            Some("Alpha")
        );
        assert!(listing.slots[1].is_none());
        assert!(listing.autosave.is_none());
    }

    #[test]
    fn load_game_from_bytes_rejects_invalid_magic_without_parsing() {
        let error = load_game_from_bytes(
            &[0; 16],
            LegacyGameStateContext {
                crt_rand_state: 0,
                map_generation_lcg: 0,
                zone_status_lcg: 0,
            },
        )
        .unwrap_err();
        assert!(matches!(error, LoadGameError::InvalidMagic));
    }

    #[test]
    fn peek_save_preview_owners_reads_signed_header_tags() {
        let mut bytes = vec![0; HEADER_OWNERS_OFFSET + STRATEGIC_TILE_COUNT];
        bytes[HEADER_OWNERS_OFFSET] = 3;
        bytes[HEADER_OWNERS_OFFSET + 1] = 0xff;
        let owners = peek_save_preview_owners(&bytes).unwrap();
        assert_eq!(owners.len(), STRATEGIC_TILE_COUNT);
        assert_eq!(owners[0], Some(TileOwnerTag::new(3)));
        assert_eq!(owners[1], None);
        assert!(peek_save_preview_owners(&bytes[..HEADER_OWNERS_OFFSET]).is_none());
    }
}
