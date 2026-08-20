#![forbid(unsafe_code)]

//! Compatibility boundary for retail saves, maps, resources, and direct asset access.
//!
//! Retail format implementations keep binary-layout DTOs private and project into
//! `imperialism-core` state. This crate intentionally contains no live game rules or Bevy types.

mod color;
mod legacy_save;
mod legacy_stream;
mod media;
mod retail_assets;
mod retail_fonts;
mod retail_resources;
mod retail_ui;
mod scenario;
mod scores_dat;

pub use color::{DibPalette, Rgb};
pub use legacy_save::{
    BattleReportSideText, BattleReportText, CityWindowLayout, CityWindowPosition,
    LegacyGameStateContext, LegacySaveV62, LoadGameError, LoadedGame, NUMBERED_SAVE_SLOT_COUNT,
    OverwritePolicy, SAVE_FORMAT_VERSION, SAVE_LABEL_MAX_CHARS, SAVE_MAGIC, SaveDirectoryListing,
    SaveFileError, SaveHeaderInfo, SaveSlot, list_save_slots, load_game_from_bytes,
    load_game_from_path, normalize_save_label, peek_save_header, peek_save_preview_owners,
    retail_save_path, write_game_state, write_save_file,
};
pub use media::{MovieId, MusicTrack, SoundId};
pub use retail_assets::{NewsTable, RetailAssetError, RetailAssets};
pub use retail_fonts::{
    ResolvedRetailTextStyle, RetailFontCellMetrics, RetailFontFace, RetailFontMetricsError,
    RetailTextAlignment, RetailTextStyleError, RetailTextStylePreset,
    decode_retail_font_cell_metrics, resolve_retail_text_style,
};
pub use retail_resources::{IndexedPicture, RetailCursor};
pub use retail_ui::{FourCc, OKAY, PictureId, TRADE};
pub use scenario::{ScenarioScriptError, decode_scenario_script};
pub use scores_dat::{
    HIGH_SCORE_COUNT, HIGH_SCORE_NAME_LENGTH, HighScoreEntry, HighScoreTable,
    empty_high_score_table, insert_high_score, read_scores_dat, read_scores_dat_from,
    write_scores_dat, write_scores_dat_to,
};
