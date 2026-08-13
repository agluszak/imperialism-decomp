mod from_game_state;
mod model;
mod parse;
mod project;
mod slots;
mod write;

#[cfg(test)]
mod tests;

use imperialism_core::NationId;
use model::{
    LegacyDiplomacyState, LegacyHelpState, LegacyMajorNationState, LegacyMapState,
    LegacyMinorState, LegacyNavyState, LegacyOceanState, LegacySaveHeader, LegacySimulationPrefix,
    LegacyTechnologyState, LegacyTradeMarketState,
};

const SAVE_LABEL_LENGTH: usize = 0x20;
const ACTIVE_NATION_NAME_LENGTH: usize = 0x20;
const RESOURCE_KIND_COUNT: usize = 23;
const CITY_PRODUCTION_SLOT_COUNT: usize = 16;
const TRADE_CATEGORY_COUNT: usize = 17;
const TERRAIN_TILE_SERIALIZED_SIZE: usize = 0x24;
const PROVINCE_COUNT: usize = 0x180;
const PROVINCE_FIXED_SERIALIZED_SIZE: usize = 0xa4;
const AI_ZONE_TARGET_CAPACITY: usize = 0x70;

pub use slots::{
    LoadGameError, NUMBERED_SAVE_SLOT_COUNT, OverwritePolicy, SAVE_FORMAT_VERSION,
    SAVE_LABEL_MAX_CHARS, SAVE_MAGIC, SaveDirectoryListing, SaveFileError, SaveHeaderInfo,
    SaveSlot, list_save_slots, load_game_from_bytes, load_game_from_path, normalize_save_label,
    peek_save_header, peek_save_preview_owners, retail_save_path, write_game_state,
    write_save_file,
};

#[allow(dead_code)]
pub struct LegacySaveV62 {
    header: LegacySaveHeader,
    simulation: LegacySimulationPrefix,
    animator_idle_frequency: i32,
    market: LegacyTradeMarketState,
    diplomacy: LegacyDiplomacyState,
    technology: LegacyTechnologyState,
    map: LegacyMapState,
    ocean: LegacyOceanState,
    navy: LegacyNavyState,
    army_report_count: u16,
    major_nations: Vec<LegacyMajorNationState>,
    minor_nations: Vec<LegacyMinorState>,
    help: LegacyHelpState,
}

/// Runtime-only state that the retail save format does not persist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyGameStateContext {
    pub crt_rand_state: u32,
    pub map_generation_lcg: u32,
    pub zone_status_lcg: u32,
    pub selected_nation: NationId,
}
