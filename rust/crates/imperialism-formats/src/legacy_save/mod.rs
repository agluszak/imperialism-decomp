mod conversions;
mod from_game_state;
pub(crate) mod model;
mod parse;
pub(crate) mod project;
mod slots;
mod write;

#[cfg(test)]
mod tests;

use imperialism_core::{
    BattleReportSideTable, GameState, MajorNationId, MajorNationTable, MinorNationId,
    ProductionTable, TileId,
};
use indexmap::IndexMap;
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
    army_reports: Vec<model::LegacyBattleReport>,
    major_nations: IndexMap<MajorNationId, LegacyMajorNationState>,
    minor_nations: IndexMap<MinorNationId, LegacyMinorState>,
    help: LegacyHelpState,
}

/// Runtime-only state that the retail save format does not persist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyGameStateContext {
    pub crt_rand_state: u32,
    pub map_generation_lcg: u32,
    pub zone_status_lcg: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CityWindowPosition {
    pub left: i16,
    pub top: i16,
}

pub type CityWindowLayout = MajorNationTable<ProductionTable<Option<CityWindowPosition>>>;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BattleReportSideText {
    pub name: String,
    pub overlay: String,
}

pub type BattleReportText = BattleReportSideTable<BattleReportSideText>;

#[derive(Debug, PartialEq)]
pub struct LoadedGame {
    pub game: GameState,
    pub map_view_origin: TileId,
    pub city_windows: CityWindowLayout,
    pub battle_report_text: Vec<BattleReportText>,
}

fn city_windows_from_retail(
    flags: [u8; CITY_PRODUCTION_SLOT_COUNT],
    left: [i16; CITY_PRODUCTION_SLOT_COUNT],
    top: [i16; CITY_PRODUCTION_SLOT_COUNT],
) -> ProductionTable<Option<CityWindowPosition>> {
    ProductionTable::from_array(std::array::from_fn(|index| {
        (flags[index] != 0).then_some(CityWindowPosition {
            left: left[index],
            top: top[index],
        })
    }))
}

fn city_windows_to_retail(
    windows: &ProductionTable<Option<CityWindowPosition>>,
) -> (
    [u8; CITY_PRODUCTION_SLOT_COUNT],
    [i16; CITY_PRODUCTION_SLOT_COUNT],
    [i16; CITY_PRODUCTION_SLOT_COUNT],
) {
    let mut flags = [0_u8; CITY_PRODUCTION_SLOT_COUNT];
    let mut left = [0_i16; CITY_PRODUCTION_SLOT_COUNT];
    let mut top = [0_i16; CITY_PRODUCTION_SLOT_COUNT];
    for (index, window) in windows.as_array().iter().enumerate() {
        if let Some(position) = window {
            flags[index] = 1;
            left[index] = position.left;
            top[index] = position.top;
        }
    }
    (flags, left, top)
}
