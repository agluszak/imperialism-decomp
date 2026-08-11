mod errors;
mod model;
mod normalize;
mod parse;
mod project;

#[cfg(test)]
mod tests;

use imperialism_core::{DiplomacyState, NationId, TechnologyState, TradeMarketState};
use model::{
    LegacyHelpState, LegacyMajorNationState, LegacyMapState, LegacyMinorState, LegacyNavyState,
    LegacyOceanState, LegacySaveHeader, LegacySimulationPrefix,
};

pub use errors::LegacySaveError;

pub(super) const SAVE_MAGIC: [u8; 4] = *b"IBMA";
pub(super) const CURRENT_RETAIL_VERSION: u32 = 0x3e;
pub(super) const SAVE_LABEL_LENGTH: usize = 0x20;
pub(super) const ACTIVE_NATION_NAME_LENGTH: usize = 0x20;
pub(super) const RESOURCE_KIND_COUNT: usize = 23;
pub(super) const CITY_PRODUCTION_SLOT_COUNT: usize = 16;
pub(super) const TRADE_CATEGORY_COUNT: usize = 17;
pub(super) const DIPLOMACY_SERIALIZED_SIZE_V62: usize = 5_460;
pub(super) const TECH_SERIALIZED_SIZE_V62: usize = 1_914;
pub(super) const TECH_PRIORITY_SLOTS_OFFSET_V62: usize = 0;
pub(super) const TECH_GLOBAL_UNLOCK_FLAGS_OFFSET_V62: usize = 0x180;
pub(super) const TECH_INDUSTRY_ENABLED_OFFSET_V62: usize = 0x19d;
pub(super) const TECH_ADVANCED_IRON_WORKING_OFFSET_V62: usize = 0x1a5;
pub(super) const TECH_MARINE_ENGINEERING_OFFSET_V62: usize = 0x1a8;
pub(super) const TECH_ORDER_CAP_ROWS_OFFSET_V62: usize = 0x262;
pub(super) const TECH_ORDER_CAP_ROW_SIZE: usize = 0x1d;
pub(super) const TECH_ABILITY_ACTIVE_ROWS_OFFSET_V62: usize = 0x38f;
pub(super) const TECH_ABILITY_ACTIVE_ROW_SIZE: usize = 30;
pub(super) const TECH_ADVANCED_IRON_WORKING_ID: usize = 0x0f;
pub(super) const TECH_OIL_DRILLING_ID: usize = 0x13;
pub(super) const TECH_UNIVERSITY_AVAILABILITY_OFFSET_V62: usize = 0x461;
pub(super) const TECH_UNIVERSITY_AVAILABILITY_ROW_SIZE: usize = 9;
pub(super) const TECH_FINAL_REQUIREMENT_LEVELS_OFFSET_V62: usize = 0x636;
pub(super) const TECH_REQUIREMENT_LEVELS_ROW_SIZE: usize =
    RESOURCE_KIND_COUNT * std::mem::size_of::<i16>();
pub(super) const TERRAIN_TILE_SERIALIZED_SIZE: usize = 0x24;
pub(super) const PROVINCE_COUNT: usize = 0x180;
pub(super) const PROVINCE_FIXED_SERIALIZED_SIZE: usize = 0xa4;
/// Format-specific ceilings for externally supplied collection lengths.
pub(super) const MAX_MISSIONS: usize = 1_024;
pub(super) const MAX_OCEAN_ZONES: usize = 4_096;
pub(super) const MAX_OCEAN_ROUTES: usize = 4_096;
pub(super) const AI_ZONE_TARGET_CAPACITY: usize = 0x70;
pub(super) const MAX_SHIPS: usize = 1_024;
pub(super) const MAX_ADMIRALS: usize = 1_024;
pub(super) const MAX_TASK_FORCES: usize = 1_024;
pub(super) const MAX_TASK_FORCE_CHILDREN: usize = 256;
pub(super) const MAX_MILITARY_UNITS: usize = 4_096;
pub(super) const MAX_OWNED_REGIONS: usize = PROVINCE_COUNT;
pub(super) const MAX_CITY_TASKS: usize = 1_024;
pub(super) const MAX_ARMY_REPORTS: usize = 1_024;
pub(super) const MAX_TRADE_HISTORY_RECORDS: usize = 65_536;
pub(super) const MAX_LONGINT_LIST: usize = 65_536;

#[derive(Clone, Debug, PartialEq)]
pub struct LegacySaveV62 {
    header: LegacySaveHeader,
    simulation: LegacySimulationPrefix,
    animator_idle_frequency: i32,
    market: TradeMarketState,
    diplomacy: DiplomacyState,
    technology: TechnologyState,
    map: LegacyMapState,
    ocean: LegacyOceanState,
    navy: LegacyNavyState,
    army_report_count: u16,
    /// Byte position immediately after `TArmyMgr`; nation records start here.
    remaining_manager_chain_offset: usize,
    major_nations: Vec<LegacyMajorNationState>,
    minor_nations: Vec<LegacyMinorState>,
    help: LegacyHelpState,
    /// Must equal the input length for a complete, non-trailing v62 save.
    end_offset: usize,
}

/// Runtime-only state that the retail save format does not persist.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LegacyGameStateContext {
    pub crt_rand_state: u32,
    pub map_generation_lcg: u32,
    pub zone_status_lcg: u32,
    pub selected_nation: NationId,
}
