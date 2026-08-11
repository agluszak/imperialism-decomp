mod model;
mod parse;
mod project;

#[cfg(test)]
mod tests;

use imperialism_core::NationId;
use model::{
    LegacyDiplomacyState, LegacyHelpState, LegacyMajorNationState, LegacyMapState,
    LegacyMinorState, LegacyNavyState, LegacyOceanState, LegacySaveHeader, LegacySimulationPrefix,
    LegacyTechnologyState, LegacyTradeMarketState,
};

pub(super) const SAVE_LABEL_LENGTH: usize = 0x20;
pub(super) const ACTIVE_NATION_NAME_LENGTH: usize = 0x20;
pub(super) const RESOURCE_KIND_COUNT: usize = 23;
pub(super) const CITY_PRODUCTION_SLOT_COUNT: usize = 16;
pub(super) const TRADE_CATEGORY_COUNT: usize = 17;
pub(super) const TERRAIN_TILE_SERIALIZED_SIZE: usize = 0x24;
pub(super) const PROVINCE_COUNT: usize = 0x180;
pub(super) const PROVINCE_FIXED_SERIALIZED_SIZE: usize = 0xa4;
pub(super) const AI_ZONE_TARGET_CAPACITY: usize = 0x70;

#[derive(Clone, Debug, PartialEq)]
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
