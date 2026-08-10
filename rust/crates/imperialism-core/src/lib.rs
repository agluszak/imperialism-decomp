#![forbid(unsafe_code)]
#![allow(clippy::large_enum_variant)]

mod calendar;
mod city_buildings;
mod city_economy;
mod city_industry;
mod city_site;
mod city_transport_phase;
mod civilian_phase;
mod civilian_work;
mod combat_movement_phase;
mod create_random_game;
mod difficulty;
mod diplomacy;
mod ids;
mod map_geometry;
mod market;
mod military;
mod military_cleanup_phase;
mod military_phase;
mod nation_economy;
mod news;
mod population;
mod production;
mod random_map;
mod random_map_terrain;
mod random_map_water_merge;
mod random_setup_name;
mod recruitment;
mod resources;
mod rng;
mod state;
mod tables;
mod territory;
#[cfg(test)]
pub(crate) mod test_support;
mod trade;
mod trade_phase;
mod turn_flow;
mod units;

pub use calendar::TurnCalendar;
pub use city_buildings::{BuildingWindowState, ProductionSlot};
pub use city_site::{
    CapitalSite, CitySiteError, confirm_capital_site,
    enter_strategic_map_without_capital_selection, is_valid_secondary_nation_home_tile_candidate,
    place_city, requires_capital_site_selection, supports_city_site_terrain,
    validate_capital_site_selection,
};
pub use civilian_work::{CivilianWorkOrder, RailSegment, TurnsRemaining};
pub use create_random_game::create_random_game;
pub use difficulty::Difficulty;
pub use diplomacy::{PlayerDiplomacyOrderResult, PlayerDiplomacyRejection};
pub use ids::{
    CivilianUnitId, MajorNationId, MilitaryUnitId, MinorNationId, NationId, OceanZoneId,
    ProvinceId, ShipId, TaskForceId, TileId, TileOwnerTag,
};
pub use map_geometry::{
    HexDirection, MapGeometry, MapTopology, STRATEGIC_MAP_HEIGHT, STRATEGIC_MAP_WIDTH,
    STRATEGIC_TILE_COUNT,
};
pub use market::{
    DealBookEntryKind, ProcessedTradeCommodity, ProcessedTradeCommodityTable, TradeCommodity,
    TradeCommodityTable, TradeDealBookEntry, TradeMarketRow, TradeMarketState,
};
pub use population::{FoodOutcome, LaborPool, SkillBand};
pub use production::*;
pub use random_map::{
    COARSE_MAP_CELL_COUNT, COARSE_MAP_HEIGHT, COARSE_MAP_WIDTH, EXPANDED_MAP_HEIGHT,
    EXPANDED_MAP_WIDTH, RANDOM_MAP_CLASS_COUNT,
};
pub use random_map_terrain::{
    GeneratedMap, GeneratedProvince, GeneratedTerrainTile, RandomMapTuning, RandomSetupPreview,
    RandomSetupPreviewError, generate_random_map, generate_random_setup_preview,
    generate_random_setup_preview_with_clock_seed,
};
pub use random_setup_name::{COUNTRY_NAME_MAX_CHARS, generate_english_random_setup_name};

/// Instrumentation used only by the C++ differential test harness. It is not
/// enabled by `imperialism-core`'s default feature set and must not be used by
/// normal game creation.
#[cfg(feature = "differential-trace")]
pub mod differential_trace {
    pub use crate::random_map::{
        CoarseMap, CoarseMapAttempt, CoarseMapGrid, CoarseMapTrace, trace_coarse_random_map,
    };
    pub use crate::random_map_terrain::{
        RandomMapTerrainAttemptTrace, RandomMapTerrainStageTrace, RandomMapTerrainTrace,
        trace_random_map_terrain,
    };
}
pub(crate) use resources::all_resources;
pub use resources::{ResourceKind, ResourceTable};
pub use rng::{RetailCrtRng, RetailLcg, hash_retail_scenario_tag};
pub use state::*;
pub use tables::{
    MAJOR_NATION_COUNT, MINOR_NATION_COUNT, MajorNationTable, MinorNationTable, NATION_COUNT,
    NationCapacities, NationTable, PENDING_ACTION_COUNT, PROVINCE_COUNT, PendingActionKind,
    PendingActionTable, ProductionTable, ProvinceTable, ShipType, ShipTypeTable,
};
pub use territory::{CountryStatus, ProvinceState, ProvinceStateError, TerritoryInvariantError};
pub use trade::{PlayerTradeOrder, TransportAllocation};
pub use turn_flow::{AdvanceTurnOutcome, TurnBlock, TurnEffect};
pub use units::{CivilianUnitKind, CivilianUnitTable, MilitaryUnitKind, MilitaryUnitTable};
