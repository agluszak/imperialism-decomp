#![forbid(unsafe_code)]
#![allow(clippy::large_enum_variant)]

mod calendar;
mod city_buildings;
mod city_economy;
mod city_industry;
mod city_site;
mod create_random_game;
mod difficulty;
mod ids;
mod map_geometry;
mod nation_economy;
mod population;
mod production;
mod random_map;
mod random_map_terrain;
mod random_setup_name;
mod recruitment;
mod resources;
mod rng;
mod state;
mod tables;
mod trade;
mod turn_flow;
mod units;

pub use calendar::TurnCalendar;
pub use city_buildings::{BuildingWindowState, ProductionSlot};
pub use city_site::{
    CitySiteError, confirm_capital_site, enter_strategic_map_without_capital_selection,
    is_valid_secondary_nation_home_tile_candidate, place_city, requires_capital_site_selection,
    supports_city_site_terrain, validate_capital_site_selection,
};
pub use create_random_game::create_random_game;
pub use difficulty::Difficulty;
pub use ids::{
    ArmyId, CityId, CivilianUnitId, MajorNationId, MilitaryUnitId, MinorNationId, MissionId,
    NationId, NavyId, ProvinceId, ShipId, TaskForceId, TileId, TileOwnerTag,
};
pub use map_geometry::{
    HexDirection, MapGeometry, RetailTopologyByte, STRATEGIC_MAP_HEIGHT, STRATEGIC_MAP_WIDTH,
    STRATEGIC_TILE_COUNT,
};
pub use population::{FoodOutcome, LaborPool, PopulationError, SkillBand};
pub use production::{
    CapacityProductionOrder, CapacityTarget, ExpansionProductionOrder, ExpansionTarget,
    FoodProductionOrder, ItemInputs, ItemProductionOrder, PopulationGrowthOrder,
    PowerPlantProductionOrder, ProductionConstraint, ProductionError, ResourceCost, TrainingLevel,
    TrainingProductionOrder, UnitCostProfile, UnitProductionOrder,
};
pub use random_map::{
    COARSE_MAP_CELL_COUNT, COARSE_MAP_HEIGHT, COARSE_MAP_WIDTH, CoarseMap, CoarseMapGrid,
    EXPANDED_MAP_HEIGHT, EXPANDED_MAP_WIDTH, ExpandedProvinceSeed, RANDOM_MAP_CLASS_COUNT,
    generate_coarse_random_map,
};
pub use random_map_terrain::{
    GeneratedMap, GeneratedTerrainTile, RandomMapTuning, RandomSetupPreview,
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
        CoarseMapAttempt, CoarseMapTrace, ExpandedMapSeedTile, trace_coarse_random_map,
    };
    pub use crate::random_map_terrain::{
        RandomMapTerrainAttemptTrace, RandomMapTerrainCapture, RandomMapTerrainStageTrace,
        RandomMapTerrainTrace, trace_random_map_terrain,
    };
}
pub use recruitment::RecruitmentError;
pub use resources::{ResourceKind, ResourceTable, all_resources};
pub use rng::{RetailCrtRng, RetailLcg, hash_retail_scenario_tag};
pub use state::{
    ArmyMissionState, AttackMissionState, CityState, CivilianUnitState, DiplomacyGrant,
    DiplomacyGrantFlags, DiplomacyPolicy, GameEvent, GameState, LandSale, MajorNationState,
    MilitaryUnitState, MissionData, MissionState, NationCommonState, NationData, NationPendingWork,
    NationState, NavyMissionState, PendingWorkState, PopulationState, RngState, SelectedShip,
    ShipState, StepOutcome, TaggedValue, TaskForceState, TaskForceTarget, TileState,
    TradePolicyScore, TurnStartEventState, TurnState, TurnSummary, WarTransition, WorldState,
};
pub use tables::{
    IndustryActionSlot, IndustryActionTable, MAJOR_NATION_COUNT, MINOR_NATION_COUNT,
    MajorNationTable, MinorNationTable, NATION_COUNT, NationCapacity, NationCapacityTable,
    NationTable, PENDING_ACTION_COUNT, PendingActionKind, PendingActionTable, ProductionTable,
};
pub use trade::RuleError;
pub use turn_flow::TurnFlowError;
pub use units::{
    CivilianUnitKind, CivilianUnitTable, MilitaryUnitKind, MilitaryUnitTable, RecruitKind,
};
