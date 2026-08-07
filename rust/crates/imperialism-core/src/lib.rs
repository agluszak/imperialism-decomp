#![forbid(unsafe_code)]

mod calendar;
mod city_buildings;
mod city_economy;
mod city_industry;
mod ids;
mod map_geometry;
mod nation_economy;
mod population;
mod production;
mod resources;
mod rng;
mod snapshot;
mod state;
mod turn_flow;

pub use calendar::TurnCalendar;
pub use city_buildings::{BuildingWindowState, CityBuildingError, ProductionSlot};
pub use city_economy::CityEconomyError;
pub use city_industry::{CityIndustryError, IndustryActionSlot};
pub use ids::{
    ArmyId, CityId, MilitaryUnitId, MissionId, NationId, NavyId, ProvinceId, ShipId, TaskForceId,
    TileId,
};
pub use map_geometry::{
    HexDirection, MapGeometry, STRATEGIC_MAP_HEIGHT, STRATEGIC_MAP_WIDTH, STRATEGIC_TILE_COUNT,
};
pub use nation_economy::NationEconomyError;
pub use population::{FoodOutcome, LaborPool, PopulationError, SkillBand};
pub use production::{
    CapacityProductionOrder, CapacityTarget, ExpansionProductionOrder, ExpansionTarget,
    FoodProductionOrder, ItemInputs, ItemProductionOrder, PopulationGrowthOrder,
    PowerPlantProductionOrder, ProductionConstraint, ProductionError,
};
pub use resources::ResourceKind;
pub use snapshot::{
    GAME_SNAPSHOT_SCHEMA, GAME_SNAPSHOT_SECTIONS, GameSnapshotV1, SnapshotArmyMission,
    SnapshotAttackMission, SnapshotCity, SnapshotEconomy, SnapshotHashes, SnapshotMajorNation,
    SnapshotMetadata, SnapshotMilitary, SnapshotMilitaryUnit, SnapshotMission, SnapshotMissions,
    SnapshotNation, SnapshotNationPending, SnapshotNations, SnapshotNavyMission, SnapshotPending,
    SnapshotPopulation, SnapshotRng, SnapshotShip, SnapshotTaskForce, SnapshotTurnStartEvent,
    SnapshotValidationError, SnapshotWorld, TileSnapshot,
};
pub use state::{
    ArmyMissionState, CityState, GameCommand, GameEvent, GameState, MajorNationState,
    MilitaryUnitState, MissionKind, MissionState, NationKind, NationPendingWork, NationState,
    NavyMissionState, PendingWorkState, PopulationState, RngState, ShipState, StepOutcome,
    TaskForceState, TaskForceTarget, TileState, TurnStartEventState, TurnState, WorldState,
};
pub use turn_flow::TurnFlowError;
