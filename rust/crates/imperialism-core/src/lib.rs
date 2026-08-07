#![forbid(unsafe_code)]

mod ids;
mod snapshot;
mod state;

pub use ids::{
    ArmyId, CityId, MilitaryUnitId, MissionId, NationId, NavyId, ProvinceId, ShipId, TaskForceId,
    TileId,
};
pub use snapshot::{
    GAME_SNAPSHOT_SCHEMA, GAME_SNAPSHOT_SECTIONS, GameSnapshotV1, SnapshotCity, SnapshotEconomy,
    SnapshotHashes, SnapshotMajorNation, SnapshotMetadata, SnapshotMilitary, SnapshotMilitaryUnit,
    SnapshotNation, SnapshotNations, SnapshotPopulation, SnapshotRng, SnapshotShip,
    SnapshotTaskForce, SnapshotValidationError, SnapshotWorld, TileSnapshot,
};
pub use state::{
    CityState, GameCommand, GameEvent, GameState, MajorNationState, MilitaryUnitState, NationKind,
    NationState, PopulationState, RngState, ShipState, StepOutcome, TaskForceState,
    TaskForceTarget, TileState, TurnState, WorldState,
};
