#![forbid(unsafe_code)]

mod ids;
mod snapshot;
mod state;

pub use ids::{
    ArmyId, CityId, MilitaryUnitId, MissionId, NationId, NavyId, ProvinceId, ShipId, TaskForceId,
    TileId,
};
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
