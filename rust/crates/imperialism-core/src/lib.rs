#![forbid(unsafe_code)]

mod ids;
mod snapshot;
mod state;

pub use ids::{ArmyId, CityId, MissionId, NationId, NavyId, ProvinceId, TileId};
pub use snapshot::{
    GAME_SNAPSHOT_SCHEMA, GAME_SNAPSHOT_SECTIONS, GameSnapshotV1, SnapshotCity, SnapshotEconomy,
    SnapshotHashes, SnapshotMajorNation, SnapshotMetadata, SnapshotNation, SnapshotNations,
    SnapshotPopulation, SnapshotRng, SnapshotValidationError, SnapshotWorld, TileSnapshot,
};
pub use state::{
    CityState, GameCommand, GameEvent, GameState, MajorNationState, NationKind, NationState,
    PopulationState, RngState, StepOutcome, TileState, TurnState, WorldState,
};
