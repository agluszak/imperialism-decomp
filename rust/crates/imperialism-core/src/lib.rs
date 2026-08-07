#![forbid(unsafe_code)]

mod ids;
mod snapshot;
mod state;

pub use ids::{ArmyId, CityId, MissionId, NationId, NavyId, ProvinceId, TileId};
pub use snapshot::{
    GAME_SNAPSHOT_SCHEMA, GAME_SNAPSHOT_SECTIONS, GameSnapshotV1, SnapshotHashes, SnapshotMetadata,
    SnapshotRng, SnapshotValidationError, SnapshotWorld, TileSnapshot,
};
pub use state::{
    GameCommand, GameEvent, GameState, RngState, StepOutcome, TileState, TurnState, WorldState,
};
