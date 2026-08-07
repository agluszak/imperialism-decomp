#![forbid(unsafe_code)]

use imperialism_core::{GameSnapshotV1, SnapshotValidationError};
use std::error::Error;
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;

#[derive(Debug)]
pub enum SnapshotReadError {
    Io(std::io::Error),
    Json(serde_json::Error),
    MissingGameSnapshot,
    Validation(SnapshotValidationError),
}

impl fmt::Display for SnapshotReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "could not read game snapshot: {error}"),
            Self::Json(error) => write!(formatter, "could not decode game snapshot: {error}"),
            Self::MissingGameSnapshot => write!(formatter, "result contains no game snapshot"),
            Self::Validation(error) => write!(formatter, "invalid game snapshot: {error}"),
        }
    }
}

impl Error for SnapshotReadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::MissingGameSnapshot => None,
            Self::Validation(error) => Some(error),
        }
    }
}

pub fn read_game_snapshot(path: &Path) -> Result<GameSnapshotV1, SnapshotReadError> {
    let file = File::open(path).map_err(SnapshotReadError::Io)?;
    decode_game_snapshot(file)
}

pub fn decode_game_snapshot(reader: impl Read) -> Result<GameSnapshotV1, SnapshotReadError> {
    let value: serde_json::Value =
        serde_json::from_reader(reader).map_err(SnapshotReadError::Json)?;
    let snapshot_value = if value.get("schema").is_some() {
        value
    } else {
        value
            .get("game_snapshot")
            .cloned()
            .filter(|snapshot| !snapshot.is_null())
            .ok_or(SnapshotReadError::MissingGameSnapshot)?
    };
    let snapshot: GameSnapshotV1 =
        serde_json::from_value(snapshot_value).map_err(SnapshotReadError::Json)?;
    snapshot
        .verify_hashes()
        .map_err(SnapshotReadError::Validation)?;
    Ok(snapshot)
}
