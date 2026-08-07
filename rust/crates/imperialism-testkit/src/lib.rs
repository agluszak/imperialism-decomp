#![forbid(unsafe_code)]

use imperialism_core::{GameSnapshotV1, SnapshotValidationError};
use std::collections::BTreeSet;
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotDifference {
    pub path: String,
    pub original: Option<serde_json::Value>,
    pub reimplementation: Option<serde_json::Value>,
}

pub fn first_snapshot_difference(
    original: &GameSnapshotV1,
    reimplementation: &GameSnapshotV1,
) -> Result<Option<SnapshotDifference>, serde_json::Error> {
    for (name, original_section, reimplementation_section) in [
        (
            "metadata",
            serde_json::to_value(&original.metadata)?,
            serde_json::to_value(&reimplementation.metadata)?,
        ),
        (
            "rng",
            serde_json::to_value(&original.rng)?,
            serde_json::to_value(&reimplementation.rng)?,
        ),
        (
            "world",
            serde_json::to_value(&original.world)?,
            serde_json::to_value(&reimplementation.world)?,
        ),
        (
            "nations",
            serde_json::to_value(&original.nations)?,
            serde_json::to_value(&reimplementation.nations)?,
        ),
        (
            "economy",
            serde_json::to_value(&original.economy)?,
            serde_json::to_value(&reimplementation.economy)?,
        ),
        (
            "military",
            serde_json::to_value(&original.military)?,
            serde_json::to_value(&reimplementation.military)?,
        ),
    ] {
        if let Some(difference) = difference_at(
            name.to_owned(),
            Some(&original_section),
            Some(&reimplementation_section),
        ) {
            return Ok(Some(difference));
        }
    }
    Ok(None)
}

fn difference_at(
    path: String,
    original: Option<&serde_json::Value>,
    reimplementation: Option<&serde_json::Value>,
) -> Option<SnapshotDifference> {
    if original == reimplementation {
        return None;
    }
    match (original, reimplementation) {
        (Some(serde_json::Value::Object(left)), Some(serde_json::Value::Object(right))) => {
            let keys = left
                .keys()
                .chain(right.keys())
                .map(String::as_str)
                .collect::<BTreeSet<_>>();
            keys.into_iter().find_map(|key| {
                difference_at(format!("{path}.{key}"), left.get(key), right.get(key))
            })
        }
        (Some(serde_json::Value::Array(left)), Some(serde_json::Value::Array(right))) => {
            (0..left.len().max(right.len())).find_map(|index| {
                difference_at(
                    format!("{path}[{index}]"),
                    left.get(index),
                    right.get(index),
                )
            })
        }
        _ => Some(SnapshotDifference {
            path,
            original: original.cloned(),
            reimplementation: reimplementation.cloned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reports_the_first_structural_path() {
        let original = json!({"cities": [{"stock": [2, 4, 6]}]});
        let reimplementation = json!({"cities": [{"stock": [2, 5, 6]}]});
        let difference = difference_at(
            "economy".to_owned(),
            Some(&original),
            Some(&reimplementation),
        )
        .unwrap();
        assert_eq!(difference.path, "economy.cities[0].stock[1]");
        assert_eq!(difference.original, Some(json!(4)));
        assert_eq!(difference.reimplementation, Some(json!(5)));
    }
}
