use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fmt;

pub const GAME_SNAPSHOT_SCHEMA: &str = "imperialism.game_snapshot.v1";
pub const GAME_SNAPSHOT_SECTIONS: [&str; 3] = ["metadata", "rng", "world"];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GameSnapshotV1 {
    pub schema: String,
    pub sections: Vec<String>,
    pub hashes: SnapshotHashes,
    pub metadata: SnapshotMetadata,
    pub rng: SnapshotRng,
    pub world: SnapshotWorld,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotHashes {
    pub metadata: String,
    pub rng: String,
    pub world: String,
    pub state: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotMetadata {
    pub scenario_map_index_plus_one: i32,
    pub economic_turn: i32,
    pub turn_state: i32,
    pub mode: i32,
    pub difficulty: i32,
    pub active_nation: i32,
    pub selected_nation: i32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotRng {
    pub runtime_seed: u32,
    pub crt_rand_state: u32,
    pub map_generation_lcg: u32,
    pub zone_status_lcg: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SnapshotWorld {
    pub width: u16,
    pub height: u16,
    pub wrap: i32,
    pub tiles: Vec<TileSnapshot>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TileSnapshot(pub [i64; 10]);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SnapshotValidationError {
    Schema(String),
    Sections(Vec<String>),
    Dimensions {
        width: u16,
        height: u16,
    },
    TileCount {
        expected: usize,
        actual: usize,
    },
    HashFormat {
        section: &'static str,
        value: String,
    },
    HashMismatch {
        section: &'static str,
        expected: String,
        actual: String,
    },
    Serialization(String),
}

impl fmt::Display for SnapshotValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Schema(schema) => {
                write!(formatter, "unsupported game snapshot schema {schema:?}")
            }
            Self::Sections(sections) => {
                write!(formatter, "invalid game snapshot sections {sections:?}")
            }
            Self::Dimensions { width, height } => {
                write!(
                    formatter,
                    "invalid game snapshot dimensions {width}x{height}"
                )
            }
            Self::TileCount { expected, actual } => {
                write!(formatter, "expected {expected} world tiles, found {actual}")
            }
            Self::HashFormat { section, value } => {
                write!(formatter, "invalid {section} hash {value:?}")
            }
            Self::HashMismatch {
                section,
                expected,
                actual,
            } => write!(
                formatter,
                "{section} hash mismatch: snapshot {expected}, computed {actual}"
            ),
            Self::Serialization(message) => {
                write!(formatter, "snapshot serialization failed: {message}")
            }
        }
    }
}

impl Error for SnapshotValidationError {}

impl GameSnapshotV1 {
    pub fn validate(&self) -> Result<(), SnapshotValidationError> {
        if self.schema != GAME_SNAPSHOT_SCHEMA {
            return Err(SnapshotValidationError::Schema(self.schema.clone()));
        }
        if self.sections.iter().map(String::as_str).collect::<Vec<_>>() != GAME_SNAPSHOT_SECTIONS {
            return Err(SnapshotValidationError::Sections(self.sections.clone()));
        }
        if self.world.width != 108 || self.world.height != 60 {
            return Err(SnapshotValidationError::Dimensions {
                width: self.world.width,
                height: self.world.height,
            });
        }
        let expected = usize::from(self.world.width) * usize::from(self.world.height);
        if self.world.tiles.len() != expected {
            return Err(SnapshotValidationError::TileCount {
                expected,
                actual: self.world.tiles.len(),
            });
        }
        for (section, hash) in self.hashes.iter() {
            if hash.len() != 8
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(SnapshotValidationError::HashFormat {
                    section,
                    value: hash.to_owned(),
                });
            }
        }
        Ok(())
    }

    pub fn verify_hashes(&self) -> Result<(), SnapshotValidationError> {
        self.validate()?;
        let computed = self.computed_hashes()?;
        for (section, expected, actual) in [
            ("metadata", &self.hashes.metadata, &computed.metadata),
            ("rng", &self.hashes.rng, &computed.rng),
            ("world", &self.hashes.world, &computed.world),
            ("state", &self.hashes.state, &computed.state),
        ] {
            if expected != actual {
                return Err(SnapshotValidationError::HashMismatch {
                    section,
                    expected: expected.clone(),
                    actual: actual.clone(),
                });
            }
        }
        Ok(())
    }

    pub fn refresh_hashes(&mut self) -> Result<(), SnapshotValidationError> {
        self.hashes = self.computed_hashes()?;
        Ok(())
    }

    fn computed_hashes(&self) -> Result<SnapshotHashes, SnapshotValidationError> {
        let metadata = compact_json(&self.metadata)?;
        let rng = compact_json(&self.rng)?;
        let world = compact_json(&self.world)?;
        let mut state = String::with_capacity(metadata.len() + rng.len() + world.len());
        state.push_str(&metadata);
        state.push_str(&rng);
        state.push_str(&world);
        Ok(SnapshotHashes {
            metadata: fnv1a_hex(metadata.as_bytes()),
            rng: fnv1a_hex(rng.as_bytes()),
            world: fnv1a_hex(world.as_bytes()),
            state: fnv1a_hex(state.as_bytes()),
        })
    }
}

impl SnapshotHashes {
    fn iter(&self) -> [(&'static str, &str); 4] {
        [
            ("metadata", &self.metadata),
            ("rng", &self.rng),
            ("world", &self.world),
            ("state", &self.state),
        ]
    }
}

fn compact_json<T: Serialize>(value: &T) -> Result<String, SnapshotValidationError> {
    serde_json::to_string(value)
        .map_err(|error| SnapshotValidationError::Serialization(error.to_string()))
}

fn fnv1a_hex(bytes: &[u8]) -> String {
    let hash = bytes.iter().fold(2_166_136_261_u32, |hash, byte| {
        (hash ^ u32::from(*byte)).wrapping_mul(16_777_619)
    });
    format!("{hash:08x}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> GameSnapshotV1 {
        let mut snapshot = GameSnapshotV1 {
            schema: GAME_SNAPSHOT_SCHEMA.to_owned(),
            sections: GAME_SNAPSHOT_SECTIONS.map(str::to_owned).to_vec(),
            hashes: SnapshotHashes::default(),
            metadata: SnapshotMetadata {
                scenario_map_index_plus_one: 0,
                economic_turn: 1,
                turn_state: 5,
                mode: 18,
                difficulty: 1,
                active_nation: 6,
                selected_nation: 6,
            },
            rng: SnapshotRng {
                runtime_seed: 1,
                crt_rand_state: 3_018_468_955,
                map_generation_lcg: 2_556_087_536,
                zone_status_lcg: 1,
            },
            world: SnapshotWorld {
                width: 108,
                height: 60,
                wrap: 0,
                tiles: vec![TileSnapshot([0; 10]); 6480],
            },
        };
        snapshot.refresh_hashes().unwrap();
        snapshot
    }

    #[test]
    fn validates_and_verifies_canonical_snapshot() {
        let snapshot = snapshot();
        assert_eq!(snapshot.hashes.metadata, "199ad7b2");
        assert_eq!(snapshot.hashes.rng, "cda0c2d8");
        snapshot.verify_hashes().unwrap();
    }

    #[test]
    fn rejects_tampered_semantic_state() {
        let mut snapshot = snapshot();
        snapshot.world.tiles[0].0[1] = 6;
        assert!(matches!(
            snapshot.verify_hashes(),
            Err(SnapshotValidationError::HashMismatch {
                section: "world",
                ..
            })
        ));
    }
}
