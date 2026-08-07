use serde::de::Error as DeserializeError;
use serde::{Deserialize, Deserializer, Serialize};
use std::error::Error;
use std::fmt;

/// The byte stored by the retail map model for its horizontal-edge behavior.
///
/// Despite the recovered C++ field name, zero enables horizontal wrapping and
/// every nonzero value rejects coordinates beyond the left and right edges.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct RetailTopologyByte(u8);

impl RetailTopologyByte {
    pub const fn from_retail_byte(value: u8) -> Self {
        Self(value)
    }

    pub const fn retail_byte(self) -> u8 {
        self.0
    }

    pub const fn wraps_horizontally(self) -> bool {
        self.0 == 0
    }

    /// Produces the canonical byte written by the setup UI for the requested
    /// semantic topology. Reading still preserves arbitrary nonzero bytes.
    pub const fn from_wraps_horizontally(wraps_horizontally: bool) -> Self {
        Self(if wraps_horizontally { 0 } else { 1 })
    }
}

/// Explicit inputs to the normal retail setup path. The selected nation is
/// intentionally absent because beginning setup draws it from CRT `rand()`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BeginRandomGameSetupInputs {
    pub planet_seed: String,
    pub retail_topology: RetailTopologyByte,
    pub country_name: String,
    pub difficulty: i32,
    pub use_localized_name_tables: bool,
}

/// Complete setup state supplied only when restoring an oracle or saved test
/// boundary that already contains the selected nation. This path consumes no
/// RNG draw and is therefore not exposed as a gameplay command.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RestoredRandomGameSetupInputs {
    pub planet_seed: String,
    pub retail_topology: RetailTopologyByte,
    pub selected_nation_slot: i16,
    pub country_name: String,
    pub difficulty: i32,
    pub use_localized_name_tables: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RandomGameSetupState {
    planet_seed: String,
    retail_topology: RetailTopologyByte,
    selected_nation_slot: i16,
    country_name: String,
    difficulty: i32,
    use_localized_name_tables: bool,
}

impl<'de> Deserialize<'de> for RandomGameSetupState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let inputs = RestoredRandomGameSetupInputs::deserialize(deserializer)?;
        Self::try_from_restored_inputs(inputs).map_err(D::Error::custom)
    }
}

impl RandomGameSetupState {
    pub fn try_from_restored_inputs(
        inputs: RestoredRandomGameSetupInputs,
    ) -> Result<Self, RandomGameSetupValidationError> {
        validate_nation_slot(inputs.selected_nation_slot)?;
        validate_difficulty(inputs.difficulty)?;
        Ok(Self {
            planet_seed: inputs.planet_seed,
            retail_topology: inputs.retail_topology,
            selected_nation_slot: inputs.selected_nation_slot,
            country_name: inputs.country_name,
            difficulty: inputs.difficulty,
            use_localized_name_tables: inputs.use_localized_name_tables,
        })
    }

    pub(crate) fn validate_begin_inputs(
        inputs: &BeginRandomGameSetupInputs,
    ) -> Result<(), RandomGameSetupValidationError> {
        validate_difficulty(inputs.difficulty)
    }

    pub(crate) fn from_validated_begin_inputs(
        inputs: BeginRandomGameSetupInputs,
        selected_nation_slot: i16,
    ) -> Self {
        debug_assert!((0..=6).contains(&selected_nation_slot));
        debug_assert!((0..=4).contains(&inputs.difficulty));
        Self {
            planet_seed: inputs.planet_seed,
            retail_topology: inputs.retail_topology,
            selected_nation_slot,
            country_name: inputs.country_name,
            difficulty: inputs.difficulty,
            use_localized_name_tables: inputs.use_localized_name_tables,
        }
    }

    pub fn query(&self) -> RandomGameSetupModel {
        RandomGameSetupModel {
            planet_seed: self.planet_seed.clone(),
            retail_topology_byte: self.retail_topology.retail_byte(),
            wraps_horizontally: self.retail_topology.wraps_horizontally(),
            selected_nation_slot: self.selected_nation_slot,
            country_name: self.country_name.clone(),
            difficulty: self.difficulty,
            use_localized_name_tables: self.use_localized_name_tables,
        }
    }

    pub(crate) fn set_planet(&mut self, planet_seed: String, retail_topology: RetailTopologyByte) {
        self.planet_seed = planet_seed;
        self.retail_topology = retail_topology;
    }

    pub(crate) fn set_selected_nation_slot(
        &mut self,
        selected_nation_slot: i16,
    ) -> Result<(), RandomGameSetupValidationError> {
        validate_nation_slot(selected_nation_slot)?;
        self.selected_nation_slot = selected_nation_slot;
        Ok(())
    }

    pub(crate) fn set_country_name(&mut self, country_name: String) {
        self.country_name = country_name;
    }

    pub(crate) fn set_difficulty(
        &mut self,
        difficulty: i32,
    ) -> Result<(), RandomGameSetupValidationError> {
        validate_difficulty(difficulty)?;
        self.difficulty = difficulty;
        Ok(())
    }

    pub(crate) fn set_use_localized_name_tables(&mut self, enabled: bool) {
        self.use_localized_name_tables = enabled;
    }
}

/// Read model for the setup screen. The semantic topology is supplied beside
/// the original byte so presentation code never has to duplicate its inversion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RandomGameSetupModel {
    pub planet_seed: String,
    pub retail_topology_byte: u8,
    pub wraps_horizontally: bool,
    pub selected_nation_slot: i16,
    pub country_name: String,
    pub difficulty: i32,
    pub use_localized_name_tables: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RandomGameSetupValidationError {
    InvalidNationSlot { actual: i16 },
    InvalidDifficulty { actual: i32 },
}

impl fmt::Display for RandomGameSetupValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNationSlot { actual } => {
                write!(
                    formatter,
                    "random-game nation slot {actual} is outside 0..=6"
                )
            }
            Self::InvalidDifficulty { actual } => {
                write!(
                    formatter,
                    "random-game difficulty {actual} is outside 0..=4"
                )
            }
        }
    }
}

impl Error for RandomGameSetupValidationError {}

fn validate_nation_slot(selected_nation_slot: i16) -> Result<(), RandomGameSetupValidationError> {
    if (0..=6).contains(&selected_nation_slot) {
        Ok(())
    } else {
        Err(RandomGameSetupValidationError::InvalidNationSlot {
            actual: selected_nation_slot,
        })
    }
}

fn validate_difficulty(difficulty: i32) -> Result<(), RandomGameSetupValidationError> {
    if (0..=4).contains(&difficulty) {
        Ok(())
    } else {
        Err(RandomGameSetupValidationError::InvalidDifficulty { actual: difficulty })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> RestoredRandomGameSetupInputs {
        RestoredRandomGameSetupInputs {
            planet_seed: "earth".to_owned(),
            retail_topology: RetailTopologyByte::from_retail_byte(0),
            selected_nation_slot: 3,
            country_name: "Republic".to_owned(),
            difficulty: 2,
            use_localized_name_tables: true,
        }
    }

    #[test]
    fn converts_the_inverted_retail_topology_byte_without_losing_it() {
        let wrapping = RetailTopologyByte::from_retail_byte(0);
        let bounded = RetailTopologyByte::from_retail_byte(7);
        assert!(wrapping.wraps_horizontally());
        assert!(!bounded.wraps_horizontally());
        assert_eq!(bounded.retail_byte(), 7);
        assert_eq!(
            RetailTopologyByte::from_wraps_horizontally(true).retail_byte(),
            0
        );
        assert_eq!(
            RetailTopologyByte::from_wraps_horizontally(false).retail_byte(),
            1
        );
    }

    #[test]
    fn query_exposes_only_setup_values_and_the_converted_topology() {
        let state = RandomGameSetupState::try_from_restored_inputs(inputs()).unwrap();
        assert_eq!(
            state.query(),
            RandomGameSetupModel {
                planet_seed: "earth".to_owned(),
                retail_topology_byte: 0,
                wraps_horizontally: true,
                selected_nation_slot: 3,
                country_name: "Republic".to_owned(),
                difficulty: 2,
                use_localized_name_tables: true,
            }
        );
    }

    #[test]
    fn rejects_only_ranges_proven_by_the_setup_controls() {
        let mut invalid_nation = inputs();
        invalid_nation.selected_nation_slot = 7;
        assert_eq!(
            RandomGameSetupState::try_from_restored_inputs(invalid_nation),
            Err(RandomGameSetupValidationError::InvalidNationSlot { actual: 7 })
        );

        let mut invalid_difficulty = inputs();
        invalid_difficulty.difficulty = -1;
        assert_eq!(
            RandomGameSetupState::try_from_restored_inputs(invalid_difficulty),
            Err(RandomGameSetupValidationError::InvalidDifficulty { actual: -1 })
        );

        let invalid_json = r#"{"planet_seed":"earth","retail_topology":0,"selected_nation_slot":7,"country_name":"Republic","difficulty":2,"use_localized_name_tables":true}"#;
        assert!(serde_json::from_str::<RandomGameSetupState>(invalid_json).is_err());
    }
}
