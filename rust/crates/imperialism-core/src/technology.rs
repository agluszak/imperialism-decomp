use crate::*;
use serde::{Deserialize, Deserializer, Serialize};

/// Per-nation University capability state used by city production and recruitment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct UniversityTechnologyState {
    pub available: CivilianUnitTable<bool>,
    /// Highest unlocked requirement column (0..=3) for each resource.
    pub requirement_levels: ResourceTable<u8>,
}

impl<'de> Deserialize<'de> for UniversityTechnologyState {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct SerializedUniversityTechnologyState {
            available: CivilianUnitTable<bool>,
            requirement_levels: ResourceTable<u8>,
        }

        let serialized = SerializedUniversityTechnologyState::deserialize(deserializer)?;
        if serialized
            .requirement_levels
            .values()
            .any(|level| *level > 3)
        {
            return Err(serde::de::Error::custom(
                "university requirement levels must be in 0..=3",
            ));
        }
        Ok(Self {
            available: serialized.available,
            requirement_levels: serialized.requirement_levels,
        })
    }
}

impl Default for UniversityTechnologyState {
    fn default() -> Self {
        Self {
            available: CivilianUnitTable::from_array([
                true, true, true, false, true, false, false, true, false,
            ]),
            requirement_levels: ResourceTable::from_array([
                0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1,
            ]),
        }
    }
}

/// The technology capabilities consumed by one major nation's city and civilian-order rules.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CityTechnologyCapabilities {
    pub advanced_iron_working: bool,
    pub oil_drilling: bool,
    pub university: UniversityTechnologyState,
    pub primary_civilian_distance_terrain: CivilianTerrainAccess,
    pub secondary_civilian_hills: bool,
    pub secondary_civilian_swamp: bool,
    pub fort_level_cap: FortLevelCap,
}

impl Default for CityTechnologyCapabilities {
    fn default() -> Self {
        Self {
            advanced_iron_working: false,
            oil_drilling: false,
            university: UniversityTechnologyState::default(),
            primary_civilian_distance_terrain: CivilianTerrainAccess::default(),
            secondary_civilian_hills: false,
            secondary_civilian_swamp: false,
            fort_level_cap: FortLevelCap::ONE,
        }
    }
}

impl CityTechnologyCapabilities {
    pub(crate) const fn secondary_civilian_distance_terrain(self) -> CivilianTerrainAccess {
        CivilianTerrainAccess {
            hills: self.secondary_civilian_hills,
            mountain: self.oil_drilling,
            swamp: self.secondary_civilian_swamp,
        }
    }
}

pub const TECHNOLOGY_COUNT: usize = 29;

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TechnologyResearchStatus {
    #[default]
    NotStarted,
    Pending,
    Researched,
}

/// Global technology milestones and the city capabilities of every major nation.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct TechnologyState {
    pub advanced_iron_working: bool,
    pub marine_engineering: bool,
    pub scheduled_unlock_turn_by_technology: [i16; TECHNOLOGY_COUNT],
    pub global_unlocks_by_technology: [bool; TECHNOLOGY_COUNT],
    pub research_status_by_nation: MajorNationTable<[TechnologyResearchStatus; TECHNOLOGY_COUNT]>,
    pub industry_enabled_by_slot: [bool; 14],
    pub military_unit_ability_active_by_nation: MajorNationTable<MilitaryUnitTable<bool>>,
    pub city_capabilities_by_nation: MajorNationTable<CityTechnologyCapabilities>,
}

impl Default for TechnologyState {
    fn default() -> Self {
        Self {
            advanced_iron_working: false,
            marine_engineering: false,
            scheduled_unlock_turn_by_technology: [0; TECHNOLOGY_COUNT],
            global_unlocks_by_technology: [
                true, true, true, false, false, false, false, false, false, false, false, false,
                false, false, false, false, false, false, false, false, false, false, false, false,
                false, false, false, false, false,
            ],
            research_status_by_nation: MajorNationTable::from_fn(|_| {
                let mut status = [TechnologyResearchStatus::NotStarted; TECHNOLOGY_COUNT];
                status[0] = TechnologyResearchStatus::Researched;
                status[1] = TechnologyResearchStatus::Researched;
                status[2] = TechnologyResearchStatus::Researched;
                status
            }),
            industry_enabled_by_slot: [
                true, true, true, true, true, false, false, false, false, false, false, false,
                false, false,
            ],
            military_unit_ability_active_by_nation: MajorNationTable::from_fn(|_| {
                MilitaryUnitTable::from_array([
                    true, true, true, true, true, true, true, true, false, false, false, false,
                    false, false, false, false, false, false, false, false, false, false, false,
                    false, true, false, false, true, false, false,
                ])
            }),
            city_capabilities_by_nation: MajorNationTable::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CivilianTerrainAccess {
    pub hills: bool,
    pub mountain: bool,
    pub swamp: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct FortLevelCap(i8);

impl FortLevelCap {
    pub const ONE: Self = Self(1);
    pub const TWO: Self = Self(2);
    pub const THREE: Self = Self(3);

    pub const fn get(self) -> i8 {
        self.0
    }
}

impl<'de> Deserialize<'de> for FortLevelCap {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        match i8::deserialize(deserializer)? {
            1 => Ok(Self::ONE),
            2 => Ok(Self::TWO),
            3 => Ok(Self::THREE),
            value => Err(serde::de::Error::custom(format!(
                "fort level cap {value} is outside 1..=3"
            ))),
        }
    }
}

impl Default for FortLevelCap {
    fn default() -> Self {
        Self::ONE
    }
}

impl TechnologyState {
    pub const fn oil_drilling_available(&self) -> bool {
        self.global_unlocks_by_technology[0x13]
    }

    /// Selects the production-capacity term used by retail's naval-force score.
    pub const fn naval_production_capacity(
        self,
        lumber_mill_capacity: i32,
        steel_mill_capacity: i32,
    ) -> i32 {
        if self.marine_engineering {
            steel_mill_capacity
        } else if self.advanced_iron_working {
            (lumber_mill_capacity + steel_mill_capacity) / 2
        } else {
            lumber_mill_capacity
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn naval_production_capacity_follows_the_technology_priority_order() {
        for (advanced_iron_working, marine_engineering, expected) in [
            (false, false, 7),
            (true, false, 5),
            (false, true, 4),
            (true, true, 4),
        ] {
            let technology = TechnologyState {
                advanced_iron_working,
                marine_engineering,
                ..Default::default()
            };
            assert_eq!(technology.naval_production_capacity(7, 4), expected);
        }
    }
}
